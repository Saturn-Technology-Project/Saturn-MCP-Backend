"""Blocking work runs off the event loop, and upstream failures are classified by what may have happened."""

import gzip
import json
import threading

import httpx
import pytest
from fastapi import HTTPException

from app.features.execution.approvals.services.claimed_call import is_uncertain as _uncertain
from app.features.mcp.oauth.services import mcp_oauth as oauth_module
from app.features.mcp.servers.services import mcp_remote
from app.features.mcp.servers.services.mcp_remote import McpOutcomeUnknown, McpTimeout, _payload, _raise_for_status
from app.features.webhooks.services import webhook_service
from app.features.webhooks.services.destinations import PinnedTarget, WebhookUnresolved
from tests.test_payload_keys_hardening import _gateway


def _response(status=200, body=b"{}", content_type="application/json"):
    return httpx.Response(status, headers={"content-type": content_type}, content=body, request=httpx.Request("POST", "https://x/"))


# --- Upstream OAuth -----------------------------------------------------------------------------


async def test_a_compressed_authorization_server_answer_is_read(monkeypatch):
    document = {"token_endpoint": "https://auth.example.com/token"}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json", "content-encoding": "gzip"},
            content=gzip.compress(json.dumps(document).encode()),
        )

    real_client = httpx.AsyncClient

    def client(**kwargs):
        kwargs.pop("transport", None)
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(oauth_module.httpx, "AsyncClient", client)
    monkeypatch.setattr(
        "app.features.webhooks.services.destinations.pin_webhook_url",
        lambda url: PinnedTarget(url="https://203.0.113.10/.well-known/oauth-authorization-server", host="auth.example.com", address="203.0.113.10"),
    )
    response = await oauth_module._request("GET", "https://auth.example.com/.well-known/oauth-authorization-server")
    # Decoding the already-decoded body a second time used to raise here.
    assert response.json() == document
    assert "content-encoding" not in response.headers


# --- What a failed tools/call means ---------------------------------------------------------------


def test_an_unusable_answer_to_a_call_is_uncertain_not_failed():
    cases = [
        _response(body=b"not json"),
        _response(body=b"\xff\xfe\x00"),
        _response(body=b"[1, 2]"),
        _response(body=b"", content_type="text/event-stream"),
        _response(body=b"[" * 100_000 + b"]" * 100_000),
    ]
    for response in cases:
        with pytest.raises(McpOutcomeUnknown) as caught:
            _payload(response, call=True)
        assert _uncertain(caught.value)
        assert caught.value.status_code == 502
        # The same answer to tools/list means nothing ran: an ordinary error.
        with pytest.raises(HTTPException) as plain:
            _payload(response)
        assert not isinstance(plain.value, McpTimeout)


def test_a_server_error_after_the_call_was_sent_is_uncertain():
    with pytest.raises(McpOutcomeUnknown):
        _raise_for_status(_response(500), "https://x/", call=True)
    with pytest.raises(McpOutcomeUnknown):
        _raise_for_status(_response(503), "https://x/", call=True)
    # A refusal means the server did not run it.
    for code in (400, 403, 404, 429):
        with pytest.raises(HTTPException) as refused:
            _raise_for_status(_response(code), "https://x/", call=True)
        assert not _uncertain(refused.value)
    # Listing tools runs nothing, so a 500 there is a plain failure.
    with pytest.raises(HTTPException) as listed:
        _raise_for_status(_response(500), "https://x/")
    assert not _uncertain(listed.value)


async def test_a_failed_direct_call_records_how_it_ended(client, monkeypatch):
    call = await _gateway(client, monkeypatch)
    await call({"repo": "works"})

    async def unknown(endpoint, tool, arguments, authorization=""):
        raise McpOutcomeUnknown("MCP server returned HTTP 500")

    monkeypatch.setattr("app.features.mcp.saturn.services.saturn_mcp.call_remote_tool", unknown)
    with pytest.raises(AssertionError):
        await call({"repo": "breaks"})
    rows = (await client.get("/activity", params={"tool": "repo.read"})).json()
    ended = [item for item in rows if item["event"] == "tool_executed"]
    assert sorted(item["result"] for item in ended) == ["completed", "uncertain"]
    reason = next(item for item in ended if item["result"] == "uncertain")["payload"]["reason"]
    assert reason == "MCP server returned HTTP 500"


# --- Off the event loop --------------------------------------------------------------------------


async def test_endpoint_lookups_run_in_a_worker_thread(monkeypatch):
    seen = []

    def target(endpoint, authorization):
        seen.append(threading.get_ident())
        raise HTTPException(400, "stop here")

    monkeypatch.setattr(mcp_remote, "_target", target)
    for function in (mcp_remote.list_remote_tools, mcp_remote.call_remote_tool):
        with pytest.raises(HTTPException):
            if function is mcp_remote.call_remote_tool:
                await function("https://mcp.example.com/mcp", "tool", {})
            else:
                await function("https://mcp.example.com/mcp")
    assert len(seen) == 2 and threading.get_ident() not in seen


async def test_webhook_url_checks_run_in_a_worker_thread(client, monkeypatch):
    seen = []

    def check(url):
        seen.append(threading.get_ident())
        return url

    monkeypatch.setattr(webhook_service, "require_webhook_url", check)
    created = await client.post("/org/webhooks", json={"url": "https://hooks.example.com/a", "events": ["approval.granted"]})
    assert created.status_code == 201, created.text
    changed = await client.patch(f"/org/webhooks/{created.json()['id']}", json={"url": "https://hooks.example.com/b"})
    assert changed.status_code == 200, changed.text
    assert len(seen) == 2 and threading.get_ident() not in seen


async def test_password_hashing_runs_in_a_worker_thread(client, monkeypatch):
    from app.features.identity.auth.services import auth_service

    seen = []
    real = auth_service.verify_password

    def verify(password, stored):
        seen.append(threading.get_ident())
        return real(password, stored)

    monkeypatch.setattr(auth_service, "verify_password", verify)
    wrong = await client.post("/auth/login", json={"email": "rick@saturn.ai", "password": "not it"})
    assert wrong.status_code == 401
    right = await client.post("/auth/login", json={"email": "rick@saturn.ai", "password": "saturn"})
    assert right.status_code == 200, right.text
    assert seen and threading.get_ident() not in seen


# --- Webhook destinations -------------------------------------------------------------------------


async def test_a_host_that_does_not_resolve_is_retried_not_dropped(monkeypatch):
    def unresolved(url):
        raise WebhookUnresolved()

    monkeypatch.setattr(webhook_service, "pin_webhook_url", unresolved)
    code, error = await webhook_service.send_webhook("https://hooks.example.com/x", b"{}", {})
    assert (code, error) == (None, "host did not resolve")
    # No status code and not a refused destination: the delivery stays in the retry cycle.
    assert webhook_service._retryable(code) and error != "destination not allowed"
