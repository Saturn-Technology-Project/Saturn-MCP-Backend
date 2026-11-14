"""Regression tests for the approval, run and Saturn MCP hardening (audit 2026-10-20)."""

import hashlib
import json

import httpx
import pytest
from sqlalchemy import select

from app.db.database import get_session
from app.main import app
from tests.oauth_access import oauth_access, oauth_tokens
from tests.policy_helpers import activate_created
from tests.test_quorum import _auth, _people, _quorum_tool, _request


async def _db():
    """A session on the test database, through the same override the app uses."""
    factory = app.dependency_overrides[get_session]
    generator = factory()
    session = await generator.__anext__()
    return generator, session


async def _close(generator):
    try:
        await generator.__anext__()
    except StopAsyncIteration:
        pass


async def _payments(client, monkeypatch, calls, seen, policy_body=None):
    """Payments tool behind approval. policy_body(groups) adds an approval policy rule."""

    async def listed(endpoint, authorization=""):
        return [{"name": "pay.send", "description": "Send", "inputSchema": {"type": "object", "properties": {}}}]

    async def called(endpoint, name, arguments, authorization=""):
        calls["n"] += 1
        seen.append(arguments)
        return {"content": [{"type": "text", "text": "ok"}], "tool": name, "echo": arguments}

    monkeypatch.setattr("app.features.mcp.servers.services.mcp_connect.list_remote_tools", listed)
    monkeypatch.setattr("app.features.mcp.saturn.services.saturn_mcp.call_remote_tool", called)
    connected = await client.post(
        "/mcp-servers",
        json={"name": "Payments", "endpoint": "https://mcp.stripe.com/mcp", "authorization": "token-1"},
    )
    assert connected.status_code == 201, connected.text
    tool_id = connected.json()["catalog"][0]["id"]
    created = await client.post("/tool-sets", json={"name": "Payments", "items": [{"tool_id": tool_id, "approval": True}]})
    assert created.status_code == 201, created.text
    people = await _people(client)
    groups = {}
    for name in ("Admin", "Finance"):
        made = await client.post("/org/groups", json={"name": name})
        assert made.status_code == 201, made.text
        groups[name] = made.json()["id"]
    if policy_body is not None:
        policy = await client.post("/org/approval-policies", json=policy_body(groups))
        assert policy.status_code == 201, policy.text
        rule = await client.post(
            "/policies",
            json={
                "name": "HV",
                "rules": [
                    {
                        "tool": "pay.send",
                        "condition": "true",
                        "decision": "approval_required",
                        "approval_policy_id": policy.json()["id"],
                    }
                ],
            },
        )
        await activate_created(client, rule)
    access = await oauth_access(client, "Pay Agent")
    opened = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {access}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    assert opened.status_code == 200, opened.text
    agent_id = next(item["id"] for item in (await client.get("/agents")).json() if item["name"] == "Pay Agent")
    assigned = await client.patch(f"/agents/{agent_id}", json={"tool_set_id": created.json()["id"]})
    assert assigned.status_code == 200, assigned.text
    return people, groups, access, agent_id


# H-04 ---------------------------------------------------------------------------------------------


async def test_quorum_without_payload_key_sends_the_approved_arguments(client, monkeypatch):
    seen = []
    calls, people, access, agent_id, _rule, _group = await _quorum_tool(client, monkeypatch)

    async def called(endpoint, name, arguments, authorization=""):
        calls["n"] += 1
        seen.append(arguments)
        return {"content": [{"type": "text", "text": "ok"}], "tool": name, "echo": arguments}

    monkeypatch.setattr("app.features.mcp.saturn.services.saturn_mcp.call_remote_tool", called)
    body = await _request(client, access, agent_id, {"amount": 42, "to": "acct_1"})
    approval_id = body["error"]["data"]["approval_id"]
    first = await client.post(f"/approvals/{approval_id}/approve", headers=_auth(people[0][1]))
    assert first.status_code == 200, first.text
    # No arguments in the body: the server kept them sealed.
    second = await client.post(f"/approvals/{approval_id}/approve", headers=_auth(people[1][1]))
    assert second.status_code == 200, second.text
    assert second.json()["status"] == "completed"
    assert seen == [{"amount": 42, "to": "acct_1"}]

    generator, session = await _db()
    try:
        from app.models import Action, Approval

        approval = await session.get(Approval, approval_id)
        action = await session.get(Action, approval.action_id)
        stored = json.dumps(action.arguments)
        assert "acct_1" not in stored
        assert action.arguments["encryption"] == "server-sealed-v1"
        assert action.arguments["sealed"].startswith("s2.")
        plain = hashlib.sha256(json.dumps({"amount": 42, "to": "acct_1"}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        # L-27: the digest is keyed, so it cannot confirm a guess of the arguments.
        assert action.arguments["digest"] != plain
        assert approval.parameter_digest != plain
    finally:
        await _close(generator)


async def test_legacy_digest_only_action_never_sends_the_digest_upstream(client, monkeypatch):
    seen = []
    calls, people, access, agent_id, _rule, _group = await _quorum_tool(client, monkeypatch)

    async def called(endpoint, name, arguments, authorization=""):
        calls["n"] += 1
        seen.append(arguments)
        return {"content": [{"type": "text", "text": "ok"}], "echo": arguments}

    monkeypatch.setattr("app.features.mcp.saturn.services.saturn_mcp.call_remote_tool", called)
    body = await _request(client, access, agent_id, {"amount": 7})
    approval_id = body["error"]["data"]["approval_id"]
    legacy = hashlib.sha256(json.dumps({"amount": 7}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    generator, session = await _db()
    try:
        from app.models import Action, Approval

        approval = await session.get(Approval, approval_id)
        action = await session.get(Action, approval.action_id)
        # A row written before this fix: only an unkeyed digest was kept.
        action.arguments = {"digest": legacy, "encryption": "unavailable"}
        approval.parameter_digest = legacy
        await session.commit()
    finally:
        await _close(generator)
    assert (await client.post(f"/approvals/{approval_id}/approve", headers=_auth(people[0][1]))).status_code == 200
    missing = await client.post(f"/approvals/{approval_id}/approve", headers=_auth(people[1][1]))
    assert missing.status_code == 409, missing.text
    wrong = await client.post(
        f"/approvals/{approval_id}/approve", headers=_auth(people[1][1]), json={"arguments": {"amount": 8}}
    )
    assert wrong.status_code == 409, wrong.text
    assert seen == []
    right = await client.post(
        f"/approvals/{approval_id}/approve", headers=_auth(people[1][1]), json={"arguments": {"amount": 7}}
    )
    assert right.status_code == 200, right.text
    assert seen == [{"amount": 7}]


# H-03 ---------------------------------------------------------------------------------------------


async def test_single_approver_checks_group_and_requester(client, monkeypatch):
    calls, seen = {"n": 0}, []
    people, groups, access, agent_id = await _payments(
        client,
        monkeypatch,
        calls,
        seen,
        lambda g: {"name": "Finance one", "required_count": 1, "group_id": g["Finance"], "allow_requester": False},
    )
    assert (await client.post(f"/org/groups/{groups['Finance']}/members", json={"employee_id": people[0][0]})).status_code == 200
    body = await _request(client, access, agent_id, {"amount": 900})
    approval_id = body["error"]["data"]["approval_id"]
    outsider = await client.post(f"/approvals/{approval_id}/approve", headers=_auth(people[1][1]))
    assert outsider.status_code == 403, outsider.text
    outsider_reject = await client.post(f"/approvals/{approval_id}/reject", headers=_auth(people[1][1]))
    assert outsider_reject.status_code == 403, outsider_reject.text
    # The OAuth agent acts for rick, so rick is the requester and allow_requester is false.
    own = await client.post(f"/approvals/{approval_id}/approve")
    assert own.status_code == 403, own.text
    own_reject = await client.post(f"/approvals/{approval_id}/reject")
    assert own_reject.status_code == 403, own_reject.text
    assert (await client.get(f"/approvals/{approval_id}")).json()["status"] == "pending"
    member = await client.post(f"/approvals/{approval_id}/approve", headers=_auth(people[0][1]))
    assert member.status_code == 200, member.text
    ran = await _request(client, access, agent_id, {"amount": 900}, run_id=body["error"]["data"]["saturnRunId"])
    assert ran["result"]["echo"] == {"amount": 900}
    assert calls["n"] == 1


# M-25 ---------------------------------------------------------------------------------------------


async def test_single_approver_claim_is_atomic(client, monkeypatch):
    calls, seen = {"n": 0}, []
    people, _groups, access, agent_id = await _payments(client, monkeypatch, calls, seen)
    body = await _request(client, access, agent_id, {"amount": 5})
    approval_id = body["error"]["data"]["approval_id"]
    from sqlalchemy import update

    from app.features.execution.approvals.services import approval_service as module
    from app.features.execution.activity.services.audit_service import audit_service
    from app.models import Approval

    original = module.run_service.evaluate_action_policy
    granted = []
    log = audit_service.log

    async def record(*args, **kwargs):
        if getattr(kwargs.get("event"), "value", kwargs.get("event")) == "approval_granted":
            granted.append(kwargs.get("result"))
        return await log(*args, **kwargs)

    async def raced(session, action, **kwargs):
        # Another approver wins between this request's read and its write.
        await session.execute(update(Approval).where(Approval.id == approval_id).values(status="approved"))
        return await original(session, action, **kwargs)

    monkeypatch.setattr(module.run_service, "evaluate_action_policy", raced)
    monkeypatch.setattr(audit_service, "log", record)
    lost = await client.post(f"/approvals/{approval_id}/approve", headers={"Authorization": f"Bearer {people[0][1]}"})
    assert lost.status_code == 409, lost.text
    assert granted == []


# M-09 ---------------------------------------------------------------------------------------------


async def test_one_vote_fills_only_one_group_requirement(client, monkeypatch):
    calls, seen = {"n": 0}, []
    people, groups, access, agent_id = await _payments(
        client,
        monkeypatch,
        calls,
        seen,
        lambda g: {
            "name": "Fin+Admin",
            "allow_requester": False,
            "requirements": [
                {"group_id": g["Finance"], "required_count": 1},
                {"group_id": g["Admin"], "required_count": 1},
            ],
        },
    )
    for group_id in groups.values():
        assert (await client.post(f"/org/groups/{group_id}/members", json={"employee_id": people[0][0]})).status_code == 200
    assert (await client.post(f"/org/groups/{groups['Admin']}/members", json={"employee_id": people[1][0]})).status_code == 200
    body = await _request(client, access, agent_id, {"amount": 900})
    approval_id = body["error"]["data"]["approval_id"]
    both = await client.post(f"/approvals/{approval_id}/approve", headers=_auth(people[0][1]))
    assert both.status_code == 200, both.text
    assert both.json()["status"] == "pending"
    assert both.json()["result"] in {"1/1+0/1", "0/1+1/1"}
    assert calls["n"] == 0
    # The Admin-only member takes the Admin seat, so the first vote moves to Finance.
    admin = await client.post(f"/approvals/{approval_id}/approve", headers=_auth(people[1][1]))
    assert admin.status_code == 200, admin.text
    assert admin.json()["status"] == "completed"
    assert seen == [{"amount": 900}]


def test_assignment_is_a_maximum_matching():
    from app.features.execution.approvals.services.approval_service import _assign_votes

    specs = [{"group_id": "fin", "required_count": 2}, {"group_id": "adm", "required_count": 1}]
    both = {"a": {"fin", "adm"}, "b": {"fin"}, "c": {"adm"}}
    assert _assign_votes(["a"], both, specs) == [(1, 2), (0, 1)]
    assert _assign_votes(["a", "c"], both, specs) == [(1, 2), (1, 1)]
    assert _assign_votes(["a", "b", "c"], both, specs) == [(2, 2), (1, 1)]
    assert _assign_votes(["c", "a"], both, specs) == [(1, 2), (1, 1)]
    assert _assign_votes(["a", "b"], both, specs) == [(2, 2), (0, 1)]


# H-05 ---------------------------------------------------------------------------------------------


async def test_failure_after_upstream_ran_never_executes_twice(client, monkeypatch):
    calls, people, access, agent_id, _rule, _group = await _quorum_tool(client, monkeypatch)
    from app.features.execution.activity.services.audit_service import audit_service

    original = audit_service.log

    async def broken(*args, **kwargs):
        if getattr(kwargs.get("event"), "value", kwargs.get("event")) == "tool_executed":
            raise ValueError("invalid ML-KEM public key")
        return await original(*args, **kwargs)

    body = await _request(client, access, agent_id, {"amount": 900})
    approval_id = body["error"]["data"]["approval_id"]
    first = await client.post(f"/approvals/{approval_id}/approve", headers=_auth(people[0][1]))
    assert first.json()["status"] == "pending"
    monkeypatch.setattr(audit_service, "log", broken)
    second = await client.post(f"/approvals/{approval_id}/approve", headers=_auth(people[1][1]))
    assert second.status_code == 409, second.text
    assert calls["n"] == 1
    monkeypatch.setattr(audit_service, "log", original)
    state = (await client.get(f"/approvals/{approval_id}")).json()
    assert state["status"] == "approved"
    assert state["execution_state"] == "uncertain"
    third = await client.post(f"/approvals/{approval_id}/approve", headers=_auth(people[2][1]))
    assert third.status_code == 409, third.text
    retry = await _request(client, access, agent_id, {"amount": 900}, run_id=body["error"]["data"]["saturnRunId"])
    assert retry["error"]["message"] == "execution_uncertain"
    assert calls["n"] == 1


async def test_resubmit_failure_after_upstream_ran_is_uncertain(client, monkeypatch):
    calls, seen = {"n": 0}, []
    people, _groups, access, agent_id = await _payments(client, monkeypatch, calls, seen)
    from app.features.execution.activity.services.audit_service import audit_service

    original = audit_service.log

    async def broken(*args, **kwargs):
        if getattr(kwargs.get("event"), "value", kwargs.get("event")) == "tool_executed":
            raise ValueError("invalid ML-KEM public key")
        return await original(*args, **kwargs)

    body = await _request(client, access, agent_id, {"amount": 3})
    run_id = body["error"]["data"]["saturnRunId"]
    assert (await client.post(f"/approvals/{body['error']['data']['approval_id']}/approve", headers={"Authorization": f"Bearer {people[0][1]}"})).status_code == 200
    monkeypatch.setattr(audit_service, "log", broken)
    first = await _request(client, access, agent_id, {"amount": 3}, run_id=run_id)
    assert first["error"]["message"] == "execution_uncertain"
    monkeypatch.setattr(audit_service, "log", original)
    again = await _request(client, access, agent_id, {"amount": 3}, run_id=run_id)
    assert again["error"]["message"] == "execution_uncertain"
    assert calls["n"] == 1


# M-08 / I-08 --------------------------------------------------------------------------------------


async def test_resubmit_timeout_is_uncertain_not_claimed(client, monkeypatch):
    calls, seen = {"n": 0}, []
    people, _groups, access, agent_id = await _payments(client, monkeypatch, calls, seen)
    from app.features.mcp.servers.services.mcp_remote import McpTimeout

    async def slow(endpoint, name, arguments, authorization=""):
        calls["n"] += 1
        raise McpTimeout("MCP server did not answer (ReadTimeout)")

    monkeypatch.setattr("app.features.mcp.saturn.services.saturn_mcp.call_remote_tool", slow)
    body = await _request(client, access, agent_id, {"amount": 4})
    approval_id = body["error"]["data"]["approval_id"]
    assert (await client.post(f"/approvals/{approval_id}/approve", headers={"Authorization": f"Bearer {people[0][1]}"})).status_code == 200
    first = await _request(client, access, agent_id, {"amount": 4}, run_id=body["error"]["data"]["saturnRunId"])
    assert first["error"]["message"] == "execution_uncertain"
    assert (await client.get(f"/approvals/{approval_id}")).json()["execution_state"] == "uncertain"
    again = await _request(client, access, agent_id, {"amount": 4}, run_id=body["error"]["data"]["saturnRunId"])
    assert again["error"]["message"] == "execution_uncertain"
    assert calls["n"] == 1


async def test_resubmit_after_policy_turns_to_deny_closes_the_approval(client, monkeypatch):
    calls, seen = {"n": 0}, []
    people, _groups, access, agent_id = await _payments(client, monkeypatch, calls, seen)
    body = await _request(client, access, agent_id, {"amount": 6})
    approval_id = body["error"]["data"]["approval_id"]
    assert (await client.post(f"/approvals/{approval_id}/approve", headers={"Authorization": f"Bearer {people[0][1]}"})).status_code == 200
    from app.features.policy.policies.services import policy_engine as engine_module
    from app.features.policy.policies.services.policy_engine import EvaluationResult
    from app.core.enums import PolicyDecision

    original = engine_module.policy_engine.evaluate_named
    seen_calls = {"n": 0}

    async def deny(*args, **kwargs):
        # The request-time check passes; the fresh check right before execution denies.
        seen_calls["n"] += 1
        if seen_calls["n"] == 1:
            return await original(*args, **kwargs)
        return EvaluationResult(decision=PolicyDecision.DENY, reason="blocked now")

    monkeypatch.setattr(engine_module.policy_engine, "evaluate_named", deny)
    denied = await _request(client, access, agent_id, {"amount": 6}, run_id=body["error"]["data"]["saturnRunId"])
    assert denied["error"]["data"]["code"] == "policy_denied"
    state = (await client.get(f"/approvals/{approval_id}")).json()
    assert state["status"] == "invalidated"
    assert state["execution_state"] == "none"
    assert calls["n"] == 0


async def test_cancel_is_limited_to_the_requester_or_an_admin(client, monkeypatch):
    calls, seen = {"n": 0}, []
    people, _groups, access, agent_id = await _payments(client, monkeypatch, calls, seen)
    body = await _request(client, access, agent_id, {"amount": 1})
    approval_id = body["error"]["data"]["approval_id"]
    other = await client.post(f"/approvals/{approval_id}/cancel", headers=_auth(people[0][1]))
    assert other.status_code == 403, other.text
    own = await client.post(f"/approvals/{approval_id}/cancel")
    assert own.status_code == 200, own.text


# M-08 / I-06: mcp_remote --------------------------------------------------------------------------


_REAL_CLIENT = httpx.AsyncClient


def _fake_client(monkeypatch, handler):
    def build(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return _REAL_CLIENT(*args, **kwargs)

    monkeypatch.setattr("app.features.mcp.servers.services.mcp_remote.httpx.AsyncClient", build)
    # Upstream clients are kept per host: drop the ones built around an earlier handler.
    from app.features.mcp.servers.services import mcp_remote

    mcp_remote._clients.clear()


def _rpc_handler(on_call):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["method"] == "initialize":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})
        return on_call(request)

    return handler


async def test_tools_call_timeout_is_uncertain_and_hides_the_key(monkeypatch):
    from fastapi import HTTPException

    from app.features.execution.approvals.services.claimed_call import is_uncertain as _uncertain
    from app.features.mcp.servers.services.mcp_remote import McpTimeout, call_remote_tool

    def timeout(request):
        raise httpx.ReadTimeout(f"timed out reading {request.url}", request=request)

    _fake_client(monkeypatch, _rpc_handler(timeout))
    with pytest.raises(McpTimeout) as caught:
        await call_remote_tool("https://api.sec-api.io/mcp", "search", {"q": "x"}, "Bearer sk-secret-123456")
    assert isinstance(caught.value, HTTPException)
    assert caught.value.status_code == 504
    assert _uncertain(caught.value)
    assert "sk-secret" not in str(caught.value.detail)

    def refused(request):
        raise httpx.ConnectError(f"could not connect to {request.url}", request=request)

    _fake_client(monkeypatch, _rpc_handler(refused))
    with pytest.raises(HTTPException) as failed:
        await call_remote_tool("https://api.sec-api.io/mcp", "search", {"q": "x"}, "sk-secret-123456")
    assert not isinstance(failed.value, McpTimeout)
    assert not _uncertain(failed.value)
    assert "sk-secret" not in str(failed.value.detail)
    assert "apiKey" not in str(failed.value.detail)

    def echoed(request):
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 2, "error": {"message": f"bad url {request.url}"}})

    _fake_client(monkeypatch, _rpc_handler(echoed))
    with pytest.raises(HTTPException) as upstream:
        await call_remote_tool("https://api.sec-api.io/mcp", "search", {"q": "x"}, "sk-secret-123456")
    assert "sk-secret" not in str(upstream.value.detail)


async def test_upstream_response_size_is_capped(monkeypatch):
    from fastapi import HTTPException

    from app.features.mcp.servers.services import mcp_remote

    monkeypatch.setattr(mcp_remote, "MAX_RESPONSE_BYTES", 1024)

    def huge(request):
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 2, "result": {"blob": "x" * 5000}})

    _fake_client(monkeypatch, _rpc_handler(huge))
    with pytest.raises(HTTPException) as caught:
        await mcp_remote.call_remote_tool("https://mcp.stripe.com/mcp", "pay.send", {}, "token-1")
    assert "too large" in str(caught.value.detail)

    def small(request):
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 2, "result": {"ok": True}})

    _fake_client(monkeypatch, _rpc_handler(small))
    body = await mcp_remote.call_remote_tool("https://mcp.stripe.com/mcp", "pay.send", {}, "token-1")
    assert body["result"] == {"ok": True}


# M-23 / M-24 / L-13 / L-17 ------------------------------------------------------------------------


async def test_initialize_caps_agents_per_oauth_client(client):
    access = await oauth_access(client, "Many Names")
    headers = {"Authorization": f"Bearer {access}"}
    from app.features.mcp.saturn.services.saturn_mcp import MAX_AGENTS_PER_CLIENT

    accepted = 0
    for index in range(MAX_AGENTS_PER_CLIENT * 3):
        response = await client.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": index, "method": "initialize", "params": {"clientInfo": {"name": f"Name {index}"}}},
        )
        assert response.status_code == 200, response.text
        if "result" in response.json():
            accepted += 1
        else:
            assert response.json()["error"]["data"]["reason"] == "AGENT_LIMIT"
    assert 1 <= accepted <= MAX_AGENTS_PER_CLIENT
    names = [item["name"] for item in (await client.get("/agents")).json() if item["name"].startswith("Name ")]
    assert len(names) == accepted
    created = [item for item in (await client.get("/agents")).json() if item["name"] in {"Many Names", *names}]
    assert len(created) <= MAX_AGENTS_PER_CLIENT
    # An existing name still reconnects.
    again = await client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": 99, "method": "initialize", "params": {"clientInfo": {"name": "Name 0"}}},
    )
    assert "result" in again.json(), again.text


async def test_agent_cannot_choose_a_new_run_id(client, monkeypatch):
    calls, seen = {"n": 0}, []
    _people_, _groups, access, agent_id = await _payments(client, monkeypatch, calls, seen)
    chosen = "run_0123456789abcdef0123456789abcdef"
    body = await _request(client, access, agent_id, {"amount": 2}, run_id=chosen)
    assert body["error"]["data"]["reason"] == "UNKNOWN_RUN"
    generator, session = await _db()
    try:
        from app.models import Run

        assert await session.get(Run, chosen) is None
    finally:
        await _close(generator)
    fresh = await _request(client, access, agent_id, {"amount": 2})
    assert fresh["error"]["data"]["code"] == "approval_pending"
    assert fresh["error"]["data"]["saturnRunId"] != chosen


async def test_www_authenticate_uses_the_configured_origin(client, monkeypatch):
    monkeypatch.setenv("PUBLIC_WS_URL", "https://api.saturn-core.com")
    response = await client.post(
        "/mcp",
        headers={"Authorization": "", "Host": "evil.example"},
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )
    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert "https://api.saturn-core.com/.well-known/oauth-protected-resource" in challenge
    assert "evil.example" not in challenge
    monkeypatch.setenv("PUBLIC_WS_URL", "wss://ws.saturn-core.com")
    again = await client.post("/mcp", headers={"Authorization": ""}, json={"jsonrpc": "2.0", "id": 2, "method": "ping"})
    assert 'resource_metadata="https://ws.saturn-core.com/.well-known/oauth-protected-resource"' in again.headers["www-authenticate"]


async def test_session_ids_are_server_issued_and_owned(client):
    access, _refresh, client_id = await oauth_tokens(client, "Session Agent")
    headers = {"Authorization": f"Bearer {access}"}
    chosen = "attacker-chosen-session-id"
    opened = await client.post(
        "/mcp",
        headers={**headers, "Mcp-Session-Id": chosen},
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    assert opened.status_code == 200, opened.text
    issued = opened.headers["mcp-session-id"]
    assert issued and issued != chosen
    from app.features.mcp.saturn.services.mcp_sessions import mcp_sessions

    me = (await client.get("/auth/me")).json()["id"]
    assert await mcp_sessions.get(chosen, me, client_id) is None
    assert await mcp_sessions.get(issued, me, client_id) is not None

    unknown = await client.post(
        "/mcp",
        headers={**headers, "Mcp-Session-Id": "never-issued"},
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    )
    assert unknown.status_code == 404, unknown.text

    known = await client.post(
        "/mcp",
        headers={**headers, "Mcp-Session-Id": issued},
        json={"jsonrpc": "2.0", "id": 3, "method": "ping"},
    )
    assert known.status_code == 200, known.text

    other, _other_refresh, other_client = await oauth_tokens(client, "Other Agent")
    stolen = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {other}", "Mcp-Session-Id": issued},
        json={"jsonrpc": "2.0", "id": 4, "method": "tools/list"},
    )
    assert stolen.status_code == 404, stolen.text
    record = await mcp_sessions.get(issued, me, client_id)
    assert record is not None and record.client_id == client_id
    assert await mcp_sessions.open(issued, me, "agent_x", other_client) is None
    assert (await mcp_sessions.get(issued, me, client_id)) is not None


# L-26 / L-28 / I-09 -------------------------------------------------------------------------------


async def test_task_notice_needs_run_access_and_safe_text(client, monkeypatch):
    sent = []

    async def capture(email, **kwargs):
        sent.append(kwargs)
        return True

    monkeypatch.setattr("app.features.identity.auth.services.notices.send_notice", capture)
    assert (await client.patch("/auth/notices", json={"approval": False, "execute": False, "audit": False})).status_code == 200
    created = await client.post("/runs", json={"agent_id": "agent_customer_ops", "input": "Refund 50 for Acme"})
    assert created.status_code == 201, created.text
    run_id = created.json()["id"]
    people = await _people(client)
    viewer = await client.post(f"/runs/{run_id}/notice", headers=_auth(people[3][1]), json={"status": "completed"})
    assert viewer.status_code in {403, 404}, viewer.text
    missing = await client.post("/runs/run_missing/notice", json={"status": "failed"})
    assert missing.status_code == 404, missing.text
    too_long = await client.post(f"/runs/{run_id}/notice", json={"status": "completed", "summary": "x " * 200})
    assert too_long.status_code == 422, too_long.text
    from app.features.identity.auth.services.notices import _summary_text

    assert _summary_text("Refund sent to Acme") == "Refund sent to Acme"
    assert _summary_text("Verify your account at https://evil.example/login") == ""
    assert _summary_text("Call support at evil.example now") == ""
    assert _summary_text("Write to help@evil.example") == ""
    assert _summary_text("<b>urgent</b>") == ""


async def test_approve_with_malformed_json_is_a_400(client):
    created = await client.post("/runs", json={"agent_id": "agent_customer_ops", "input": "Refund Acme's duplicate charge."})
    assert created.status_code == 201, created.text
    approval_id = created.json()["approval_id"]
    broken = await client.post(
        f"/approvals/{approval_id}/approve",
        content=b"{not json",
        headers={"Content-Type": "application/json"},
    )
    assert broken.status_code == 400, broken.text
    assert (await client.get(f"/approvals/{approval_id}")).json()["status"] == "pending"


async def test_unreadable_sealed_arguments_fail_closed(client):
    created = await client.post("/runs", json={"agent_id": "agent_customer_ops", "input": "Refund Acme's duplicate charge."})
    assert created.status_code == 201, created.text
    approval_id = created.json()["approval_id"]
    generator, session = await _db()
    try:
        from app.models import Action, Approval

        approval = await session.get(Approval, approval_id)
        action = await session.get(Action, approval.action_id)
        action.arguments = {"sealed": "s2." + "00" * 40}
        approval.parameter_digest = None
        await session.commit()
    finally:
        await _close(generator)
    approved = await client.post(f"/approvals/{approval_id}/approve")
    assert approved.status_code == 403, approved.text
    run = (await client.get(f"/runs/{created.json()['id']}")).json()
    assert run["status"] == "failed"


def test_keyed_digest_accepts_legacy_rows():
    from app.features.execution.approvals.services.approval_arguments import digest_matches, keyed_digest, legacy_digest

    arguments = {"amount": 42, "to": "acct_1"}
    keyed = keyed_digest("org_saturn", arguments)
    assert len(keyed) == 64
    assert keyed != legacy_digest(arguments)
    assert keyed != keyed_digest("org_other", arguments)
    assert digest_matches("org_saturn", keyed, arguments)
    assert digest_matches("org_saturn", legacy_digest(arguments), arguments)
    assert not digest_matches("org_saturn", keyed, {"amount": 43, "to": "acct_1"})
    assert not digest_matches("org_other", keyed, arguments)


async def test_requester_needs_a_second_person_when_one_exists(client, monkeypatch):
    calls, seen = {"n": 0}, []
    people, _groups, access, agent_id = await _payments(client, monkeypatch, calls, seen)
    body = await _request(client, access, agent_id, {"amount": 7})
    approval_id = body["error"]["data"]["approval_id"]

    own = await client.post(f"/approvals/{approval_id}/approve")
    assert own.status_code == 403, own.text
    assert calls["n"] == 0
    other = await client.post(f"/approvals/{approval_id}/approve", headers=_auth(people[0][1]))
    assert other.status_code == 200, other.text


async def test_requester_alone_in_the_org_can_still_approve(client, monkeypatch):
    async def listed(endpoint, authorization=""):
        return [{"name": "pay.send", "description": "Send", "inputSchema": {"type": "object", "properties": {}}}]

    monkeypatch.setattr("app.features.mcp.servers.services.mcp_connect.list_remote_tools", listed)
    connected = await client.post(
        "/mcp-servers", json={"name": "Payments", "endpoint": "https://mcp.stripe.com/mcp", "authorization": "t"}
    )
    tool_id = connected.json()["catalog"][0]["id"]
    created = await client.post("/tool-sets", json={"name": "Payments", "items": [{"tool_id": tool_id, "approval": True}]})
    access = await oauth_access(client, "Solo Agent")
    await client.post("/mcp", headers=_auth(access), json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    agent_id = next(item["id"] for item in (await client.get("/agents")).json() if item["name"] == "Solo Agent")
    await client.patch(f"/agents/{agent_id}", json={"tool_set_id": created.json()["id"]})
    body = await _request(client, access, agent_id, {"amount": 7})
    approved = await client.post(f"/approvals/{body['error']['data']['approval_id']}/approve")
    assert approved.status_code == 200, approved.text


async def test_mcp_refuses_oversized_bodies(client):
    access = await oauth_access(client, "Big Body")
    huge = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"pad": "x" * (300 * 1024)}}
    response = await client.post("/mcp", headers={"Authorization": f"Bearer {access}"}, json=huge)
    assert response.status_code == 413


async def test_an_agent_cannot_flood_the_approval_queue(client, monkeypatch):
    from app.features.mcp.saturn.services import saturn_mcp as module

    monkeypatch.setattr(module, "MAX_PENDING_APPROVALS_PER_AGENT", 2)
    calls, seen = {"n": 0}, []
    _people_list, _groups, access, agent_id = await _payments(client, monkeypatch, calls, seen)
    for n in range(2):
        held = await _request(client, access, agent_id, {"amount": n})
        assert held["error"]["data"]["code"] == "approval_pending"
    refused = await _request(client, access, agent_id, {"amount": 99})
    assert "too_many_pending_approvals" in refused["error"]["message"]
    listed = await client.get("/approvals", params={"limit": 1})
    assert listed.status_code == 200 and len(listed.json()) == 1


# Stored results ------------------------------------------------------------------------------------


async def test_an_executed_result_is_stored_sealed_and_still_replays(client, monkeypatch):

    from app.cli.seal_results import seal_plain_results
    from app.models import Action
    from app.schemas import ActionRead

    calls, seen = {"n": 0}, []
    people, _groups, access, agent_id = await _payments(client, monkeypatch, calls, seen)
    body = await _request(client, access, agent_id, {"amount": 900})
    approval_id = body["error"]["data"]["approval_id"]
    run_id = body["error"]["data"]["saturnRunId"]
    assert (await client.post(f"/approvals/{approval_id}/approve", headers=_auth(people[0][1]))).status_code == 200
    ran = await _request(client, access, agent_id, {"amount": 900}, run_id=run_id)
    assert ran["result"]["echo"] == {"amount": 900}

    generator, session = await _db()
    try:
        action = (await session.scalars(select(Action).where(Action.run_id == run_id))).one()
        # What the upstream answered is not readable in the database.
        assert set(action.result) == {"sealed", "encryption"}
        # Checked with words hex cannot spell: the ciphertext is random hex, which holds "900" now and then.
        assert "echo" not in str(action.result) and "amount" not in str(action.result)
        # A run response carries a marker, not the result or its ciphertext.
        assert ActionRead.model_validate(action).result == {"sealed": True}
    finally:
        await _close(generator)

    # A repeated call is answered from the sealed copy and does not run again.
    again = await _request(client, access, agent_id, {"amount": 900}, run_id=run_id)
    assert again["result"]["echo"] == {"amount": 900}
    assert calls["n"] == 1

    # A row from before results were sealed is sealed by the one-off command, and still replays.
    generator, session = await _db()
    try:
        action = (await session.scalars(select(Action).where(Action.run_id == run_id))).one()
        action.result = {"echo": {"amount": 900}, "tool": "pay.send"}
        await session.commit()
        assert await seal_plain_results(session, apply=False) == 1
        assert await seal_plain_results(session, apply=True) == 1
        assert await seal_plain_results(session, apply=True) == 0
        await session.refresh(action)
        assert set(action.result) == {"sealed", "encryption"}
    finally:
        await _close(generator)
    replay = await _request(client, access, agent_id, {"amount": 900}, run_id=run_id)
    assert replay["result"]["echo"] == {"amount": 900}
    assert calls["n"] == 1
