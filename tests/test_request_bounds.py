"""Request bodies and per-client memory are bounded."""

from app.core.body_limit import DEFAULT_MAX_BYTES, SMALL_MAX_BYTES, limit_for
from app.features.mcp.saturn.services import mcp_sessions as sessions_module
from app.features.mcp.saturn.services.mcp_sessions import LIST_CHANGED, MAX_QUEUED_NOTICES, McpSessionHub


def test_unauthenticated_routes_get_the_small_limit():
    for path in ("/oauth/register", "/oauth/login", "/oauth/token", "/auth/login", "/auth/register", "/auth/reset-password"):
        assert limit_for(path) == SMALL_MAX_BYTES, path
    for path in ("/auth/me/photo", "/policies", "/org/payload-keys/rotate/batch", "/mcp"):
        assert limit_for(path) == DEFAULT_MAX_BYTES, path


async def test_a_large_body_is_refused_before_it_is_read(client):
    big = "x" * (SMALL_MAX_BYTES + 1)
    refused = await client.post("/oauth/register", json={"client_name": big, "redirect_uris": ["https://a.example/cb"]})
    assert refused.status_code == 413, refused.text
    assert refused.json()["detail"] == "Request body is too large"
    # The security headers still apply to the refusal.
    assert refused.headers["x-content-type-options"] == "nosniff"
    login = await client.post("/auth/login", json={"email": "a@b.co", "password": big})
    assert login.status_code == 413, login.text


async def test_a_body_without_a_length_is_cut_off_at_the_limit(client):
    async def chunks():
        for _ in range(3):
            yield b"a" * (SMALL_MAX_BYTES // 2)

    # A streamed body has no Content-Length, so the limit has to count as it reads.
    form = await client.post("/oauth/login", content=chunks(), headers={"content-type": "application/x-www-form-urlencoded"})
    assert form.status_code == 413, form.text
    registered = await client.post("/oauth/register", content=chunks(), headers={"content-type": "application/json"})
    assert registered.status_code == 413, registered.text


async def test_an_ordinary_request_is_unaffected(client):
    registered = await client.post(
        "/oauth/register", json={"client_name": "Agent", "redirect_uris": ["http://127.0.0.1:8765/callback"]}
    )
    assert registered.status_code == 201, registered.text
    photo = await client.patch("/auth/me/photo", json={"photo": None})
    assert photo.status_code != 413


async def test_a_redirect_uri_has_a_length_limit(client):
    long = "https://a.example/" + "c" * 2048
    refused = await client.post("/oauth/register", json={"client_name": "Agent", "redirect_uris": [long]})
    assert refused.status_code == 400, refused.text
    assert refused.json()["detail"] == "redirect_uri is too long"


async def test_sessions_without_an_agent_do_not_pile_up():
    hub = McpSessionHub()
    for index in range(50):
        await hub.open(f"s{index}", "user_1", "", "client_1")
    assert len(hub._items) == sessions_module.MAX_UNBOUND_PER_CLIENT
    # The newest ones are the ones kept.
    assert "s49" in hub._items and "s0" not in hub._items
    # Another client's sessions are counted separately.
    await hub.open("other", "user_1", "", "client_2")
    assert len(hub._items) == sessions_module.MAX_UNBOUND_PER_CLIENT + 1


async def test_the_local_session_table_has_a_ceiling(monkeypatch):
    monkeypatch.setattr(sessions_module, "MAX_LOCAL_SESSIONS", 5)
    hub = McpSessionHub()
    for index in range(20):
        await hub.open(f"s{index}", f"user_{index}", f"agent_{index}", "client_1")
    assert list(hub._items) == ["s15", "s16", "s17", "s18", "s19"]


async def test_idle_sessions_expire(monkeypatch):
    hub = McpSessionHub()
    await hub.open("old", "user_1", "agent_1", "client_1")
    hub._items["old"].touched -= sessions_module.SESSION_TTL + 1
    await hub.open("new", "user_2", "agent_2", "client_2")
    assert list(hub._items) == ["new"]


async def test_unread_notices_are_bounded_and_the_stream_still_ends():
    hub = McpSessionHub()
    record = await hub.open("s1", "user_1", "agent_1", "client_1")
    for _ in range(MAX_QUEUED_NOTICES * 4):
        await hub.notify(["agent_1"])
    assert record.queue.qsize() == MAX_QUEUED_NOTICES
    await hub.close("s1")
    # The end marker is in the queue even though it was full.
    seen = []
    while not record.queue.empty():
        seen.append(record.queue.get_nowait())
    assert seen[-1] is None and seen[0] == LIST_CHANGED


async def test_webhook_tests_are_rate_limited(client, monkeypatch):
    sent = {"n": 0}

    from fastapi import HTTPException

    async def stub(session, organization_id, endpoint_id):
        sent["n"] += 1
        raise HTTPException(404, "Endpoint not found")

    monkeypatch.setattr("app.features.webhooks.controllers.webhooks.send_test", stub)
    codes = [(await client.post("/org/webhooks/whe_missing/test")).status_code for _ in range(32)]
    assert codes[:30] == [404] * 30
    assert codes[30:] == [429, 429]
    assert sent["n"] == 30


async def test_the_runs_list_is_paged(client):
    assert (await client.get("/runs?limit=0")).status_code == 422
    assert (await client.get("/runs?limit=501")).status_code == 422
    page = await client.get("/runs?limit=1")
    assert page.status_code == 200, page.text
    assert isinstance(page.json(), list) and len(page.json()) <= 1


async def test_expiry_only_loads_approvals_that_are_due(client, monkeypatch):
    from datetime import timedelta

    from app.core.ids import utcnow
    from app.db.database import get_session
    from app.features.execution.approvals.services import expiration
    from app.main import app
    from app.models import Approval
    from tests.test_approval_hardening import _payments
    from tests.test_quorum import _request

    calls, seen = {"n": 0}, []
    _people, _groups, access, agent_id = await _payments(client, monkeypatch, calls, seen)
    first = (await _request(client, access, agent_id, {"amount": 1}))["error"]["data"]["approval_id"]
    second = (await _request(client, access, agent_id, {"amount": 2}))["error"]["data"]["approval_id"]

    checked = []
    real = expiration.expire_if_due

    async def spy(session, approval, now):
        checked.append(approval.id)
        return await real(session, approval, now)

    monkeypatch.setattr(expiration, "expire_if_due", spy)
    async for session in app.dependency_overrides[get_session]():
        due = await session.get(Approval, first)
        due.expires_at = utcnow() - timedelta(minutes=1)
        await session.flush()
        assert await expiration.expire_due(session) == 1
    # The one still inside its window was never loaded.
    assert checked == [first]
    assert (await client.get(f"/approvals/{first}")).json()["status"] == "expired"
    assert (await client.get(f"/approvals/{second}")).json()["status"] == "pending"


async def test_approval_policy_and_key_requests_have_field_limits(client):
    long_name = await client.post("/org/approval-policies", json={"name": "n" * 256})
    assert long_name.status_code == 422, long_name.text
    many = await client.post(
        "/org/approval-policies",
        json={"name": "ok", "requirements": [{"group_id": "g", "required_count": 1}] * 51},
    )
    assert many.status_code == 422, many.text

    oversized_key = await client.post("/org/payload-keys/member", json={"public_key": "a" * 16_385})
    assert oversized_key.status_code == 422, oversized_key.text
    # A real ML-KEM-1024 public key (3,136 hex characters) is nowhere near the limit.
    assert 3_136 * 4 < 16_384


async def test_approve_refuses_an_oversized_body_before_reading_it_as_json(client):
    from app.features.execution.approvals.controllers.approvals import MAX_APPROVE_BODY_BYTES

    body = b'{"arguments": {"note": "' + b"a" * MAX_APPROVE_BODY_BYTES + b'"}}'
    answer = await client.post("/approvals/apr_missing/approve", content=body, headers={"Content-Type": "application/json"})
    assert answer.status_code == 413, answer.text
    # A normal body still reaches the approval lookup.
    assert (await client.post("/approvals/apr_missing/approve", json={"arguments": {}})).status_code == 404
