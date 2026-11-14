"""A request gives its database connection back before it waits on anything slow."""

from types import SimpleNamespace

from app.db.database import engine_options
from tests.test_payload_keys_hardening import _gateway


def _settings(**changes):
    values = {
        "db_pool_size": 5,
        "db_max_overflow": 10,
        "db_pool_timeout": 10.0,
        "db_pool_recycle": 1800,
        "db_command_timeout": 60.0,
    }
    values.update(changes)
    return SimpleNamespace(**values)


def test_postgres_engine_checks_connections_and_bounds_waits():
    options = engine_options("postgresql+asyncpg://u:p@db/saturn", _settings(db_pool_size=3, db_max_overflow=4))
    assert options["pool_size"] == 3 and options["max_overflow"] == 4
    assert options["pool_pre_ping"] is True
    assert options["pool_timeout"] == 10.0 and options["pool_recycle"] == 1800
    assert options["connect_args"] == {"command_timeout": 60.0}
    # 0 turns the statement limit off.
    unlimited = engine_options("postgresql+asyncpg://u:p@db/saturn", _settings(db_command_timeout=0))
    assert "connect_args" not in unlimited


def test_sqlite_engine_takes_no_pool_arguments():
    options = engine_options("sqlite+aiosqlite://", _settings())
    assert options == {"echo": False, "connect_args": {"check_same_thread": False}}


async def test_no_transaction_is_open_while_the_upstream_is_called(client, monkeypatch):
    call = await _gateway(client, monkeypatch)
    seen = {}

    from app.features.mcp.oauth.services.mcp_oauth import mcp_oauth

    original = mcp_oauth.authorization_for

    async def remember(session, server):
        seen["session"] = session
        return await original(session, server)

    async def called(endpoint, tool, arguments, authorization=""):
        seen["open"] = seen["session"].in_transaction()
        return {"content": [{"type": "text", "text": "ok"}]}

    monkeypatch.setattr(mcp_oauth, "authorization_for", remember)
    monkeypatch.setattr("app.features.mcp.saturn.services.saturn_mcp.call_remote_tool", called)
    first = await call({"repo": "one"})
    assert seen["open"] is False
    # The request record was committed before the upstream ran, and the numbering still advances by one.
    second = await call({"repo": "two"})
    rows = (await client.get("/activity", params={"tool": "repo.read"})).json()
    numbers = sorted(item["payload"]["audit_no"] for item in rows if item["event"] == "tool_requested")
    assert numbers == [numbers[0], numbers[0] + 1]
    assert first["payload"]["audit_no"] in numbers and second["payload"]["audit_no"] in numbers


async def test_a_failed_upstream_call_still_leaves_its_request_record(client, monkeypatch):
    call = await _gateway(client, monkeypatch)
    await call({"repo": "works"})

    async def broken(endpoint, tool, arguments, authorization=""):
        raise RuntimeError("upstream fell over")

    monkeypatch.setattr("app.features.mcp.saturn.services.saturn_mcp.call_remote_tool", broken)
    before = [item for item in (await client.get("/activity", params={"tool": "repo.read"})).json() if item["event"] == "tool_requested"]
    try:
        await call({"repo": "fails"})
    except Exception:
        pass
    after = [item for item in (await client.get("/activity", params={"tool": "repo.read"})).json() if item["event"] == "tool_requested"]
    # It used to be rolled back with the failed request, leaving an attempted call with no trace.
    assert len(after) == len(before) + 1


async def test_a_listening_stream_gives_its_connection_back_first(monkeypatch):
    from app.features.mcp.saturn.controllers import saturn_mcp as controller

    order = []

    class Session:
        async def commit(self):
            order.append("commit")

        async def close(self):
            order.append("close")

    async def caller(request, session):
        return SimpleNamespace(id="user_1"), "Agent", "client_1"

    async def found(session_id, user_id, client_id):
        return SimpleNamespace(queue=None)

    monkeypatch.setattr(controller, "_caller", caller)
    monkeypatch.setattr(controller.mcp_sessions, "get", found)
    request = SimpleNamespace(headers={"mcp-session-id": "s1"})
    response = await controller.saturn_mcp_listen(request, Session())
    order.append("stream returned")
    assert order == ["commit", "close", "stream returned"]
    assert response.media_type == "text/event-stream"


async def test_a_stream_that_ends_leaves_the_session_and_pings_while_silent(client, monkeypatch):
    """The platform ends every stream at its time limit. The client reopens it with the same session."""
    import asyncio

    from app.features.mcp.saturn.controllers import saturn_mcp as controller
    from tests.oauth_access import oauth_tokens

    access, _refresh_token, client_id = await oauth_tokens(client, "Stream Agent")
    headers = {"Authorization": f"Bearer {access}"}
    started = await client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}}},
    )
    assert started.status_code == 200, started.text
    session_id = started.headers["mcp-session-id"]
    me = (await client.get("/auth/me")).json()["id"]
    record = await controller.mcp_sessions.get(session_id, me, client_id)
    assert record is not None

    monkeypatch.setattr(controller, "STREAM_PING_SECONDS", 0.01)

    class Session:
        async def commit(self):
            return None

        async def close(self):
            return None

    async def caller(_request, _session):
        return SimpleNamespace(id=me), "Stream Agent", client_id

    with monkeypatch.context() as patched:
        patched.setattr(controller, "_caller", caller)
        response = await controller.saturn_mcp_listen(SimpleNamespace(headers={"mcp-session-id": session_id}), Session())
    stream = response.body_iterator
    assert await anext(stream) == ": connected\n\n"
    assert await anext(stream) == ": ping\n\n"
    await controller.mcp_sessions.notify([record.agent_id] if record.agent_id else [])
    # The stream is cut off, the way a request time limit cuts it.
    await stream.aclose()
    await asyncio.sleep(0)
    assert await controller.mcp_sessions.get(session_id, me, client_id) is not None
    again = await client.post("/mcp", headers={**headers, "Mcp-Session-Id": session_id}, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert again.status_code == 200 and "result" in again.json(), again.text
