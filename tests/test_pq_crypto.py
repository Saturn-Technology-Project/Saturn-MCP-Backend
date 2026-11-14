import base64

import pytest

from app.features.credentials.vault.services.credential_service import open_secret, seal
from app.features.credentials.vault.services.pq_crypto import SecretNeedsReconnect


def test_credentials_use_mlkem_1024_and_hide_the_plaintext():
    token = seal("gho-example-token", "org_acme")
    assert token.startswith("pq2.")
    assert "gho-example-token" not in token
    assert open_secret(token, "org_acme") == "gho-example-token"
    with pytest.raises(SecretNeedsReconnect):
        open_secret(token, "org_other")
    with pytest.raises(SecretNeedsReconnect):
        open_secret(token, "org_acme", "user_other")
    raw = base64.b64decode(token.removeprefix("pq2."))
    assert len(raw) > 1568


def test_tampered_ciphertext_does_not_open():
    token = seal("gho-example-token", "org_acme")
    raw = bytearray(base64.b64decode(token.removeprefix("pq2.")))
    raw[-1] ^= 1
    broken = "pq2." + base64.b64encode(bytes(raw)).decode()
    with pytest.raises(SecretNeedsReconnect):
        opened = open_secret(broken, "org_acme")
        assert opened != ""


def test_content_key_is_reused_until_it_expires():
    from app.features.credentials.vault.services import pq_crypto

    pq_crypto._content_keys.clear()
    first = pq_crypto.content_key("org_acme")
    assert pq_crypto.content_key("org_acme") == first
    assert "org_acme" in pq_crypto._content_keys


def test_tenants_do_not_share_a_credential_key():
    from app.features.credentials.vault.services import pq_crypto

    assert pq_crypto.mlkem_seed("org_acme") != pq_crypto.mlkem_seed("org_other")
    assert pq_crypto.mlkem_seed("org_acme", "user_a") != pq_crypto.mlkem_seed("org_acme", "user_b")
    assert pq_crypto.content_key("org_acme") != pq_crypto.content_key("org_other")


def test_missing_kms_key_refuses_to_start(monkeypatch):
    from app.features.credentials.vault.services import pq_crypto

    monkeypatch.setattr(pq_crypto, "_root", None)
    monkeypatch.setattr(pq_crypto, "_keys", {})
    monkeypatch.delenv("SATURN_KMS_KEY", raising=False)
    try:
        with pytest.raises(RuntimeError, match="SATURN_KMS_KEY"):
            pq_crypto.require_root()
    finally:
        pq_crypto.install_root(b"\x11" * 32)


@pytest.mark.asyncio
async def test_connected_mcp_keeps_the_token_out_of_the_server_row(client, monkeypatch):
    async def listed(endpoint, authorization=""):
        assert authorization == "access-1"
        return [{"name": "docs", "description": "Docs", "inputSchema": {"type": "object", "properties": {}}}]

    monkeypatch.setattr("app.features.mcp.servers.services.mcp_connect.list_remote_tools", listed)
    created = await client.post(
        "/mcp-servers",
        json={"name": "Context7", "endpoint": "https://mcp.context7.com/mcp", "authorization": "access-1"},
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["has_authorization"] is True
    assert "access-1" not in created.text

    from app.db.database import get_session
    from app.main import app
    from app.models import McpServer, SecretVault

    session_gen = app.dependency_overrides[get_session]()
    session = await session_gen.__anext__()
    try:
        server = await session.get(McpServer, body["id"])
        assert server.credential_id.startswith("mcp-")
        vault = await session.get(SecretVault, server.credential_id)
        # Bound to its vault entry, so it does not open anywhere else.
        assert vault.ciphertext.startswith("pq3.")
        assert "access-1" not in vault.ciphertext
    finally:
        await session_gen.aclose()


def test_a_bound_value_only_opens_where_it_was_sealed_for(monkeypatch):
    from app.features.credentials.vault.services.pq_crypto import SecretNeedsReconnect, open_secret, seal

    token = seal("bearer-for-server-1", "org_a", "", "vault:mcp-server-1")
    assert token.startswith("pq3.")
    assert open_secret(token, "org_a", "", "vault:mcp-server-1") == "bearer-for-server-1"
    # Copied onto another server's vault entry, it refuses to open.
    with pytest.raises(SecretNeedsReconnect):
        open_secret(token, "org_a", "", "vault:mcp-server-2")
    # Editing the visible context does not help: it is authenticated.
    from app.features.credentials.vault.services.pq_crypto import join_bound, split_bound

    _context, blob = split_bound(token)
    with pytest.raises(SecretNeedsReconnect):
        open_secret(join_bound("vault:mcp-server-2", blob), "org_a", "", "vault:mcp-server-2")
    # Unbound values from before still open, until the operator requires bound ones.
    legacy = seal("old", "org_a", "")
    assert open_secret(legacy, "org_a", "", "vault:mcp-server-1") == "old"
    monkeypatch.setenv("SATURN_REQUIRE_BOUND_SECRETS", "true")
    with pytest.raises(SecretNeedsReconnect):
        open_secret(legacy, "org_a", "", "vault:mcp-server-1")


def test_the_tenant_key_cache_is_bounded(monkeypatch):
    from app.features.credentials.vault.services import pq_crypto

    monkeypatch.setattr(pq_crypto, "_MAX_CACHED_KEYS", 3)
    pq_crypto._keys.clear()
    for n in range(6):
        pq_crypto.open_secret(pq_crypto.seal("x", f"org_{n}"), f"org_{n}")
    assert len(pq_crypto._keys) <= 3


def test_a_key_service_outage_is_not_reported_as_a_broken_secret(monkeypatch):
    """SecretNeedsReconnect tells people to reconnect and kills webhook deliveries. An outage ends by itself."""
    from app.features.credentials.vault.services import pq_crypto

    token = seal("gho-example-token", "org_acme")

    def down(_data):
        raise ConnectionError("kms did not answer")

    monkeypatch.setattr(pq_crypto, "_mac", down)
    monkeypatch.setattr(pq_crypto, "_keys", {})
    with pytest.raises(pq_crypto.KeyUnavailable):
        open_secret(token, "org_acme")
    monkeypatch.undo()
    assert open_secret(token, "org_acme") == "gho-example-token"


def test_the_key_cache_survives_many_threads_at_its_limit(monkeypatch):
    """seal and open run on worker threads; evicting while another thread iterates used to raise."""
    from concurrent.futures import ThreadPoolExecutor

    from app.features.credentials.vault.services import pq_crypto

    monkeypatch.setattr(pq_crypto, "_MAX_CACHED_KEYS", 4)
    monkeypatch.setattr(pq_crypto, "_keys", {})
    tokens = {f"org_{index}": seal("value", f"org_{index}") for index in range(12)}

    def work(turn: int) -> bool:
        organization_id = f"org_{turn % 12}"
        return open_secret(tokens[organization_id], organization_id) == "value"

    with ThreadPoolExecutor(max_workers=16) as pool:
        assert all(pool.map(work, range(400)))
    assert len(pq_crypto._keys) <= 4


async def test_the_content_key_is_fetched_off_the_event_loop_before_it_is_needed(monkeypatch):
    """A KMS call made while sealing would hold the event loop for every request."""
    import threading

    from app.features.credentials.vault.services import pq_crypto

    loop_thread = threading.get_ident()
    calls: list[bool] = []
    real = pq_crypto._mac

    def mac(data):
        calls.append(threading.get_ident() == loop_thread)
        return real(data)

    monkeypatch.setattr(pq_crypto, "_mac", mac)
    monkeypatch.setattr(pq_crypto, "_content_keys", {})
    await pq_crypto.warm_content_key("org_warm")
    assert calls == [False]
    # The synchronous readers now find it, and warming again does nothing until it nears expiry.
    key = pq_crypto.content_key("org_warm")
    await pq_crypto.warm_content_key("org_warm")
    assert calls == [False]
    expires, _ = pq_crypto._content_keys["org_warm"]
    pq_crypto._content_keys["org_warm"] = (expires - pq_crypto._CONTENT_TTL_SECONDS + 10, key)
    await pq_crypto.warm_content_key("org_warm")
    assert calls == [False, False]

    def down(_data):
        raise ConnectionError("kms did not answer")

    monkeypatch.setattr(pq_crypto, "_mac", down)
    monkeypatch.setattr(pq_crypto, "_content_keys", {})
    await pq_crypto.warm_content_key("org_warm")  # left for the code that needs the key to report
