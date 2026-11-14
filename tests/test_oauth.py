import re
from urllib.parse import parse_qs, urlparse

import pytest

from app.features.identity.oauth.services.oauth_service import pkce_s256


@pytest.mark.asyncio
async def test_agent_registers_with_oauth_and_binds_its_profile(client):
    session = client.headers["Authorization"]
    client.headers.pop("Authorization")

    blocked = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert blocked.status_code == 401
    assert "oauth-protected-resource" in blocked.headers["www-authenticate"]

    metadata = await client.get("/.well-known/oauth-authorization-server")
    assert metadata.status_code == 200
    assert metadata.json()["registration_endpoint"].endswith("/oauth/register")
    resource = await client.get("/.well-known/oauth-protected-resource")
    assert resource.json()["resource"].endswith("/mcp")

    verifier = "a" * 43
    challenge = pkce_s256(verifier)
    registered = await client.post(
        "/oauth/register",
        json={
            "client_name": "Cursor",
            "redirect_uris": ["http://127.0.0.1:8765/callback"],
        },
    )
    assert registered.status_code == 201, registered.text
    desktop = await client.post(
        "/oauth/register",
        json={"redirect_uris": ["cursor://anysphere.cursor-mcp/oauth/callback"]},
    )
    assert desktop.status_code == 201, desktop.text
    client_id = registered.json()["client_id"]
    query = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": "http://127.0.0.1:8765/callback",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "xyz",
    }
    login_page = await client.get("/oauth/authorize", params=query)
    assert login_page.status_code == 200
    assert "Sign in" in login_page.text

    signed = await client.post(
        "/oauth/login",
        data={**query, "email": "rick@saturn.ai", "password": "saturn"},
        follow_redirects=False,
    )
    assert signed.status_code == 303
    consent = await client.get(signed.headers["location"])
    assert "org_saturn:user_operator" in consent.text
    assert "授權代理人" in consent.text
    assert "僅建立連線" in consent.text
    assert "Set：" not in consent.text
    assert "Policy：" not in consent.text
    assert 'type="checkbox"' not in consent.text
    assert "服務條款" in consent.text
    assert "<code>127.0.0.1:8765</code>" in consent.text
    # Browsers check form-action on the 303 that follows the submit, so the agent's origin must be listed.
    assert "form-action 'self' http://127.0.0.1:8765;" in consent.headers["content-security-policy"]
    csrf = re.search(r'name="csrf" value="([^"]+)"', consent.text)
    assert csrf is not None
    allowed = await client.post(
        "/oauth/consent",
        data={**query, "csrf": csrf.group(1), "decision": "allow"},
        follow_redirects=False,
    )
    assert allowed.status_code == 303
    location = urlparse(allowed.headers["location"])
    params = parse_qs(location.query)
    assert params["state"] == ["xyz"]
    code = params["code"][0]

    token = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "redirect_uri": "http://127.0.0.1:8765/callback",
            "code_verifier": verifier,
        },
    )
    assert token.status_code == 200, token.text
    access = token.json()["access_token"]
    assert access.startswith("sat_oa_")

    reused = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "redirect_uri": "http://127.0.0.1:8765/callback",
            "code_verifier": verifier,
        },
    )
    assert reused.status_code == 400

    opened = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {access}"},
        json={"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}},
    )
    assert opened.status_code == 200, opened.text
    assert opened.json()["result"]["serverInfo"]["name"] == "Saturn MCP"

    client.headers["Authorization"] = session
    listed = (await client.get("/agents")).json()
    cursor = next(item for item in listed if item["name"] == "Cursor")
    assert cursor["origin"] == "saturn_mcp"
    assert cursor["profile_id"] == "org_saturn:user_operator"


@pytest.mark.asyncio
async def test_root_does_not_advertise_the_build(client):
    response = await client.get("/")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_register_is_rate_limited(client, monkeypatch):
    async def refuse(_request):
        return False

    monkeypatch.setattr("app.features.identity.oauth.controllers.oauth.registration_allowed", refuse)
    response = await client.post(
        "/oauth/register",
        json={"redirect_uris": ["http://127.0.0.1:8765/callback"]},
    )
    assert response.status_code == 429
    assert response.headers["retry-after"] == "600"
