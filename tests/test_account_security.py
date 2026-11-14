import pytest

from app.features.identity.auth.services.auth_service import RECENT_AUTH
from tests.oauth_access import oauth_tokens


async def _refresh(client, refresh: str, client_id: str):
    saved = client.headers.get("Authorization")
    client.headers.pop("Authorization", None)
    try:
        return await client.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": refresh, "client_id": client_id},
        )
    finally:
        if saved:
            client.headers["Authorization"] = saved


@pytest.mark.asyncio
async def test_password_changes_revoke_oauth_tokens(client, monkeypatch):
    async def noop(*_args, **_kwargs):
        return None

    monkeypatch.setattr("app.features.identity.auth.controllers.auth.send_reset_code", noop)
    access, refresh, client_id = await oauth_tokens(client, "Security Agent")
    opened = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {access}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    assert opened.status_code == 200, opened.text

    changed = await client.patch(
        "/auth/password",
        json={"current_password": "saturn", "new_password": "saturn-new"},
    )
    assert changed.status_code == 204, changed.text
    blocked = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {access}"},
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
    assert blocked.status_code == 401
    assert (await _refresh(client, refresh, client_id)).status_code == 400

    requested = await client.post("/auth/forgot-password", json={"email": "rick@saturn.ai"})
    assert requested.status_code == 204, requested.text
    again = await client.post("/auth/forgot-password", json={"email": "nobody-reset@saturn.ai"})
    assert again.status_code == 204
    limited = await client.post("/auth/forgot-password", json={"email": "nobody-reset@saturn.ai"})
    assert limited.status_code == 429
    known = await client.post("/auth/forgot-password", json={"email": "rick@saturn.ai"})
    assert known.status_code == 429


@pytest.mark.asyncio
async def test_admin_reset_and_downgrade_revoke_oauth_tokens(client, monkeypatch):
    invited = await client.post(
        "/org/invites",
        json={"email": "agent-user@saturn.ai", "name": "Agent User", "role": "operator"},
    )
    assert invited.status_code == 201, invited.text
    accepted = await client.post(
        "/auth/accept-invite",
        json={"token": invited.json()["token"], "password": "password1"},
    )
    assert accepted.status_code == 200, accepted.text
    member_id = accepted.json()["user"]["employee"]["id"]
    access, refresh, client_id = await oauth_tokens(
        client,
        "Operator Agent",
        email="agent-user@saturn.ai",
        password="password1",
    )
    usable = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {access}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    assert usable.status_code == 200, usable.text

    org_id = (await client.get("/org")).json()["organization"]["id"]
    sent = []

    async def capture(email, code, _locale=None):
        sent.append((email, code))

    monkeypatch.setattr("app.shared.runtime.email_configured", lambda: True)
    monkeypatch.setattr("app.features.identity.auth.services.mailer.send_reset_code", capture)
    reset = await client.post(
        f"/admin/orgs/{org_id}/members/{member_id}/password",
        json={"password": "password2"},
    )
    assert reset.status_code == 200, reset.text
    assert (await _refresh(client, refresh, client_id)).status_code == 400
    # The user, not the admin, picks the new password with the emailed code.
    chosen = await client.post(
        "/auth/reset-password",
        json={"email": "agent-user@saturn.ai", "code": sent[-1][1], "password": "password2"},
    )
    assert chosen.status_code == 204, chosen.text

    access, refresh, client_id = await oauth_tokens(
        client,
        "Operator Agent 2",
        email="agent-user@saturn.ai",
        password="password2",
    )
    downgraded = await client.patch(f"/org/members/{member_id}", json={"role": "viewer"})
    assert downgraded.status_code == 200, downgraded.text
    denied = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {access}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )
    assert denied.status_code == 401
    assert (await _refresh(client, refresh, client_id)).status_code == 400


@pytest.mark.asyncio
async def test_sensitive_changes_require_recent_auth_and_both_email_codes(client, monkeypatch):
    sent = []

    async def capture(email, code, kind, _locale=None):
        sent.append((email, code, kind))

    monkeypatch.setattr("app.features.identity.auth.controllers.auth.send_email_change_code", capture)
    monkeypatch.setattr("app.features.identity.auth.services.auth_service.RECENT_AUTH", __import__("datetime").timedelta(seconds=-1))
    assert RECENT_AUTH.total_seconds() == 600

    blocked = await client.delete("/auth/mfa/email")
    assert blocked.status_code == 403
    assert blocked.json()["detail"] == "Reauthentication required"

    confirmed = await client.post("/auth/reauth", json={"password": "saturn"})
    assert confirmed.status_code == 204, confirmed.text
    monkeypatch.setattr("app.features.identity.auth.services.auth_service.RECENT_AUTH", __import__("datetime").timedelta(minutes=10))
    opened = await client.delete("/auth/mfa/email")
    assert opened.status_code == 204, opened.text

    monkeypatch.setattr("app.features.identity.auth.services.auth_service.RECENT_AUTH", __import__("datetime").timedelta(seconds=-1))
    stale = await client.patch("/auth/me", json={"name": "Rick", "email": "rick-next@saturn.ai"})
    assert stale.status_code == 403
    await client.post("/auth/reauth", json={"password": "saturn"})
    monkeypatch.setattr("app.features.identity.auth.services.auth_service.RECENT_AUTH", __import__("datetime").timedelta(minutes=10))
    started = await client.patch("/auth/me", json={"name": "Rick", "email": "rick-next@saturn.ai"})
    assert started.status_code == 200, started.text
    assert started.json()["email"] == "rick@saturn.ai"
    assert started.json()["email_change_pending"] is True
    current = next(code for email, code, kind in sent if kind == "email_current")
    nxt = next(code for email, code, kind in sent if kind == "email_next" and email == "rick-next@saturn.ai")
    half = await client.post("/auth/email/confirm", json={"current_code": current, "next_code": "000000"})
    assert half.status_code == 400
    still = await client.get("/auth/me")
    assert still.json()["email"] == "rick@saturn.ai"
    done = await client.post("/auth/email/confirm", json={"current_code": current, "next_code": nxt})
    assert done.status_code == 200, done.text
    assert done.json()["email"] == "rick-next@saturn.ai"


@pytest.mark.asyncio
async def test_public_signup_does_not_reveal_an_existing_account(client, monkeypatch):
    async def noop(*_args, **_kwargs):
        return None

    monkeypatch.setattr("app.features.identity.auth.controllers.auth.send_signup_code", noop)
    first = await client.post(
        "/auth/register/code",
        json={"name": "New", "email": "fresh-account@saturn.ai", "password": "password1"},
    )
    assert first.status_code == 204, first.text
    second_new = await client.post(
        "/auth/register/code",
        json={"name": "New", "email": "fresh-account@saturn.ai", "password": "password1"},
    )
    existing = await client.post(
        "/auth/register/code",
        json={"name": "Rick", "email": "rick@saturn.ai", "password": "password1"},
    )
    second_existing = await client.post(
        "/auth/register/code",
        json={"name": "Rick", "email": "rick@saturn.ai", "password": "password1"},
    )
    assert existing.status_code == 204, existing.text
    assert second_new.status_code == second_existing.status_code == 429


@pytest.mark.asyncio
async def test_adding_a_factor_needs_a_recent_sign_in_and_tells_the_owner(client, monkeypatch):
    # A stolen session must not be able to enrol its own authenticator or passkey.
    from datetime import timedelta

    from app.features.identity.auth.services.totp import current_code

    told = []

    async def capture(email, factor, locale=None):
        told.append((email, factor))
        return True

    monkeypatch.setattr("app.features.identity.auth.controllers.auth.send_factor_added", capture)
    invited = await client.post("/org/invites", json={"email": "factor@saturn.ai", "name": "Factor", "role": "viewer"})
    assert invited.status_code == 201, invited.text
    accepted = await client.post("/auth/accept-invite", json={"token": invited.json()["token"], "password": "password1"})
    assert accepted.status_code == 200, accepted.text
    member = {"Authorization": f"Bearer {accepted.json()['token']}"}

    monkeypatch.setattr("app.features.identity.auth.services.auth_service.RECENT_AUTH", timedelta(seconds=-1))
    for path in ("/auth/totp/setup", "/auth/passkeys/options"):
        blocked = await client.post(path, headers=member, json={})
        assert blocked.status_code == 403, (path, blocked.text)
        assert blocked.json()["detail"] == "Reauthentication required"
    assert (await client.post("/auth/totp/confirm", headers=member, json={"code": "000000"})).status_code == 403
    assert (await client.post("/auth/passkeys", headers=member, json={"credential": {}})).status_code == 403

    monkeypatch.setattr("app.features.identity.auth.services.auth_service.RECENT_AUTH", timedelta(minutes=10))
    assert (await client.post("/auth/reauth", headers=member, json={"password": "password1"})).status_code == 204
    setup = await client.post("/auth/totp/setup", headers=member, json={})
    assert setup.status_code == 200, setup.text
    confirmed = await client.post("/auth/totp/confirm", headers=member, json={"code": current_code(setup.json()["secret"])})
    assert confirmed.status_code == 204, confirmed.text
    assert told == [("factor@saturn.ai", "totp")]


@pytest.mark.asyncio
async def test_signup_does_the_same_hashing_for_a_taken_address_as_for_a_free_one(client, monkeypatch):
    """The hashes are nearly all of the response time; skipping them told a taken address apart."""
    from app.features.identity.auth.services import mfa

    async def noop(*_args, **_kwargs):
        return None

    monkeypatch.setattr("app.features.identity.auth.controllers.auth.send_signup_code", noop)
    hashed: list[int] = []
    real = mfa.hash_password

    def counting(value):
        hashed.append(1)
        return real(value)

    monkeypatch.setattr(mfa, "hash_password", counting)

    async def cost(email):
        hashed.clear()
        answer = await client.post("/auth/register/code", json={"name": "N", "email": email, "password": "password1"})
        assert answer.status_code == 204, answer.text
        return len(hashed)

    assert await cost("free-address@saturn.ai") == await cost("rick@saturn.ai") == 2
