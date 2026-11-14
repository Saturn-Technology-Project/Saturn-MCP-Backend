"""Sign-in forms are not accepted from another site, and emailed codes have an account-wide guess limit."""

import pytest

from app.core import rate_limit

_FORM = {
    "response_type": "code",
    "client_id": "client",
    "redirect_uri": "http://127.0.0.1:8765/callback",
    "code_challenge": "c" * 43,
    "code_challenge_method": "S256",
    "state": "s",
}


@pytest.mark.parametrize("path", ["/oauth/login", "/oauth/login/code"])
async def test_oauth_sign_in_forms_are_refused_from_another_site(client, path):
    client.headers.pop("Authorization", None)
    body = {**_FORM, "email": "rick@saturn.ai", "password": "saturn", "challenge": "x", "code": "000000"}

    foreign = await client.post(path, data=body, headers={"Origin": "https://evil.example"})
    assert foreign.status_code == 403, foreign.text
    assert "saturn_oauth" not in foreign.headers.get("set-cookie", "")
    # A sandboxed frame or a stripped referrer reports the origin as "null".
    opaque = await client.post(path, data=body, headers={"Origin": "null"})
    assert opaque.status_code == 403, opaque.text
    flagged = await client.post(path, data=body, headers={"Sec-Fetch-Site": "cross-site"})
    assert flagged.status_code == 403, flagged.text


async def test_the_oauth_sign_in_page_still_signs_in_from_its_own_origin(client):
    client.headers.pop("Authorization", None)
    body = {**_FORM, "email": "rick@saturn.ai", "password": "saturn"}
    # The form on this origin's own page: same origin, as a browser reports it.
    own = await client.post(
        "/oauth/login", data=body, headers={"Origin": "http://test", "Sec-Fetch-Site": "same-origin"}, follow_redirects=False
    )
    assert own.status_code == 303, own.text
    # A client that is not a browser sends neither header.
    plain = await client.post("/oauth/login", data=body, follow_redirects=False)
    assert plain.status_code == 303, plain.text


async def test_wrong_emailed_codes_are_capped_per_account_across_challenges(client, monkeypatch):
    sent = {}

    async def capture(_email, code, _locale=None):
        sent["code"] = code

    monkeypatch.setattr("app.features.identity.auth.controllers.auth.send_login_code", capture)
    monkeypatch.setattr(rate_limit, "LOGIN_CODE_DAILY_FAILURES", 3)
    assert (await client.post("/auth/mfa/email/code")).status_code == 204
    assert (await client.post("/auth/mfa/email", json={"code": sent["code"]})).status_code == 204
    user_id = (await client.get("/auth/me")).json()["id"]

    async def challenge() -> str:
        started = await client.post("/auth/login", json={"email": "rick@saturn.ai", "password": "saturn"})
        assert started.status_code == 200, started.text
        return started.json()["challenge"]

    token = await challenge()
    wrong = "111111" if sent["code"] == "000000" else "000000"
    for _ in range(3):
        guess = await client.post("/auth/login/email", json={"challenge": token, "code": wrong})
        assert guess.status_code == 400, guess.text
    assert not await rate_limit.login_code_open(user_id)
    # Even the right code is refused now, on this challenge and on any other.
    locked = await client.post("/auth/login/email", json={"challenge": token, "code": sent["code"]})
    assert locked.status_code == 429, locked.text
    rate_limit.reset()
    assert await rate_limit.login_code_open(user_id)


async def test_a_right_code_does_not_count_as_a_failure():
    assert await rate_limit.login_code_open("user_x")
    for _ in range(rate_limit.LOGIN_CODE_DAILY_FAILURES - 1):
        await rate_limit.login_code_failed("user_x")
    assert await rate_limit.login_code_open("user_x")
    await rate_limit.login_code_failed("user_x")
    assert not await rate_limit.login_code_open("user_x")
    assert await rate_limit.login_code_open("user_y")


async def test_another_site_cannot_sign_a_visitor_out(client):
    from app.features.identity.auth.controllers.session_cookie import COOKIE_NAME

    token = client.headers.pop("Authorization").removeprefix("Bearer ")
    cookie = {"Cookie": f"{COOKIE_NAME}={token}"}
    forced = await client.post("/auth/logout", headers={**cookie, "Origin": "https://evil.example"})
    assert forced.status_code == 403, forced.text
    assert (await client.get("/auth/me", headers=cookie)).status_code == 200
    # The console's own origin still signs out.
    own = await client.post("/auth/logout", headers={**cookie, "Origin": "http://localhost:3000"})
    assert own.status_code == 204, own.text
    assert (await client.get("/auth/me", headers=cookie)).status_code == 401


async def test_oauth_pages_are_not_cached(client):
    page = await client.get("/oauth/authorize", params=_FORM)
    assert page.headers["cache-control"] == "no-store"


def test_redirect_schemes_a_browser_would_run_are_refused():
    from app.features.identity.oauth.services.oauth_service import redirect_allowed

    for uri in ("javascript:alert(1)", "JAVASCRIPT:alert(1)", "data:text/html,x", "vbscript:x", "about:blank", "filesystem:x", "file:///etc/passwd"):
        assert not redirect_allowed(uri), uri
    for uri in ("https://app.example/cb", "http://127.0.0.1:8765/callback", "cursor://anysphere.cursor-mcp/oauth/callback"):
        assert redirect_allowed(uri), uri


async def test_expired_sessions_and_agent_tokens_are_purged(client):
    from datetime import timedelta

    from sqlalchemy import func, select

    from app.core.ids import new_id, utcnow
    from app.db.database import get_session
    from app.features.identity.auth.models.session import AuthSession
    from app.features.identity.auth.services.throttle import purge_expired
    from app.features.identity.oauth.models.oauth import OAuthAccess
    from app.main import app

    user_id = (await client.get("/auth/me")).json()["id"]
    registered = await client.post(
        "/oauth/register", json={"client_name": "Purge", "redirect_uris": ["http://127.0.0.1:8765/callback"]}
    )
    client_id = registered.json()["client_id"]
    async for session in app.dependency_overrides[get_session]():
        old, recent = utcnow() - timedelta(days=3), utcnow() - timedelta(hours=1)
        for name, moment in (("old", old), ("recent", recent)):
            session.add(AuthSession(id=new_id("ses"), user_id=user_id, token_hash=f"hash-{name}", expires_at=moment))
            session.add(
                OAuthAccess(
                    id=new_id("oat"),
                    access_hash=f"access-{name}",
                    refresh_hash=f"refresh-{name}",
                    client_id=client_id,
                    user_id=user_id,
                    expires_at=moment,
                    refresh_expires_at=moment,
                )
            )
        await session.flush()
        await purge_expired(session)
        sessions = set(await session.scalars(select(AuthSession.token_hash).where(AuthSession.token_hash.like("hash-%"))))
        tokens = set(await session.scalars(select(OAuthAccess.access_hash).where(OAuthAccess.access_hash.like("access-%"))))
        # Only rows expired for more than a day go. The live session used by this test stays.
        assert sessions == {"hash-recent"} and tokens == {"access-recent"}
        assert await session.scalar(select(func.count()).select_from(AuthSession).where(AuthSession.user_id == user_id)) >= 2


def test_cloud_run_never_falls_back_to_localhost_origins(monkeypatch):
    from app import main

    monkeypatch.setattr(main.settings, "cors_origins", "")
    assert main._cors_origins() == ["http://localhost:3000", "http://localhost:3001"]
    monkeypatch.setenv("K_SERVICE", "saturn-backend")
    assert main._cors_origins() == []
