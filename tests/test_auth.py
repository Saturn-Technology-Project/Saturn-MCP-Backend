def test_verification_email_uses_the_account_language():
    from app.features.identity.auth.services.mailer import _code_message, _notice_message, mail_locale

    assert mail_locale("en-US,en;q=0.9") == "en-US"
    assert mail_locale("zh-TW,zh;q=0.9,en;q=0.8") == "zh-Hant"
    assert mail_locale("zh-Hant") == "zh-Hant"
    assert mail_locale(None) == "zh-Hant"

    zh_subject, zh_text, zh_html = _code_message("482193", "signup", "zh-Hant")
    en_subject, en_text, en_html = _code_message("482193", "signup", "en-US")
    assert zh_subject == "482193 是你的 Saturn 帳號確認碼"
    assert "確認你的帳號" in zh_text
    assert "Confirm your account" not in zh_text
    assert 'lang="zh-Hant"' in zh_html
    assert "Confirm your account" not in zh_html
    assert en_subject == "482193 is your Saturn confirmation code"
    assert "Confirm your account" in en_text
    assert "確認你的帳號" not in en_text
    assert 'lang="en-US"' in en_html
    assert "確認你的帳號" not in en_html
    assert "482193" in zh_html and "482193" in en_html
    assert "<script" not in zh_html

    notice_subject, notice_text, notice_html = _notice_message(
        "approval", "billing.refund", "Acme Ops", "https://dashboard.saturn-core.com/activity?event=1", "en-US"
    )
    assert notice_subject == "Saturn: Approval required — billing.refund"
    assert "Approval required" in notice_text
    assert "需要核准" not in notice_text
    assert "需要核准" not in notice_html


def test_reset_code_hash_fits_column():
    from app.features.identity.auth.models.password_reset import PasswordReset
    from app.features.identity.auth.services.auth_service import hash_password

    first = hash_password("123456")
    second = hash_password("123456")
    limit = PasswordReset.__table__.c.code_hash.type.length
    assert first.startswith("$argon2id$")
    assert first != second
    assert len(first) <= limit


async def test_login_and_me(client):
    me = await client.get("/auth/me")
    assert me.status_code == 200
    body = me.json()
    assert body["id"] == "user_operator"
    assert body["email"] == "rick@saturn.ai"
    assert body["organization"]["id"] == "org_saturn"
    assert body["enterprise"]["id"] == "org_saturn"
    assert body["role"] == "admin"
    assert body["permissions"]["team"] == "write"
    assert body["locale"] == "zh-Hant"
    updated = await client.patch("/auth/locale", json={"locale": "en"})
    assert updated.status_code == 200
    assert updated.json()["locale"] == "en-US"
    assert (await client.get("/auth/me")).json()["locale"] == "en-US"


async def test_legacy_password_is_refused_after_the_deadline(client, monkeypatch):
    import hashlib
    import secrets

    from app.db.database import get_session
    from app.features.identity.auth.services import auth_service as auth_module
    from app.main import app
    from app.models import User

    monkeypatch.setattr(auth_module, "legacy_password_allowed", lambda: False)
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", b"correct horse", bytes.fromhex(salt), 210_000)
    session_gen = app.dependency_overrides[get_session]()
    session = await session_gen.__anext__()
    try:
        user = await session.get(User, "user_operator")
        user.password_hash = f"pbkdf2_sha256$210000${salt}${digest.hex()}"
        await session.commit()
    finally:
        await session_gen.aclose()

    refused = await client.post(
        "/auth/login",
        json={"email": "rick@saturn.ai", "password": "v2." + ("ab" * 32), "legacy_password": "correct horse"},
    )
    assert refused.status_code == 401
    assert refused.json()["detail"]["migration"] == "reset"
    assert refused.json()["detail"]["message"] == "請重設密碼。 Reset your password."

    # The raw legacy password in the ordinary password field must not get around the deadline.
    raw = await client.post("/auth/login", json={"email": "rick@saturn.ai", "password": "correct horse"})
    assert raw.status_code == 401
    probe = await client.post("/auth/login/migration", json={"email": "rick@saturn.ai", "password": "correct horse"})
    assert probe.status_code == 200
    assert probe.json() == {}


async def test_migration_probe_is_limited_per_account(client):
    statuses = []
    for n in range(12):
        response = await client.post(
            "/auth/login/migration",
            headers={"X-Forwarded-For": f"10.2.0.{n}"},
            json={"email": "rick@saturn.ai", "password": f"guess-{n}"},
        )
        statuses.append(response.status_code)
    assert statuses[:10] == [200] * 10
    assert statuses[10:] == [429, 429]


async def test_legacy_password_is_rewritten_as_argon2id(client):
    import hashlib
    import secrets

    from app.db.database import get_session
    from app.main import app
    from app.models import User

    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", b"correct horse", bytes.fromhex(salt), 210_000)
    session_gen = app.dependency_overrides[get_session]()
    session = await session_gen.__anext__()
    try:
        user = await session.get(User, "user_operator")
        user.password_hash = f"pbkdf2_sha256$210000${salt}${digest.hex()}"
        await session.commit()
    finally:
        await session_gen.aclose()

    verifier = "v2." + ("ab" * 32)
    legacy_v1 = "v1." + hashlib.sha256(b"saturn-login-v1\ncorrect horse").hexdigest()
    first = await client.post("/auth/login", json={"email": "rick@saturn.ai", "password": verifier})
    assert first.status_code == 401
    assert first.json()["detail"]["migration"] == "v1"
    hinted = await client.post(
        "/auth/login",
        json={"email": "rick@saturn.ai", "password": verifier, "legacy_v1": legacy_v1},
    )
    assert hinted.status_code == 401
    assert hinted.json()["detail"]["migration"] == "password"
    second = await client.post(
        "/auth/login",
        json={"email": "rick@saturn.ai", "password": verifier, "legacy_password": "correct horse"},
    )
    assert second.status_code == 200, second.text
    again = await client.post("/auth/login", json={"email": "rick@saturn.ai", "password": verifier})
    assert again.status_code == 200, again.text

    session_gen = app.dependency_overrides[get_session]()
    session = await session_gen.__anext__()
    try:
        user = await session.get(User, "user_operator")
        assert user.password_hash.startswith("$argon2id$")
        assert "$" + salt + "$" not in user.password_hash
    finally:
        await session_gen.aclose()


async def test_v1_verifier_migrates_without_the_raw_password(client):
    import hashlib
    import secrets

    from app.db.database import get_session
    from app.main import app
    from app.models import User

    material = hashlib.sha256(b"saturn-login-v1\ncorrect horse").hexdigest()
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", material.encode(), bytes.fromhex(salt), 210_000)
    session_gen = app.dependency_overrides[get_session]()
    session = await session_gen.__anext__()
    try:
        user = await session.get(User, "user_operator")
        user.password_hash = f"pbkdf2_sha256$210000${salt}${digest.hex()}"
        await session.commit()
    finally:
        await session_gen.aclose()

    verifier = "v2." + ("cd" * 32)
    legacy_v1 = "v1." + material
    first = await client.post("/auth/login", json={"email": "rick@saturn.ai", "password": verifier})
    assert first.status_code == 401
    assert first.json()["detail"]["migration"] == "v1"
    second = await client.post(
        "/auth/login",
        json={"email": "rick@saturn.ai", "password": verifier, "legacy_v1": legacy_v1},
    )
    assert second.status_code == 200, second.text
    again = await client.post("/auth/login", json={"email": "rick@saturn.ai", "password": verifier})
    assert again.status_code == 200, again.text


async def test_login_rejects_bad_password(client):
    response = await client.post(
        "/auth/login",
        json={"email": "rick@saturn.ai", "password": "wrong"},
    )
    assert response.status_code == 401


async def test_protected_route_requires_auth():
    from httpx import ASGITransport, AsyncClient

    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as anon:
        response = await anon.get("/agents")
        assert response.status_code == 401


async def test_logout_revokes_session(client):
    me = await client.get("/auth/me")
    assert me.status_code == 200
    logout = await client.post("/auth/logout")
    assert logout.status_code == 204
    denied = await client.get("/auth/me")
    assert denied.status_code == 401


async def test_login_migration_hides_unknown_accounts_and_is_rate_limited(client, monkeypatch):
    missing = await client.post(
        "/auth/login/migration",
        json={"email": "nobody@example.com", "password": "v2.00"},
    )
    assert missing.status_code == 200
    assert missing.json() == {}

    async def refuse(_request, _email=None):
        return False

    monkeypatch.setattr("app.features.identity.auth.controllers.auth.migration_allowed", refuse)
    limited = await client.post(
        "/auth/login/migration",
        json={"email": "nobody@example.com", "password": "v2.00"},
    )
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "600"
    assert limited.json()["detail"] == "Too many attempts"
