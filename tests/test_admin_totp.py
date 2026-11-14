from sqlalchemy import select

from app.core.config import get_settings
from app.features.identity.auth.services.totp import current_code, hash_backup_code, verify_code


async def _session():
    from app.db.database import get_session
    from app.main import app

    override = app.dependency_overrides[get_session]
    generator = override()
    session = await anext(generator)
    return session, generator


async def test_admin_without_totp_is_blocked_until_setup(client):
    from app.models import TotpBackupCode, User

    session, generator = await _session()
    try:
        user = await session.get(User, get_settings().default_actor_id)
        user.totp_enabled = False
        user.totp_secret = ""
        await session.commit()
    finally:
        await generator.aclose()

    blocked = await client.get("/admin/orgs")
    assert blocked.status_code == 403
    assert blocked.json()["detail"] == "MFA setup is required"
    me = await client.get("/auth/me")
    assert me.status_code == 200
    assert me.json()["mfa_setup_required"] is True
    assert (await client.get("/auth/mfa")).json()["totp"] is False

    setup = await client.post("/auth/totp/setup")
    assert setup.status_code == 200, setup.text
    body = setup.json()
    # Started but not confirmed: the account does not have an authenticator yet.
    assert (await client.get("/auth/mfa")).json()["totp"] is False
    assert body["secret"]
    assert body["otpauth_url"].startswith("otpauth://totp/")
    assert len(body["backup_codes"]) == 8

    session, generator = await _session()
    try:
        stored = list(
            (
                await session.scalars(
                    select(TotpBackupCode).where(TotpBackupCode.user_id == get_settings().default_actor_id)
                )
            ).all()
        )
        assert stored
        for code in body["backup_codes"]:
            assert all(code not in row.code_hash for row in stored)
            assert hash_backup_code(code) in {row.code_hash for row in stored}
    finally:
        await generator.aclose()

    code = current_code(body["secret"])
    confirmed = await client.post("/auth/totp/confirm", json={"code": code})
    assert confirmed.status_code == 204, confirmed.text
    allowed = await client.get("/admin/orgs")
    assert allowed.status_code == 200, allowed.text
    finished = await client.get("/auth/me")
    assert finished.json()["mfa_setup_required"] is False
    assert (await client.get("/auth/mfa")).json()["totp"] is True

    # Replaying the same code within the 90-second window is rejected.
    replayed = await client.post("/auth/totp/verify", json={"code": code})
    assert replayed.status_code == 400


async def test_totp_code_cannot_be_reused_within_90_seconds():
    secret = "JBSWY3DPEHPK3PXP"
    code = current_code(secret, now=1_800_000.0)
    assert await verify_code(secret, code, now=1_800_000.0) is True
    assert await verify_code(secret, code, now=1_800_000.0) is False
    assert await verify_code(secret, code, now=1_800_029.0) is False
    assert await verify_code(secret, code, now=1_800_035.0) is False
    next_code = current_code(secret, now=1_800_030.0)
    assert await verify_code(secret, next_code, now=1_800_030.0) is True


async def test_totp_confirm_locks_out_after_five_failed_attempts(client):
    from app.models import User

    session, generator = await _session()
    try:
        user = await session.get(User, get_settings().default_actor_id)
        user.totp_enabled = False
        user.totp_secret = ""
        user.totp_attempts = 0
        await session.commit()
    finally:
        await generator.aclose()

    setup = await client.post("/auth/totp/setup")
    assert setup.status_code == 200
    secret = setup.json()["secret"]

    for _ in range(4):
        bad = await client.post("/auth/totp/confirm", json={"code": "000000"})
        assert bad.status_code == 400

    fifth = await client.post("/auth/totp/confirm", json={"code": "000000"})
    assert fifth.status_code == 429

    # Even a valid code is rejected once locked out until setup is restarted.
    late = await client.post("/auth/totp/confirm", json={"code": current_code(secret)})
    assert late.status_code in {400, 429}


async def test_admin_with_a_passkey_does_not_need_totp(client):
    from app.core.ids import new_id
    from app.models import Passkey, User

    actor = get_settings().default_actor_id
    session, generator = await _session()
    try:
        user = await session.get(User, actor)
        user.totp_enabled = False
        user.totp_secret = ""
        await session.commit()
    finally:
        await generator.aclose()

    blocked = await client.get("/admin/orgs")
    assert blocked.status_code == 403
    assert blocked.json()["detail"] == "MFA setup is required"
    # The routes that add a passkey stay reachable, or an admin could never enrol one.
    options = await client.post("/auth/passkeys/options", headers={"Origin": "http://localhost:3000"})
    assert options.status_code == 200, options.text

    session, generator = await _session()
    try:
        session.add(
            Passkey(
                id=new_id("pkey"),
                user_id=actor,
                credential_id="admin-passkey-credential",
                public_key="public-key",
                sign_count=0,
            )
        )
        await session.commit()
    finally:
        await generator.aclose()

    allowed = await client.get("/admin/orgs")
    assert allowed.status_code == 200, allowed.text
    me = await client.get("/auth/me")
    assert me.json()["mfa_setup_required"] is False

    # Removing the only factor puts the requirement back.
    listed = await client.get("/auth/mfa")
    removed = await client.delete(f"/auth/passkeys/{listed.json()['passkeys'][0]['id']}")
    assert removed.status_code == 204, removed.text
    again = await client.get("/admin/orgs")
    assert again.status_code == 403
