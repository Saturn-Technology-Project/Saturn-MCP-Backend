"""RFC 6238 TOTP. Backup codes are stored only as hashes."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import secrets
import struct
import time
from datetime import timedelta, timezone
from urllib.parse import quote

from fastapi import HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.features.identity.auth.services.attempts import reserve_attempt
from app.core.ids import new_id, utcnow
from app.core.rate_limit import _redis_client, _use_redis
from app.features.credentials.vault.services.credential_service import open_secret, seal
from app.features.credentials.vault.services.pq_crypto import SecretNeedsReconnect
from app.features.identity.auth.models.mfa import TotpBackupCode
from app.features.identity.auth.models.user import User

_STEP = 30
_DIGITS = 6
_BACKUP_COUNT = 8
_WINDOW_SECONDS = 90
MAX_ATTEMPTS = 5
LOCKOUT = timedelta(minutes=15)

_used_steps: dict[str, int] = {}


def reset() -> None:
    _used_steps.clear()


def _hotp(secret: bytes, counter: int) -> str:
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % 10**_DIGITS).zfill(_DIGITS)


def current_code(secret_b32: str, now: float | None = None) -> str:
    moment = time.time() if now is None else now
    return _hotp(_decode(secret_b32), int(moment // _STEP))


def _matched_step(secret_b32: str, code: str, now: float | None = None) -> int | None:
    presented = code.strip()
    if len(presented) != _DIGITS or not presented.isdigit():
        return None
    moment = time.time() if now is None else now
    counter = int(moment // _STEP)
    secret = _decode(secret_b32)
    matched_step: int | None = None
    for offset in (-1, 0, 1):
        step = counter + offset
        if hmac.compare_digest(_hotp(secret, step), presented):
            matched_step = step
    return matched_step


async def _claim_step(secret_b32: str, step: int) -> bool:
    fp = hashlib.sha256(secret_b32.strip().upper().encode()).hexdigest()
    last = _used_steps.get(fp, 0)
    if step <= last:
        return False
    if _use_redis():
        try:
            client = _redis_client()
            prev = await client.get(f"saturn:totp:last:{fp}")
            if prev is not None and step <= int(prev):
                return False
            if not await client.set(f"saturn:totp:used:{fp}:{step}", "1", nx=True, ex=_WINDOW_SECONDS):
                return False
            await client.set(f"saturn:totp:last:{fp}", str(step), ex=_WINDOW_SECONDS)
        except Exception:
            return False
    _used_steps[fp] = step
    return True


async def verify_code(
    secret_b32: str,
    code: str,
    now: float | None = None,
    *,
    last_step: int = 0,
) -> bool:
    step = _matched_step(secret_b32, code, now)
    if step is None or step <= last_step:
        return False
    return await _claim_step(secret_b32, step)


def hash_backup_code(code: str) -> str:
    return hashlib.sha256(f"saturn-totp-backup-v1\n{code}".encode()).hexdigest()


def _decode(secret_b32: str) -> bytes:
    padded = secret_b32.strip().upper()
    padded += "=" * ((8 - len(padded) % 8) % 8)
    return base64.b32decode(padded)


def _otpauth(email: str, secret_b32: str) -> str:
    label = quote(f"Saturn:{email}")
    return (
        f"otpauth://totp/{label}?secret={secret_b32}"
        "&issuer=Saturn&algorithm=SHA1&digits=6&period=30"
    )


async def begin_setup(session: AsyncSession, user: User) -> dict[str, object]:
    if user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is already enabled")
    raw = secrets.token_bytes(20)
    secret_b32 = base64.b32encode(raw).decode().rstrip("=")
    user.totp_secret = await asyncio.to_thread(seal, secret_b32, user.organization_id, user.id)
    user.totp_enabled = False
    user.totp_attempts = 0
    user.totp_last_step = 0
    await session.execute(delete(TotpBackupCode).where(TotpBackupCode.user_id == user.id))
    # 64 bits each, so the unsalted digests cannot be reversed by brute force if the table leaks.
    codes = [secrets.token_hex(8) for _ in range(_BACKUP_COUNT)]
    for code in codes:
        session.add(
            TotpBackupCode(
                id=new_id("tbc"),
                user_id=user.id,
                code_hash=hash_backup_code(code),
                created_at=utcnow(),
            )
        )
    await session.flush()
    return {"secret": secret_b32, "otpauth_url": _otpauth(user.email, secret_b32), "backup_codes": codes}


async def confirm_setup(
    session: AsyncSession,
    user: User,
    code: str,
    *,
    now: float | None = None,
) -> None:
    if user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is already enabled")
    if not user.totp_secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Start MFA setup first")
    if (user.totp_attempts or 0) >= MAX_ATTEMPTS:
        user.totp_secret = ""
        await session.flush()
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed attempts")
    try:
        secret_b32 = await asyncio.to_thread(open_secret, user.totp_secret, user.organization_id, user.id)
    except SecretNeedsReconnect as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA setup needs to be started again") from exc
    used = await reserve_attempt(session, user, "totp_attempts", MAX_ATTEMPTS)
    if used is None:
        user.totp_secret = ""
        await session.flush()
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed attempts")
    last_step = int(user.totp_last_step or 0)
    step = _matched_step(secret_b32, code, now) if secret_b32 else None
    if step is None or step <= last_step or not await _claim_step(secret_b32, step):
        if used >= MAX_ATTEMPTS:
            user.totp_secret = ""
            await session.flush()
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed attempts")
        await session.flush()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That code did not match")
    user.totp_last_step = step
    user.totp_attempts = 0
    user.totp_enabled = True
    await session.flush()


async def verify_user_totp(
    session: AsyncSession,
    user: User,
    code: str,
    *,
    now: float | None = None,
) -> None:
    if not user.totp_enabled or not user.totp_secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MFA is not enabled")
    if _locked(user):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed attempts")
    try:
        secret_b32 = await asyncio.to_thread(open_secret, user.totp_secret, user.organization_id, user.id)
    except SecretNeedsReconnect as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA needs to be set up again") from exc
    used = await reserve_attempt(session, user, "totp_attempts", MAX_ATTEMPTS)
    if used is None:
        if user.totp_locked_until is None:
            user.totp_locked_until = utcnow() + LOCKOUT
            await session.flush()
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed attempts")
    last_step = int(user.totp_last_step or 0)
    step = _matched_step(secret_b32, code, now) if secret_b32 else None
    if step is not None and step > last_step and await _claim_step(secret_b32, step):
        user.totp_last_step = step
        user.totp_attempts = 0
        user.totp_locked_until = None
        await session.flush()
        return
    digest = hash_backup_code(code.strip())
    backups = list(
        (
            await session.scalars(
                select(TotpBackupCode).where(
                    TotpBackupCode.user_id == user.id,
                    TotpBackupCode.used_at.is_(None),
                )
            )
        ).all()
    )
    for row in backups:
        if hmac.compare_digest(row.code_hash, digest):
            row.used_at = utcnow()
            user.totp_attempts = 0
            await session.flush()
            return
    # The attempt was counted before the code was checked (reserve_attempt).
    if used >= MAX_ATTEMPTS:
        user.totp_locked_until = utcnow() + LOCKOUT
    await session.flush()
    if used >= MAX_ATTEMPTS:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed attempts")
    raise HTTPException(status.HTTP_400_BAD_REQUEST, "That code did not match")


def _locked(user: User) -> bool:
    """A lockout lasts LOCKOUT, then the counter starts again. It never locks an account for good."""
    if int(user.totp_attempts or 0) < MAX_ATTEMPTS:
        return False
    until = user.totp_locked_until
    if until is not None and until.tzinfo is None:
        until = until.replace(tzinfo=timezone.utc)
    if until is not None and until > utcnow():
        return True
    user.totp_attempts = 0
    user.totp_locked_until = None
    return False
