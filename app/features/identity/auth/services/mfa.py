from __future__ import annotations

import secrets
from datetime import timedelta, timezone

from app.shared.threads import in_thread
from fastapi import HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.features.identity.auth.services.attempts import reserve_attempt
from app.core.ids import new_id, utcnow
from app.features.identity.auth.models.mfa import EmailCode, LoginChallenge, Passkey
from app.features.identity.auth.services.auth_service import hash_password, hash_token, verify_password
from app.features.identity.auth.services.throttle import consume
from app.models import Employee, User

CODE_TTL = timedelta(minutes=10)
CHALLENGE_TTL = timedelta(minutes=10)
RESEND_WAIT = timedelta(seconds=60)
MAX_ATTEMPTS = 5


def _as_utc(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _email(value: str) -> str:
    normalized = value.strip().lower()
    domain = normalized.split("@")[-1] if "@" in normalized else ""
    if not domain or "." not in domain or " " in normalized:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Email is invalid")
    return normalized


def _name(value: str) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > 255:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Name is required")
    return cleaned


def _password(value: str) -> str:
    if len(value) < 8:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Password must be at least 8 characters")
    return value


def _new_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


class MfaService:
    async def request_signup(
        self,
        session: AsyncSession,
        *,
        name: str,
        email: str,
        password: str,
        request: Request,
    ) -> str | None:
        cleaned_name = _name(name)
        normalized = _email(email)
        secret = _password(password)
        await consume(session, request, "signup", normalized)
        existing = await session.execute(select(User).where(User.email == normalized))
        if existing.scalar_one_or_none() is not None:
            # Do the same two hashes a new address costs. Both answers are an empty 204, and the
            # hashes are nearly all of the time either takes; skipping them here made a taken
            # address answer measurably sooner than a free one.
            await in_thread(hash_password, secret)
            await in_thread(hash_password, _new_code())
            return None
        await self._close_open(session, normalized, "signup")
        code = _new_code()
        session.add(
            EmailCode(
                id=new_id("eml"),
                email=normalized,
                purpose="signup",
                name=cleaned_name,
                password_hash=await in_thread(hash_password, secret),
                code_hash=await in_thread(hash_password, code),
                expires_at=utcnow() + CODE_TTL,
                attempts=0,
            )
        )
        await session.flush()
        return code

    async def discard_signup(self, session: AsyncSession, email: str) -> None:
        record = await self._open_code(session, _email(email), "signup")
        if record is not None:
            await session.delete(record)
            await session.flush()

    async def confirm_signup(
        self,
        session: AsyncSession,
        *,
        email: str,
        password: str,
        code: str,
    ) -> tuple[str, str, str]:
        normalized = _email(email)
        pending = await self._open_code(session, normalized, "signup")
        now = utcnow()
        if (
            pending is None
            or pending.password_hash is None
            or _as_utc(pending.expires_at) <= now
            or pending.attempts >= MAX_ATTEMPTS
            or not await in_thread(verify_password, password, pending.password_hash)
        ):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Verification code is incorrect or expired")
        record = await self._consume_code(session, normalized, "signup", code)
        if record is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Verification code is incorrect or expired")
        existing = await session.execute(select(User).where(User.email == normalized))
        if existing.scalar_one_or_none() is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, "Email is already used")
        return record.name or "", normalized, password

    async def request_email_mfa(self, session: AsyncSession, user: User) -> str:
        await self._throttle(session, user.email, "mfa")
        await self._close_open(session, user.email, "mfa")
        code = _new_code()
        session.add(
            EmailCode(
                id=new_id("eml"),
                email=user.email,
                purpose="mfa",
                user_id=user.id,
                code_hash=await in_thread(hash_password, code),
                expires_at=utcnow() + CODE_TTL,
                attempts=0,
            )
        )
        await session.flush()
        return code

    async def discard_email_mfa(self, session: AsyncSession, user: User) -> None:
        record = await self._open_code(session, user.email, "mfa")
        if record is not None:
            await session.delete(record)
            await session.flush()

    async def enable_email_mfa(self, session: AsyncSession, user: User, code: str) -> None:
        record = await self._consume_code(session, user.email, "mfa", code)
        if record is None or record.user_id != user.id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Verification code is incorrect or expired")
        user.email_mfa = True
        await session.flush()

    async def disable_email_mfa(self, session: AsyncSession, user: User) -> None:
        user.email_mfa = False
        await session.flush()

    async def begin_email_change(self, session: AsyncSession, user: User, email: str) -> tuple[str, str | None]:
        """Returns the code for the current address and, when the new address is free, the code for it.

        A taken address gets no code and no email, but the caller sees the same response, so this
        cannot be used to find out which addresses have accounts. Confirmation then fails.
        """
        normalized = _email(email)
        if normalized == user.email:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Email is invalid")
        existing = await session.execute(select(User).where(User.email == normalized))
        other = existing.scalar_one_or_none()
        taken = other is not None and other.id != user.id
        await self._throttle(session, user.email, "email_current")
        await self._close_open(session, user.email, "email_current")
        await self._close_open(session, normalized, "email_next")
        current_code = _new_code()
        next_code = _new_code()
        while next_code == current_code:
            next_code = _new_code()
        now = utcnow()
        session.add(
            EmailCode(
                id=new_id("eml"),
                email=user.email,
                purpose="email_current",
                user_id=user.id,
                name=normalized,
                code_hash=await in_thread(hash_password, current_code),
                expires_at=now + CODE_TTL,
                attempts=0,
            )
        )
        if taken:
            await in_thread(hash_password, next_code)
            await session.flush()
            return current_code, None
        session.add(
            EmailCode(
                id=new_id("eml"),
                email=normalized,
                purpose="email_next",
                user_id=user.id,
                name=normalized,
                code_hash=await in_thread(hash_password, next_code),
                expires_at=now + CODE_TTL,
                attempts=0,
            )
        )
        await session.flush()
        return current_code, next_code

    async def discard_email_change(self, session: AsyncSession, user: User) -> None:
        result = await session.execute(
            select(EmailCode).where(
                EmailCode.user_id == user.id,
                EmailCode.purpose.in_(("email_current", "email_next")),
                EmailCode.used_at.is_(None),
            )
        )
        for record in result.scalars():
            await session.delete(record)
        await session.flush()

    async def confirm_email_change(
        self,
        session: AsyncSession,
        user: User,
        current_code: str,
        next_code: str,
    ) -> None:
        current = await self._open_code(session, user.email, "email_current")
        pending = current.name if current is not None and current.user_id == user.id else ""
        nxt = await self._open_code(session, pending, "email_next") if pending else None
        now = utcnow()
        reserved: dict[str, int | None] = {}
        for record in (current, nxt):
            if record is not None:
                reserved[record.id] = await reserve_attempt(session, record, "attempts", MAX_ATTEMPTS)
        if (
            current is None
            or nxt is None
            or nxt.user_id != user.id
            or nxt.name != pending
            or any(value is None for value in reserved.values())
            or not self._code_ok(current, current_code, now)
            or not self._code_ok(nxt, next_code, now)
        ):
            for record in (current, nxt):
                if record is None:
                    continue
                used = reserved.get(record.id)
                if used is None or used >= MAX_ATTEMPTS:
                    record.used_at = now
            await session.flush()
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Verification code is incorrect or expired")
        taken = await session.scalar(select(User).where(User.email == pending, User.id != user.id))
        current.used_at = now
        nxt.used_at = now
        if taken is not None:
            await session.flush()
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Verification code is incorrect or expired")
        user.email = pending
        await session.flush()

    async def request_reauth_code(self, session: AsyncSession, user: User) -> str:
        await self._throttle(session, user.email, "reauth")
        await self._close_open(session, user.email, "reauth")
        code = _new_code()
        session.add(
            EmailCode(
                id=new_id("eml"),
                email=user.email,
                purpose="reauth",
                user_id=user.id,
                code_hash=await in_thread(hash_password, code),
                expires_at=utcnow() + CODE_TTL,
                attempts=0,
            )
        )
        await session.flush()
        return code

    async def discard_reauth_code(self, session: AsyncSession, user: User) -> None:
        record = await self._open_code(session, user.email, "reauth")
        if record is not None:
            await session.delete(record)
            await session.flush()

    async def consume_reauth_code(self, session: AsyncSession, user: User, code: str) -> None:
        record = await self._consume_code(session, user.email, "reauth", code)
        if record is None or record.user_id != user.id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Verification code is incorrect or expired")

    def _code_ok(self, record: EmailCode, code: str, now) -> bool:
        # The caller has already reserved this attempt (reserve_attempt), which enforces the cap.
        return _as_utc(record.expires_at) > now and verify_password(code.strip(), record.code_hash)

    async def factors(self, session: AsyncSession, user: User) -> list[str]:
        methods: list[str] = []
        totp = bool(user.totp_enabled and user.totp_secret)
        # An authenticator app replaces the weaker emailed code; it is never offered alongside it.
        if user.email_mfa and not totp:
            methods.append("email")
        if totp:
            methods.append("totp")
        count = await session.scalar(
            select(func.count()).select_from(Passkey).where(Passkey.user_id == user.id)
        )
        if count:
            methods.append("passkey")
        return methods

    async def is_admin(self, session: AsyncSession, user: User) -> bool:
        """A platform admin or an organization admin. These accounts must hold a strong factor."""
        if user.is_platform_admin:
            return True
        from app.features.organization.org.services.access import is_org_admin

        employee = await session.scalar(select(Employee).where(Employee.user_id == user.id))
        return employee is not None and is_org_admin(employee.permissions)

    async def _after_email(self, session: AsyncSession, user: User) -> list[str]:
        """What an emailed code still leaves to prove.

        An admin who holds a passkey or an authenticator app must use it: the emailed code alone
        does not sign them in. Everyone else is done.
        """
        if not await self.is_admin(session, user):
            return []
        return [method for method in await self.factors(session, user) if method != "email"]

    async def has_strong_factor(self, session: AsyncSession, user: User) -> bool:
        """An authenticator app or a passkey. Either one meets the admin MFA requirement."""
        if user.totp_enabled and user.totp_secret:
            return True
        found = await session.scalar(select(Passkey.id).where(Passkey.user_id == user.id).limit(1))
        return found is not None

    async def start_login(
        self,
        session: AsyncSession,
        user: User,
    ) -> tuple[str, list[str], str | None] | None:
        methods = await self.factors(session, user)
        if not methods:
            return None
        await self._throttle_login(session, user.id)
        code = _new_code() if "email" in methods else None
        raw = secrets.token_urlsafe(32)
        now = utcnow()
        open_rows = await session.execute(
            select(LoginChallenge).where(
                LoginChallenge.user_id == user.id,
                LoginChallenge.used_at.is_(None),
            )
        )
        for row in open_rows.scalars():
            row.used_at = now
        session.add(
            LoginChallenge(
                id=new_id("mfa"),
                user_id=user.id,
                token_hash=hash_token(raw),
                code_hash=await in_thread(hash_password, code) if code else None,
                attempts=0,
                expires_at=now + CHALLENGE_TTL,
            )
        )
        await session.flush()
        return raw, methods, code

    async def discard_login(self, session: AsyncSession, token: str) -> None:
        record = await self._challenge(session, token)
        if record is not None and record.used_at is None:
            await session.delete(record)
            await session.flush()

    async def user_for_challenge(self, session: AsyncSession, token: str) -> User:
        record = await self._live_challenge(session, token)
        user = await self._user(session, record.user_id)
        if user is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Sign-in challenge is incorrect or expired")
        return user

    async def finish_email(self, session: AsyncSession, token: str, code: str) -> tuple[User, list[str]]:
        """Check the emailed code. Returns the user and the methods still required, if any.

        With methods left, the sign-in is not finished: the same challenge stays open for them
        and the emailed code cannot be presented again.
        """
        from app.core.rate_limit import login_code_failed, login_code_open

        record = await self._live_challenge(session, token)
        if record.code_hash is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Verification code is incorrect or expired")
        if not await login_code_open(record.user_id):
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Too many incorrect codes. Try again tomorrow or use another sign-in method.",
                headers={"Retry-After": "3600"},
            )
        used = await reserve_attempt(session, record, "attempts", MAX_ATTEMPTS)
        if used is None or not await in_thread(verify_password, code.strip(), record.code_hash):
            if used is not None:
                await login_code_failed(record.user_id)
            if used is None or used >= MAX_ATTEMPTS:
                record.used_at = utcnow()
            await session.flush()
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Verification code is incorrect or expired")
        user = await self._user(session, record.user_id)
        if user is None:
            record.used_at = utcnow()
            await session.flush()
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Verification code is incorrect or expired")
        further = await self._after_email(session, user)
        if further:
            record.code_hash = None
        else:
            record.used_at = utcnow()
        await session.flush()
        return user, further

    async def finish_totp(self, session: AsyncSession, token: str, code: str) -> User:
        from app.features.identity.auth.services.totp import verify_user_totp

        record = await self._live_challenge(session, token)
        user = await self._user(session, record.user_id)
        if user is None or not (user.totp_enabled and user.totp_secret):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Verification code is incorrect or expired")
        used = await reserve_attempt(session, record, "attempts", MAX_ATTEMPTS)
        if used is None:
            record.used_at = utcnow()
            await session.flush()
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Sign-in challenge is incorrect or expired")
        try:
            await verify_user_totp(session, user, code)
        except HTTPException:
            if used >= MAX_ATTEMPTS:
                record.used_at = utcnow()
            await session.flush()
            raise
        record.used_at = utcnow()
        await session.flush()
        return user

    async def finish_passkey(self, session: AsyncSession, token: str) -> User:
        record = await self._live_challenge(session, token)
        user = await self._user(session, record.user_id)
        if user is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Sign-in challenge is incorrect or expired")
        record.used_at = utcnow()
        await session.flush()
        return user

    async def _throttle(self, session: AsyncSession, email: str, purpose: str) -> None:
        recent = await session.execute(
            select(EmailCode)
            .where(EmailCode.email == email, EmailCode.purpose == purpose)
            .order_by(EmailCode.created_at.desc())
            .limit(1)
        )
        last = recent.scalar_one_or_none()
        if last is not None and utcnow() - _as_utc(last.created_at) < RESEND_WAIT:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Wait a minute before requesting another code",
            )

    async def _throttle_login(self, session: AsyncSession, user_id: str) -> None:
        recent = await session.execute(
            select(LoginChallenge)
            .where(LoginChallenge.user_id == user_id, LoginChallenge.used_at.is_(None))
            .order_by(LoginChallenge.created_at.desc())
            .limit(1)
        )
        last = recent.scalar_one_or_none()
        if last is not None and utcnow() - _as_utc(last.created_at) < RESEND_WAIT:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Wait a minute before requesting another code",
            )

    async def _close_open(self, session: AsyncSession, email: str, purpose: str) -> None:
        result = await session.execute(
            select(EmailCode).where(
                EmailCode.email == email,
                EmailCode.purpose == purpose,
                EmailCode.used_at.is_(None),
            )
        )
        now = utcnow()
        for record in result.scalars():
            record.used_at = now

    async def _open_code(self, session: AsyncSession, email: str, purpose: str) -> EmailCode | None:
        result = await session.execute(
            select(EmailCode)
            .where(
                EmailCode.email == email,
                EmailCode.purpose == purpose,
                EmailCode.used_at.is_(None),
            )
            .order_by(EmailCode.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def _consume_code(
        self,
        session: AsyncSession,
        email: str,
        purpose: str,
        code: str,
    ) -> EmailCode | None:
        record = await self._open_code(session, email, purpose)
        now = utcnow()
        if record is None or _as_utc(record.expires_at) <= now or record.attempts >= MAX_ATTEMPTS:
            return None
        used = await reserve_attempt(session, record, "attempts", MAX_ATTEMPTS)
        if used is None or not await in_thread(verify_password, code.strip(), record.code_hash):
            if used is None or used >= MAX_ATTEMPTS:
                record.used_at = now
            await session.flush()
            return None
        record.used_at = now
        await session.flush()
        return record

    async def _challenge(self, session: AsyncSession, token: str) -> LoginChallenge | None:
        result = await session.execute(
            select(LoginChallenge).where(LoginChallenge.token_hash == hash_token(token))
        )
        return result.scalar_one_or_none()

    async def _live_challenge(self, session: AsyncSession, token: str) -> LoginChallenge:
        record = await self._challenge(session, token)
        if (
            record is None
            or record.used_at is not None
            or _as_utc(record.expires_at) <= utcnow()
            or record.attempts >= MAX_ATTEMPTS
        ):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Sign-in challenge is incorrect or expired")
        return record

    async def _user(self, session: AsyncSession, user_id: str) -> User | None:
        result = await session.execute(
            select(User).options(selectinload(User.organization)).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        if user is None or user.status != "active":
            return None
        return user


mfa_service = MfaService()
