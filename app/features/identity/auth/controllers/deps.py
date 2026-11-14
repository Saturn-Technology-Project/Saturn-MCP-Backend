from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.features.identity.auth.controllers.session_cookie import COOKIE_NAME
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.origin_auth import request_path
from app.db.database import get_session
from app.features.credentials.vault.services.pq_crypto import warm_content_key
from app.models import Employee, Organization, User
from app.features.organization.org.services.access import allows
from app.features.organization.org.services.mapping_service import mapping_service
from app.features.organization.org.services.plans import PRO_REQUIRED, allows_pro, allows_saturn_cloud, suspended

SessionDep = Annotated[AsyncSession, Depends(get_session)]
_bearer = HTTPBearer(auto_error=False)
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _origin_of(value: str) -> str:
    from urllib.parse import urlparse

    parsed = urlparse(value.strip())
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}".lower()


def _trusted_origins(request: Request) -> set[str]:
    import os

    from app.core.config import get_settings
    from app.core.public_origin import configured_origin

    allowed = {_origin_of(item) for item in get_settings().cors_origins.split(",") if item.strip()}
    if configured_origin():
        allowed.add(_origin_of(configured_origin()))
    elif not os.environ.get("K_SERVICE", "").strip():
        allowed.add(_origin_of(str(request.base_url)))
    allowed.discard("")
    return allowed


def require_same_origin(request: Request) -> None:
    """A cookie is sent on cross-site requests too. A state change made with one must come from our own pages."""
    if request.method.upper() in _SAFE_METHODS:
        return
    source = request.headers.get("origin") or request.headers.get("referer") or ""
    if _origin_of(source) not in _trusted_origins(request):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cross-site request blocked")


async def get_current_user(
    request: Request,
    session: SessionDep,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None,
) -> User:
    from app.features.identity.auth.services.auth_service import auth_service

    token = ""
    if creds is not None and creds.scheme.lower() == "bearer":
        token = creds.credentials
    if not token:
        token = request.cookies.get(COOKIE_NAME, "")
        if token:
            require_same_origin(request)
    if not token:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = await auth_service.user_from_token(session, token)
    if user is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid or expired session",
            headers={"WWW-Authenticate": "Bearer"},
        )
    path = request_path(request)
    if (
        suspended(user.organization)
        and not user.is_platform_admin
        and path not in _SUSPENDED_ALLOWED
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Organization is suspended")
    if not _mfa_exempt(path) and await _admin_needs_mfa(session, user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "MFA setup is required")
    await warm_content_key(user.organization_id)
    return user


# A member of a suspended organization can still see who they are and sign out. A platform
# admin is never locked out, because they are the ones who lift the suspension.
_SUSPENDED_ALLOWED = frozenset({"/auth/me", "/auth/logout"})


# Routes an admin still needs before a factor exists: setting one up, and the fresh sign-in that takes.
_MFA_SETUP_PREFIXES = ("/auth/logout", "/auth/mfa", "/auth/totp", "/auth/passkeys", "/auth/reauth")


def _mfa_exempt(path: str) -> bool:
    if path in {"/", "/health", "/healthz", "/status", "/auth/me"}:
        return True
    return path.startswith(_MFA_SETUP_PREFIXES)


async def _admin_needs_mfa(session: AsyncSession, user: User) -> bool:
    """An admin needs an authenticator app or a passkey. Either one is enough."""
    if user.totp_enabled:
        return False
    from app.features.identity.auth.services.mfa import mfa_service

    if not await mfa_service.is_admin(session, user):
        return False
    return not await mfa_service.has_strong_factor(session, user)


CurrentUser = Annotated[User, Depends(get_current_user)]
AuthRequired = [Depends(get_current_user)]


def get_actor_id(user: CurrentUser) -> str:
    return user.id


ActorDep = Annotated[str, Depends(get_actor_id)]


def require_access(resource: str, level: str):
    async def _check(session: SessionDep, user: CurrentUser) -> Employee:
        employee = await mapping_service.membership_for_check(session, user)
        if not allows(employee.permissions, resource, level):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Missing {resource}.{level} access",
            )
        return employee

    return _check


AgentsRead = Annotated[Employee, Depends(require_access("agents", "read"))]
AgentsWrite = Annotated[Employee, Depends(require_access("agents", "write"))]
PoliciesRead = Annotated[Employee, Depends(require_access("policies", "read"))]
PoliciesWrite = Annotated[Employee, Depends(require_access("policies", "write"))]
ApprovalsRead = Annotated[Employee, Depends(require_access("approvals", "read"))]
ApprovalsWrite = Annotated[Employee, Depends(require_access("approvals", "write"))]
TeamRead = Annotated[Employee, Depends(require_access("team", "read"))]
TeamWrite = Annotated[Employee, Depends(require_access("team", "write"))]


async def require_saturn_cloud(session: SessionDep, user: CurrentUser) -> Organization:
    org = await session.get(Organization, user.organization_id)
    if org is None or not allows_saturn_cloud(org.plan):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Saturn MCP is unavailable")
    return org


SaturnCloud = Annotated[Organization, Depends(require_saturn_cloud)]


async def require_pro(session: SessionDep, user: CurrentUser) -> Organization:
    org = await session.get(Organization, user.organization_id)
    if org is None or not allows_pro(org.plan):
        raise HTTPException(status.HTTP_403_FORBIDDEN, PRO_REQUIRED)
    return org


ProPlan = Annotated[Organization, Depends(require_pro)]


async def require_platform_admin(user: CurrentUser) -> User:
    if not user.is_platform_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Platform admin required")
    return user


PlatformAdmin = Annotated[User, Depends(require_platform_admin)]
