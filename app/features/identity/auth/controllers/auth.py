from __future__ import annotations

import logging

from app.shared.threads import in_thread
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.features.agent.agents.controllers.agents import serialize_agent
from app.core.rate_limit import (
    accept_invite_allowed,
    code_check_allowed,
    login_allowed,
    login_succeeded,
    migration_allowed,
    reauth_allowed,
    signup_allowed,
)
from app.features.identity.auth.controllers.deps import CurrentUser, SessionDep, require_same_origin
from app.features.identity.auth.controllers.session_cookie import COOKIE_NAME, clear_session_cookie, set_session_cookie
from app.features.mcp.servers.controllers.mcp_servers import serialize_mcp_server
from app.features.tooling.tool_sets.controllers.tool_sets import serialize_tool_set
from app.models import Employee, User
from app.schemas import (
    AcceptInviteRequest,
    EmployeeRead,
    EmailChangeConfirm,
    ForgotPasswordRequest,
    LoginChallengeRequest,
    LoginEmailRequest,
    LoginPasskeyRequest,
    LoginRequest,
    LoginResponse,
    LocaleRequest,
    LocaleUpdate,
    McpGatewayRead,
    MfaCodeRequest,
    MfaStatus,
    NoticeSettings,
    OrgUserRead,
    PasskeyCreateRequest,
    PasskeyRead,
    PasswordChange,
    PhotoUpdate,
    ProfileUpdate,
    ReauthRequest,
    RegisterRequest,
    ResetPasswordRequest,
    SignupCodeRequest,
    UserRead,
)
from app.features.organization.org.services.access import allows, empty_permissions, is_org_admin, normalize_permissions
from app.features.organization.org.services.organization_service import serialize_organization
from app.features.platform.admin.services.admin_service import admin_service
from app.features.identity.auth.services.auth_service import (
    _pbkdf2_ok,
    auth_service,
    hash_token,
    migration_stage,
    verify_password,
)
from app.features.identity.auth.services.mfa import mfa_service
from app.features.identity.auth.services.passkeys import passkey_service
from app.features.identity.auth.services.photo import clean_photo
from app.features.identity.auth.services.mailer import (
    normalize_locale,
    send_email_change_code,
    send_login_code,
    send_factor_added,
    send_reauth_code,
    send_reset_code,
    send_signup_code,
)
from app.features.organization.org.services.mapping_service import mapping_service
from app.features.mcp.servers.services.mcp_gateway import mcp_gateway
from app.features.organization.org.services.member_service import member_service
from app.features.organization.org.services.plans import profile_identity
from app.features.tooling.tool_sets.services.tool_set_service import tool_set_service

router = APIRouter(prefix="/auth", tags=["auth"])


async def _require_code_check(request: Request, subject: str | None = None) -> None:
    if not await code_check_allowed(request, subject):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many attempts",
            headers={"Retry-After": "600"},
        )
_bearer = HTTPBearer(auto_error=False)
logger = logging.getLogger(__name__)


async def _send_quietly(sender, *args) -> None:
    """Send after the response. Whether an email exists must not show in the status code or the timing."""
    try:
        await sender(*args)
    except HTTPException as exc:
        logger.warning("Could not send an account email: %s", exc.detail)


def _too_many(retry_after: str = "600") -> HTTPException:
    return HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts", headers={"Retry-After": retry_after})


def serialize_org_user(employee: Employee) -> OrgUserRead:
    member = employee.user
    return OrgUserRead(
        id=employee.id,
        user_id=employee.user_id,
        email=member.email if member is not None else "",
        name=member.name if member is not None else "",
        title=employee.title,
        role=employee.role,
        status=employee.status,
    )


async def serialize_user(session, user: User) -> UserRead:
    org = serialize_organization(user.organization)
    employee = await mapping_service.employee_for_user(session, user.id)
    employee_read = None
    role = None
    permissions = empty_permissions()
    assigned_agent_ids: list[str] = []
    assigned_mcp_ids: list[str] = []
    agent_edit_ids: list[str] | None = None
    users: list[OrgUserRead] = []
    if employee is not None:
        permissions = normalize_permissions(employee.permissions)
        role = employee.role
        employee_read = EmployeeRead(
            id=employee.id,
            title=employee.title,
            status=employee.status,
            role=employee.role,
            permissions=permissions,
        )
        assigned_agent_ids = [agent.id for agent in employee.agents]
        assigned_mcp_ids = [server.id for server in employee.mcp_servers]
        agent_edit_ids = None if employee.agent_edit_ids is None else list(employee.agent_edit_ids)
        if allows(permissions, "team", "read"):
            members = await member_service.list_members(session, user.organization_id)
            users = [serialize_org_user(item) for item in members]

    # Each list needs the access its own endpoint asks for (GET /agents, /mcp-servers, /tool-sets).
    # Without the check, a member with no agent access still received every agent's instructions here.
    agents, servers, tool_sets = [], [], []
    if allows(permissions, "agents", "read"):
        agents = [
            serialize_agent(agent)
            for agent in await mapping_service.list_org_agents(session, user.organization_id)
            if str((agent.settings or {}).get("origin") or "") != "saturn_mcp"
        ]
        servers = [
            serialize_mcp_server(server)
            for server in await mapping_service.list_mcp_servers(session, user)
        ]
    if allows(permissions, "policies", "read"):
        tool_sets = [
            serialize_tool_set(item)
            for item in await tool_set_service.list_sets(session, user.organization_id)
        ]
    snapshot = mcp_gateway.snapshot(user.organization_id)
    return UserRead(
        id=user.id,
        email=user.email,
        name=user.name,
        photo=user.photo or None,
        status=user.status,
        is_platform_admin=user.is_platform_admin,
        organization=org,
        enterprise=org,
        employee=employee_read,
        agents=agents,
        mcp_servers=servers,
        tool_sets=tool_sets,
        users=users,
        assigned_agent_ids=assigned_agent_ids,
        assigned_mcp_server_ids=assigned_mcp_ids,
        agent_edit_ids=agent_edit_ids,
        mcp_gateway=McpGatewayRead.model_validate(snapshot),
        role=role,
        permissions=permissions,
        profile_id=profile_identity(
            user.id,
            user.organization_id,
            user.organization.kind,
            user.organization.plan,
        ),
        locale=normalize_locale(user.locale),
        mfa_setup_required=(user.is_platform_admin or is_org_admin(permissions))
        and not await mfa_service.has_strong_factor(session, user),
    )


def _presented_token(request: Request, creds: HTTPAuthorizationCredentials | None) -> str:
    if creds is not None and creds.scheme.lower() == "bearer":
        return creds.credentials
    return request.cookies.get(COOKIE_NAME, "")


def _body_token(request: Request, token: str) -> str | None:
    """The session token for the response body, or None for a browser.

    A browser gets the session only as the HttpOnly cookie, so script on the page (an XSS) cannot
    read it and use it elsewhere. A browser always sends Origin on these POSTs; API clients and
    scripts do not, and they still receive the bearer token.
    """
    if request.headers.get("origin"):
        return None
    return token


async def _issue_login(session, request: Request, response: Response, user: User) -> LoginResponse:
    await mapping_service.bind_workspace(session, user)
    token, user = await auth_service.issue_session(session, user)
    set_session_cookie(response, request, token)
    return LoginResponse(token=_body_token(request, token), user=await serialize_user(session, user))


async def _begin_mfa(session, user: User, locale: str | None) -> LoginResponse | None:
    pending = await mfa_service.start_login(session, user)
    if pending is None:
        return None
    challenge, methods, code = pending
    if code is not None:
        try:
            await send_login_code(user.email, code, user.locale or locale)
        except HTTPException:
            await mfa_service.discard_login(session, challenge)
            raise
    return LoginResponse(mfa_required=True, challenge=challenge, methods=methods)


@router.post("/register/code", status_code=204)
async def register_code(body: SignupCodeRequest, request: Request, session: SessionDep, background: BackgroundTasks):
    if not await signup_allowed(request):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many attempts",
            headers={"Retry-After": "600"},
        )
    code = await mfa_service.request_signup(
        session,
        name=body.name,
        email=body.email,
        password=body.password,
        request=request,
    )
    if not code:
        return
    background.add_task(_send_quietly, send_signup_code, body.email.strip().lower(), code, body.locale)


@router.post("/register", response_model=LoginResponse, status_code=201)
async def register(body: RegisterRequest, request: Request, response: Response, session: SessionDep):
    if not await signup_allowed(request):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many attempts",
            headers={"Retry-After": "600"},
        )
    name, email, password = await mfa_service.confirm_signup(
        session,
        email=body.email,
        password=body.password,
        code=body.code,
    )
    user = await admin_service.register_self(
        session,
        name=name,
        email=email,
        password=password,
        organization=body.organization,
    )
    user.locale = normalize_locale(body.locale)
    return await _issue_login(session, request, response, user)


@router.post("/login/migration")
async def login_migration(body: LoginRequest, request: Request, session: SessionDep):
    if not await migration_allowed(request, body.email):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many attempts",
            headers={"Retry-After": "600"},
        )
    normalized = body.email.strip().lower()
    user = await session.scalar(select(User).where(User.email == normalized))
    if user is None or user.status != "active":
        from app.features.identity.auth.services.auth_service import _DUMMY_HASH

        await in_thread(verify_password, body.password, _DUMMY_HASH)
        return {}
    stored = user.password_hash
    if await in_thread(verify_password, body.password, stored):
        return {}
    if body.legacy_v1 and await in_thread(verify_password, body.legacy_v1, stored):
        return {}
    from app.features.identity.auth.services.auth_service import legacy_password_allowed

    if body.legacy_password and await in_thread(_pbkdf2_ok, body.legacy_password, stored):
        if not legacy_password_allowed():
            return {"migration": "reset"}
        return {}
    stage = migration_stage(stored, legacy_v1=body.legacy_v1, legacy_password=body.legacy_password)
    if stage:
        return {"migration": stage}
    return {}


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, request: Request, response: Response, session: SessionDep):
    if not await login_allowed(request, body.email):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many attempts",
            headers={"Retry-After": "600"},
        )
    try:
        user = await auth_service.authenticate(
            session,
            body.email,
            body.password,
            legacy_password=body.legacy_password,
            legacy_v1=body.legacy_v1,
        )
    except HTTPException as exc:
        if exc.status_code != status.HTTP_401_UNAUTHORIZED:
            # Not a wrong password, so it does not count against the account.
            await login_succeeded(body.email)
        raise
    await login_succeeded(body.email)
    pending = await _begin_mfa(session, user, body.locale)
    if pending is not None:
        return pending
    return await _issue_login(session, request, response, user)


@router.post("/login/email", response_model=LoginResponse)
async def login_email(body: LoginEmailRequest, request: Request, response: Response, session: SessionDep):
    await _require_code_check(request)
    user, further = await mfa_service.finish_email(session, body.challenge, body.code)
    if further:
        # An admin with a passkey or an authenticator app still has to use it.
        return LoginResponse(mfa_required=True, challenge=body.challenge, methods=further)
    return await _issue_login(session, request, response, user)


class LoginTotpRequest(BaseModel):
    challenge: str
    code: str


@router.post("/login/totp", response_model=LoginResponse)
async def login_totp(body: LoginTotpRequest, request: Request, response: Response, session: SessionDep):
    await _require_code_check(request)
    user = await mfa_service.finish_totp(session, body.challenge, body.code)
    return await _issue_login(session, request, response, user)


@router.post("/login/passkey/options")
async def login_passkey_options(body: LoginChallengeRequest, request: Request, session: SessionDep):
    return await passkey_service.authentication_options(session, request, body.challenge)


@router.post("/login/passkey", response_model=LoginResponse)
async def login_passkey(body: LoginPasskeyRequest, request: Request, response: Response, session: SessionDep):
    user = await passkey_service.authenticate(session, request, body.challenge, body.credential)
    return await _issue_login(session, request, response, user)


@router.patch("/locale", response_model=LocaleUpdate)
async def update_locale(body: LocaleUpdate, user: CurrentUser, session: SessionDep):
    user.locale = normalize_locale(body.locale)
    await session.flush()
    return LocaleUpdate(locale=user.locale)


@router.get("/notices", response_model=NoticeSettings)
async def read_notices(user: CurrentUser):
    return NoticeSettings(
        approval=user.notify_approval,
        execute=user.notify_execute,
        audit=user.notify_audit,
    )


@router.patch("/notices", response_model=NoticeSettings)
async def update_notices(body: NoticeSettings, user: CurrentUser, session: SessionDep):
    user.notify_approval = body.approval
    user.notify_execute = body.execute
    user.notify_audit = body.audit
    await session.flush()
    return body


class TotpSetupRead(BaseModel):
    secret: str
    otpauth_url: str
    backup_codes: list[str]


class TotpConfirmRequest(BaseModel):
    code: str


async def _require_step_up(
    request: Request, session: SessionDep, creds: HTTPAuthorizationCredentials | None
) -> None:
    """Adding a factor needs the same fresh sign-in as removing one.

    Without it a stolen session could enrol its own authenticator and lock the owner out.
    """
    await auth_service.require_recent_auth(session, _presented_token(request, creds))


@router.post("/totp/setup", response_model=TotpSetupRead)
async def totp_setup(
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
):
    from app.features.identity.auth.services.totp import begin_setup

    await _require_step_up(request, session, creds)
    return await begin_setup(session, user)


@router.post("/totp/confirm", status_code=204)
async def totp_confirm(
    body: TotpConfirmRequest,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    background: BackgroundTasks,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
):
    from app.features.identity.auth.services.totp import confirm_setup

    await _require_code_check(request, user.id)
    await _require_step_up(request, session, creds)
    await confirm_setup(session, user, body.code)
    background.add_task(send_factor_added, user.email, "totp", user.locale)


@router.post("/totp/verify", status_code=204)
async def totp_verify(body: TotpConfirmRequest, request: Request, user: CurrentUser, session: SessionDep):
    from app.features.identity.auth.services.totp import verify_user_totp

    await _require_code_check(request, user.id)
    await verify_user_totp(session, user, body.code)


@router.get("/mfa", response_model=MfaStatus)
async def mfa_status(user: CurrentUser, session: SessionDep):
    records = await passkey_service.list_passkeys(session, user)
    return MfaStatus(
        email_mfa=user.email_mfa,
        totp=bool(user.totp_enabled and user.totp_secret),
        passkeys=[PasskeyRead(id=item.id, created_at=item.created_at) for item in records],
    )


@router.post("/mfa/email/code", status_code=204)
async def mfa_email_code(
    user: CurrentUser,
    session: SessionDep,
    body: LocaleRequest | None = None,
):
    code = await mfa_service.request_email_mfa(session, user)
    try:
        await send_login_code(user.email, code, user.locale)
    except HTTPException:
        await mfa_service.discard_email_mfa(session, user)
        raise


@router.post("/mfa/email", status_code=204)
async def mfa_email_enable(body: MfaCodeRequest, request: Request, user: CurrentUser, session: SessionDep):
    await _require_code_check(request, user.id)
    await mfa_service.enable_email_mfa(session, user, body.code)


@router.delete("/mfa/email", status_code=204)
async def mfa_email_disable(
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
):
    await auth_service.require_recent_auth(session, _presented_token(request, creds))
    await mfa_service.disable_email_mfa(session, user)


@router.post("/passkeys/options")
async def passkey_options(
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
):
    await _require_step_up(request, session, creds)
    return await passkey_service.registration_options(session, request, user)


@router.post("/passkeys", response_model=PasskeyRead, status_code=201)
async def create_passkey(
    body: PasskeyCreateRequest,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    background: BackgroundTasks,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
):
    await _require_step_up(request, session, creds)
    record = await passkey_service.register(session, request, user, body.credential)
    background.add_task(send_factor_added, user.email, "passkey", user.locale)
    return PasskeyRead(id=record.id, created_at=record.created_at)


@router.delete("/passkeys/{passkey_id}", status_code=204)
async def delete_passkey(
    passkey_id: str,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
):
    await auth_service.require_recent_auth(session, _presented_token(request, creds))
    await passkey_service.delete(session, user, passkey_id)


@router.post("/reauth", status_code=204)
async def reauthenticate(
    body: ReauthRequest,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
):
    token = _presented_token(request, creds)
    if not await reauth_allowed(user.id):
        raise _too_many("900")
    if body.password:
        if not await in_thread(verify_password, body.password, user.password_hash):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Current password is incorrect")
    elif body.code:
        await mfa_service.consume_reauth_code(session, user, body.code)
    elif body.credential:
        await passkey_service.reauth_verify(session, request, user, body.credential)
    else:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Reauthentication required")
    await auth_service.mark_session_authenticated(session, token)


@router.post("/reauth/email/code", status_code=204)
async def reauth_email_code(user: CurrentUser, session: SessionDep):
    code = await mfa_service.request_reauth_code(session, user)
    try:
        await send_reauth_code(user.email, code, user.locale)
    except HTTPException:
        await mfa_service.discard_reauth_code(session, user)
        raise


@router.post("/reauth/passkey/options")
async def reauth_passkey_options(request: Request, user: CurrentUser, session: SessionDep):
    return await passkey_service.reauth_options(session, request, user)


@router.post("/email/confirm", response_model=UserRead)
async def confirm_email_change(
    body: EmailChangeConfirm,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
):
    await _require_code_check(request, user.id)
    from app.features.execution.activity.services import payload_key_service as keys

    # Everything that can refuse the request is checked before the address changes.
    rekey = body.current_password is not None or body.new_password is not None
    if rekey:
        await auth_service.check_rekey(user, body.current_password or "", body.new_password or "")
    backup = await keys.prepare_member_backup(
        session,
        organization_id=user.organization_id,
        user_id=user.id,
        backup=body.member_backup.model_dump() if body.member_backup is not None and rekey else None,
    )
    await mfa_service.confirm_email_change(session, user, body.current_code, body.next_code)
    if rekey:
        # The console derives the stored value from the password and the email. Keeping the old
        # one would make the password stop working the moment the address changed.
        await auth_service.store_password(user, body.new_password or "")
        await keys.store_member_backup(session, backup)
    token = _presented_token(request, creds)
    await auth_service.revoke_user_sessions(
        session,
        user.id,
        keep_hash=hash_token(token) if token else None,
    )
    await auth_service._revoke_oauth(session, user.id)
    await mapping_service.bind_workspace(session, user)
    return await serialize_user(session, user)


@router.post("/session", status_code=204)
async def adopt_session(
    request: Request,
    response: Response,
    session: SessionDep,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
):
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    user = await auth_service.user_from_token(session, creds.credentials)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired session")
    set_session_cookie(response, request, creds.credentials)


@router.post("/logout", status_code=204)
async def logout(
    request: Request,
    response: Response,
    session: SessionDep,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
):
    if creds is None and request.cookies.get(COOKIE_NAME):
        # The cookie is sent on cross-site requests too. Without this, any page could sign a
        # visitor out, for example right before showing them a look-alike sign-in page.
        require_same_origin(request)
    token = _presented_token(request, creds)
    if token:
        await auth_service.logout(session, token)
    clear_session_cookie(response, request)


@router.get("/me", response_model=UserRead)
async def me(user: CurrentUser, session: SessionDep):
    await mapping_service.bind_workspace(session, user, links=False)
    return await serialize_user(session, user)


@router.patch("/me/photo", response_model=UserRead)
async def update_my_photo(body: PhotoUpdate, user: CurrentUser, session: SessionDep):
    user.photo = clean_photo(body.photo)
    await session.flush()
    await mapping_service.bind_workspace(session, user)
    return await serialize_user(session, user)


@router.patch("/me", response_model=UserRead)
async def update_me(
    body: ProfileUpdate,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
):
    pending = False
    next_email = body.email.strip().lower()
    changing = next_email != user.email
    if changing:
        # Check before writing anything: the session commits on HTTPException.
        await auth_service.require_recent_auth(session, _presented_token(request, creds))
    await auth_service.update_profile(session, user, name=body.name, email=user.email)
    if changing:
        current_code, next_code = await mfa_service.begin_email_change(session, user, next_email)
        pending = True
        try:
            await send_email_change_code(user.email, current_code, "email_current", user.locale)
            if next_code is not None:
                await send_email_change_code(next_email, next_code, "email_next", user.locale)
        except HTTPException:
            await mfa_service.discard_email_change(session, user)
            raise
    await mapping_service.bind_workspace(session, user)
    read = await serialize_user(session, user)
    if pending:
        read = read.model_copy(update={"email_change_pending": True})
    return read


@router.post("/accept-invite", response_model=LoginResponse)
async def accept_invite(body: AcceptInviteRequest, request: Request, response: Response, session: SessionDep):
    if not await accept_invite_allowed(request):
        raise _too_many()
    user = await member_service.accept_invite(session, body.token, body.password)
    await mapping_service.bind_workspace(session, user)
    token, user = await auth_service.issue_session(session, user)
    set_session_cookie(response, request, token)
    return LoginResponse(token=_body_token(request, token), user=await serialize_user(session, user))


@router.post("/forgot-password", status_code=204)
async def forgot_password(body: ForgotPasswordRequest, request: Request, session: SessionDep, background: BackgroundTasks):
    code = await auth_service.request_password_reset(session, body.email, request)
    if not code:
        return
    account = await session.scalar(select(User).where(User.email == body.email.strip().lower()))
    locale = account.locale if account is not None else body.locale
    background.add_task(_send_quietly, send_reset_code, body.email.strip().lower(), code, locale)


@router.post("/reset-password", status_code=204)
async def reset_password(body: ResetPasswordRequest, request: Request, session: SessionDep):
    await _require_code_check(request, body.email)
    await auth_service.reset_password(session, body.email, body.code, body.password)


@router.patch("/password", status_code=204)
async def change_password(
    body: PasswordChange,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
):
    from app.features.execution.activity.services import payload_key_service as keys

    # Checked before the password changes: a refused request is still committed, and a new
    # password with the old backup would leave the member unable to open their own key.
    backup = await keys.prepare_member_backup(
        session,
        organization_id=user.organization_id,
        user_id=user.id,
        backup=body.member_backup.model_dump() if body.member_backup is not None else None,
    )
    await auth_service.change_password(
        session,
        user,
        body.current_password,
        body.new_password,
        keep_token=_presented_token(request, creds) or None,
    )
    await keys.store_member_backup(session, backup)
