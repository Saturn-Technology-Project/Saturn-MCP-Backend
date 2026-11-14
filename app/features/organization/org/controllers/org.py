from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response, status

from app.features.agent.agents.controllers.agents import serialize_agent
from app.features.identity.auth.controllers.deps import CurrentUser, SessionDep, TeamRead, TeamWrite
from app.models import Employee
from app.features.organization.org.models.invitation import Invitation
from app.features.organization.org.models.organization import Organization
from app.schemas import (
    InviteCreateResponse,
    InviteRead,
    MeUpdateRequest,
    MemberInviteRequest,
    MemberRead,
    MemberUpdateRequest,
    McpGatewayRead,
    OrgUserRead,
    OrgWorkspaceRead,
    OrganizationRead,
    PhotoUpdate,
    SubscriptionRead,
)
from app.features.organization.org.services.access import allows, normalize_permissions, permission_catalog
from app.core.enums import AuditEvent
from app.features.execution.activity.services.change_log import record_change
from app.features.mcp.servers.controllers.mcp_servers import serialize_mcp_server
from app.features.organization.org.services.mapping_service import mapping_service
from app.features.mcp.servers.services.mcp_gateway import mcp_gateway
from app.features.organization.org.services.member_service import member_service
from app.features.identity.auth.services.photo import clean_photo
from app.features.organization.org.services.organization_service import serialize_organization
from app.features.organization.org.services.subscription_service import get_subscription, pay_invoice
from app.shared.pagination import Page

router = APIRouter(prefix="/org", tags=["org"])


def serialize_org_user(employee: Employee) -> OrgUserRead:
    user = employee.user
    return OrgUserRead(
        id=employee.id,
        user_id=employee.user_id,
        email=user.email if user is not None else "",
        name=user.name if user is not None else "",
        title=employee.title,
        role=employee.role,
        status=employee.status,
    )


def serialize_member(employee: Employee) -> MemberRead:
    user = employee.user
    return MemberRead(
        id=employee.id,
        user_id=employee.user_id,
        email=user.email if user is not None else "",
        name=user.name if user is not None else "",
        title=employee.title,
        role=employee.role,
        status=employee.status,
        permissions=normalize_permissions(employee.permissions),
        agent_ids=[agent.id for agent in employee.agents],
        agent_edit_ids=None if employee.agent_edit_ids is None else list(employee.agent_edit_ids),
        mcp_server_ids=[server.id for server in employee.mcp_servers],
        created_at=employee.created_at,
    )


def serialize_invite(
    invite: Invitation, token: str | None = None, *, created: bool = False
) -> InviteRead | InviteCreateResponse:
    payload = dict(
        id=invite.id,
        email=invite.email,
        name=invite.name,
        title=invite.title,
        role=invite.role,
        status=invite.status,
        permissions=normalize_permissions(invite.permissions),
        agent_ids=list(invite.agent_ids or []),
        mcp_server_ids=list(invite.mcp_server_ids or []),
        invited_by_user_id=invite.invited_by_user_id,
        expires_at=invite.expires_at,
        created_at=invite.created_at,
        token=token,
    )
    if created or token is not None:
        return InviteCreateResponse(**payload)
    return InviteRead(**payload)


@router.get("", response_model=OrgWorkspaceRead)
async def get_org(session: SessionDep, user: CurrentUser):
    employee = await mapping_service.bind_workspace(session, user)
    org = user.organization
    permissions = employee.permissions if employee is not None else {}
    users = []
    if allows(permissions, "team", "read"):
        members_list = await member_service.list_members(session, user.organization_id)
        users = [serialize_org_user(item) for item in members_list]
    # The same access GET /agents and GET /mcp-servers ask for. An agent carries its instructions,
    # so a member with no agent access must not receive them through the workspace summary.
    agents, servers = [], []
    if allows(permissions, "agents", "read"):
        agents = [
            serialize_agent(agent)
            for agent in await mapping_service.list_org_agents(session, user.organization_id)
        ]
        servers = [
            serialize_mcp_server(server)
            for server in await mapping_service.list_org_mcp_servers(session, user.organization_id)
        ]
    return OrgWorkspaceRead(
        organization=serialize_organization(org),
        catalog=permission_catalog(),
        me=serialize_member(employee) if employee is not None else None,
        agents=agents,
        mcp_servers=servers,
        users=users,
        mcp_gateway=McpGatewayRead.model_validate(mcp_gateway.snapshot(user.organization_id)),
    )


@router.patch("/photo", response_model=OrganizationRead)
async def update_org_photo(body: PhotoUpdate, session: SessionDep, user: CurrentUser, _access: TeamWrite):
    org = await session.get(Organization, user.organization_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    org.photo = clean_photo(body.photo)
    await session.flush()
    return serialize_organization(org)


@router.patch("/me", response_model=MemberRead)
async def update_me(body: MeUpdateRequest, session: SessionDep, user: CurrentUser):
    employee = await mapping_service.require_employee(session, user)
    updated = await member_service.update_member(
        session,
        user,
        employee.id,
        name=body.name,
        title=body.title,
        role=None,
        permissions=None,
        status=None,
        agent_ids=None,
        mcp_server_ids=None,
    )
    return serialize_member(updated)


@router.get("/users", response_model=list[OrgUserRead])
async def list_org_users(session: SessionDep, user: CurrentUser, _access: TeamRead, page: Page):
    members = await member_service.list_members(
        session, user.organization_id, limit=page.limit, offset=page.offset
    )
    return [serialize_org_user(item) for item in members]


@router.get("/members", response_model=list[MemberRead])
async def list_members(session: SessionDep, user: CurrentUser, _access: TeamRead, page: Page):
    members = await member_service.list_members(
        session, user.organization_id, limit=page.limit, offset=page.offset
    )
    return [serialize_member(item) for item in members]


@router.get("/members/{employee_id}", response_model=MemberRead)
async def get_member(employee_id: str, session: SessionDep, user: CurrentUser, _access: TeamRead):
    employee = await member_service.require_org_member(
        session, user.organization_id, employee_id
    )
    return serialize_member(employee)


@router.patch("/members/{employee_id}", response_model=MemberRead)
async def update_member(
    employee_id: str,
    body: MemberUpdateRequest,
    session: SessionDep,
    user: CurrentUser,
    _access: TeamWrite,
):
    current = await member_service.require_org_member(session, user.organization_id, employee_id)
    before = {"role": current.role, "status": current.status, "permissions": dict(current.permissions or {})}
    employee = await member_service.update_member(
        session,
        user,
        employee_id,
        name=body.name,
        title=body.title,
        role=body.role,
        permissions=body.permissions.model_dump() if body.permissions is not None else None,
        status=body.status,
        agent_ids=body.agent_ids,
        agent_edit_ids=body.agent_edit_ids,
        mcp_server_ids=body.mcp_server_ids,
    )
    access_fields = {"role", "permissions", "status", "agent_ids", "agent_edit_ids", "mcp_server_ids"}
    if body.model_fields_set & access_fields:
        await record_change(
            session,
            user,
            AuditEvent.MEMBER_UPDATED,
            result=employee.role,
            employee_id=employee.id,
            user_id=employee.user_id,
            role=employee.role,
            status=employee.status,
            permissions=dict(employee.permissions or {}),
            previous=before,
            changed=sorted(body.model_fields_set & access_fields),
        )
    return serialize_member(employee)


@router.get("/invites", response_model=list[InviteRead])
async def list_invites(session: SessionDep, user: CurrentUser, _access: TeamRead):
    invites = await member_service.list_invites(session, user.organization_id)
    return [serialize_invite(item) for item in invites]


@router.post("/invites", response_model=InviteCreateResponse, status_code=201)
async def invite_member(
    body: MemberInviteRequest,
    session: SessionDep,
    user: CurrentUser,
    _access: TeamWrite,
):
    invite, token = await member_service.invite(
        session,
        user,
        email=body.email,
        name=body.name,
        title=body.title,
        role=body.role,
        permissions=body.permissions.model_dump() if body.permissions is not None else None,
        agent_ids=body.agent_ids,
        mcp_server_ids=body.mcp_server_ids,
    )
    await record_change(
        session,
        user,
        AuditEvent.MEMBER_INVITED,
        result=invite.role,
        invite_id=invite.id,
        email=invite.email,
        role=invite.role,
        permissions=dict(invite.permissions or {}),
    )
    # token is None outside local development: the invitee gets the link by email.
    return serialize_invite(invite, token, created=True)


@router.get("/subscription", response_model=SubscriptionRead)
async def read_subscription(session: SessionDep, user: CurrentUser, _access: TeamWrite):
    org = await session.get(Organization, user.organization_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    return await get_subscription(session, org)


@router.post("/subscription/invoices/{invoice_id}/pay", response_model=SubscriptionRead)
async def pay_subscription_invoice(
    invoice_id: str, session: SessionDep, user: CurrentUser, _access: TeamWrite
):
    org = await session.get(Organization, user.organization_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    return await pay_invoice(session, org, invoice_id)


@router.delete("/invites/{invite_id}", status_code=204)
async def revoke_invite(
    invite_id: str,
    session: SessionDep,
    user: CurrentUser,
    _access: TeamWrite,
):
    await member_service.revoke_invite(session, user.organization_id, invite_id)
    await record_change(session, user, AuditEvent.INVITE_REVOKED, invite_id=invite_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
