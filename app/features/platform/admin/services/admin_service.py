from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from app.shared.threads import in_thread
from fastapi import HTTPException, status as http_status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.core.ids import new_id
from app.models import (
    Action,
    Agent,
    AuditLog,
    Employee,
    McpServer,
    Organization,
    Policy,
    Run,
    Tool,
    User,
)
from app.core.enums import ActorType, AuditEvent
from app.features.organization.org.services.access import permissions_for_role, resolve_permissions
from app.features.execution.activity.services.audit_service import audit_service
from app.features.identity.auth.services.auth_service import hash_password
from app.features.mcp.servers.services.mcp_gateway import mcp_gateway
from app.features.mcp.servers.services.mcp_remote import redact_url
from app.features.identity.auth.services import mailer
from app.features.organization.org.services.member_service import (
    member_service,
    require_password_policy,
    unusable_password_hash,
)
from app.shared import runtime
from app.features.organization.org.services.plans import canonical_plan, kind_for_plan

settings = get_settings()
ORG_STATUSES = {"active", "trial", "suspended"}
DEPLOYMENTS = {"cloud", "customer_vpc", "on_prem"}


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _utc(value: datetime) -> datetime:
    aware = _aware(value)
    assert aware is not None
    return aware.astimezone(timezone.utc)


class AdminService:
    async def stats(self, session: AsyncSession) -> dict[str, int]:
        organizations = await session.scalar(select(func.count()).select_from(Organization))
        users = await session.scalar(
            select(func.count()).select_from(User).where(User.status == "active")
        )
        agents = await session.scalar(select(func.count()).select_from(Agent))
        connections = await session.scalar(
            select(func.count()).select_from(McpServer).where(McpServer.status == "active")
        )
        personal = await session.scalar(
            select(func.count()).select_from(Organization).where(Organization.kind == "personal")
        )
        teams = await session.scalar(
            select(func.count()).select_from(Organization).where(Organization.kind == "organization")
        )
        return {
            "organizations": int(organizations or 0),
            "users": int(users or 0),
            "agents": int(agents or 0),
            "connections": int(connections or 0),
            "personal": int(personal or 0),
            "teams": int(teams or 0),
        }

    async def overview(self, session: AsyncSession) -> dict:
        stats = await self.stats(session)
        await self._bind_all_mcp(session)
        try:
            await session.scalar(select(func.count()).select_from(Organization))
            db_status = "operational"
        except Exception:
            db_status = "down"
        mcp_errors = 0
        for org in (await session.execute(select(Organization))).scalars():
            snap = mcp_gateway.snapshot(org.id)
            mcp_errors += max(0, int(snap["total"]) - int(snap["connected"]))
        mcp_status = "degraded" if mcp_errors else "operational"
        events = await self.list_events(session, limit=12)
        return {
            "stats": stats,
            "services": [
                {"id": "api", "name": "API", "status": "operational"},
                {"id": "gateway", "name": "Saturn MCP", "status": mcp_status},
                {"id": "database", "name": "Database", "status": db_status},
            ],
            "events": events,
        }

    async def _bind_all_mcp(self, session: AsyncSession) -> None:
        result = await session.execute(select(Organization.id))
        for org_id in result.scalars():
            await mcp_gateway.connect_organization(session, org_id)

    async def list_orgs(
        self, session: AsyncSession, *, limit: int | None = None, offset: int = 0
    ) -> list[dict]:
        await self._bind_all_mcp(session)
        statement = select(Organization).order_by(Organization.created_at.asc(), Organization.id.asc())
        if limit is not None:
            statement = statement.limit(limit).offset(offset)
        result = await session.execute(statement)
        orgs = list(result.scalars().all())
        rows = []
        for org in orgs:
            rows.append(await self.org_snapshot(session, org))
        return rows

    async def org_snapshot(self, session: AsyncSession, org: Organization) -> dict:
        user_count, agent_count = await self.org_counts(session, org.id)
        tool_count = int(
            await session.scalar(
                select(func.count()).select_from(Tool).where(Tool.organization_id == org.id)
            )
            or 0
        )
        mcp_count = int(
            await session.scalar(
                select(func.count()).select_from(McpServer).where(McpServer.organization_id == org.id)
            )
            or 0
        )
        snap = mcp_gateway.snapshot(org.id)
        mcp_status = snap["status"] if int(snap["total"] or 0) else "none"
        kind = org.kind if org.kind in {"personal", "organization"} else kind_for_plan(org.plan)
        runtime_status = "app" if kind == "personal" else "disconnected"
        return {
            "id": org.id,
            "name": org.name,
            "status": org.status,
            "plan": canonical_plan(org.plan),
            "kind": org.kind if org.kind in {"personal", "organization"} else kind_for_plan(org.plan),
            "deployment_mode": org.deployment_mode,
            "runtime_region": org.runtime_region,
            "runtime_version": org.runtime_version,
            "created_at": org.created_at,
            "user_count": user_count,
            "agent_count": agent_count,
            "tool_count": tool_count,
            "connection_count": mcp_count,
            "runtime_status": runtime_status,
            "mcp_status": mcp_status,
            "last_heartbeat_at": None,
        }

    async def get_org(self, session: AsyncSession, organization_id: str) -> Organization:
        org = await session.get(Organization, organization_id)
        if org is None:
            raise HTTPException(http_status.HTTP_404_NOT_FOUND, "Organization not found")
        return org

    async def org_counts(self, session: AsyncSession, organization_id: str) -> tuple[int, int]:
        users = await session.scalar(
            select(func.count()).select_from(User).where(User.organization_id == organization_id)
        )
        agents = await session.scalar(
            select(func.count()).select_from(Agent).where(Agent.organization_id == organization_id)
        )
        return int(users or 0), int(agents or 0)

    async def org_health(self, session: AsyncSession, org: Organization) -> dict:
        await mcp_gateway.connect_organization(session, org.id)
        snap = mcp_gateway.snapshot(org.id)
        summary = await self.org_snapshot(session, org)
        issues: list[str] = []
        agents = summary["agent_count"]
        policies = await session.scalar(
            select(func.count()).select_from(Policy).where(Policy.organization_id == org.id)
        )
        mcp = snap["status"] if int(snap["total"] or 0) else "none"
        kind = summary["kind"]
        checks = {
            "runtime": summary["runtime_status"],
            "mcp": mcp,
            "agents": "ok" if int(agents or 0) else "none",
            "policies": "ok" if int(policies or 0) else "none",
            "database": "ok",
        }
        if org.status == "suspended":
            issues.append("Organization is suspended")
        if kind != "personal" and checks["runtime"] != "connected":
            issues.append("Connector not connected")
        if int(snap["total"] or 0) > 0 and snap["status"] != "connected":
            missing = int(snap["total"]) - int(snap["connected"])
            if missing:
                issues.append(f"{missing} MCP server{'s' if missing != 1 else ''} unreachable")
        score = 100
        if kind != "personal" and checks["runtime"] != "connected":
            score -= 40
        if checks["mcp"] == "degraded":
            score -= 15
        if checks["mcp"] == "disconnected":
            score -= 25
        return {**checks, "score": max(score, 0), "issues": issues}

    async def list_agents(self, session: AsyncSession, organization_id: str) -> list[Agent]:
        result = await session.execute(
            select(Agent)
            .where(Agent.organization_id == organization_id)
            .order_by(Agent.created_at.asc())
        )
        return list(result.scalars().all())

    async def list_mcp_servers(self, session: AsyncSession, organization_id: str) -> list[McpServer]:
        result = await session.execute(
            select(McpServer)
            .options(selectinload(McpServer.tools))
            .where(McpServer.organization_id == organization_id)
            .order_by(McpServer.name.asc())
        )
        return list(result.scalars().unique().all())

    async def onboard_org(
        self,
        session: AsyncSession,
        actor: User,
        *,
        name: str,
        admin_email: str,
        admin_name: str,
        admin_password: str | None,
        admin_title: str,
        plan: str = "free",
        kind: str | None = None,
    ) -> tuple[Organization, Employee]:
        cleaned_name = name.strip()
        if not cleaned_name:
            raise HTTPException(http_status.HTTP_400_BAD_REQUEST, "Organization name is required")
        cleaned_plan = canonical_plan(plan, strict=True)
        employee = await self.create_member(
            session,
            organization=None,
            org_name=cleaned_name,
            plan=cleaned_plan,
            email=admin_email,
            name=admin_name,
            password=admin_password,
            title=admin_title.strip() or "Admin",
            role="admin",
            permissions=None,
            status="active",
            agent_ids=[],
            mcp_server_ids=[],
            kind=kind,
        )
        org = await session.get(Organization, employee.organization_id)
        if org is None:
            raise HTTPException(http_status.HTTP_500_INTERNAL_SERVER_ERROR, "Failed to create organization")
        await audit_service.log(
            session,
            event="org_onboarded",
            actor_type=ActorType.USER,
            actor_id=actor.id,
            organization_id=org.id,
            payload={"name": org.name, "plan": org.plan},
        )
        return org, employee

    async def update_org(
        self,
        session: AsyncSession,
        actor: User,
        organization_id: str,
        *,
        name: str | None,
        status: str | None = None,
        plan: str | None = None,
        deployment_mode: str | None = None,
        runtime_region: str | None = None,
    ) -> Organization:
        org = await self.get_org(session, organization_id)
        changed: dict[str, str] = {}
        if name is not None:
            cleaned = name.strip()
            if not cleaned:
                raise HTTPException(http_status.HTTP_400_BAD_REQUEST, "Organization name is required")
            org.name = cleaned
            changed["name"] = cleaned
        if status is not None:
            cleaned = status.strip().lower()
            if cleaned not in ORG_STATUSES:
                raise HTTPException(http_status.HTTP_400_BAD_REQUEST, "Status must be active, trial, or suspended")
            org.status = cleaned
            changed["status"] = cleaned
        if plan is not None:
            cleaned = canonical_plan(plan, strict=True)
            org.plan = cleaned
            org.kind = kind_for_plan(cleaned)
            changed["plan"] = cleaned
            changed["kind"] = org.kind
        if deployment_mode is not None:
            cleaned = deployment_mode.strip().lower()
            if cleaned not in DEPLOYMENTS:
                raise HTTPException(http_status.HTTP_400_BAD_REQUEST, "Unknown deployment mode")
            org.deployment_mode = cleaned
            changed["deployment_mode"] = cleaned
        if runtime_region is not None:
            cleaned = runtime_region.strip()
            if cleaned:
                org.runtime_region = cleaned
                changed["runtime_region"] = cleaned
        await session.flush()
        if changed:
            await audit_service.log(
                session,
                event=AuditEvent.ORG_UPDATED,
                actor_type=ActorType.USER,
                actor_id=actor.id,
                organization_id=org.id,
                payload={**changed, "platform_admin": True},
            )
        return org

    async def list_users(
        self, session: AsyncSession, *, limit: int | None = None, offset: int = 0
    ) -> list[User]:
        statement = (
            select(User)
            .options(selectinload(User.organization), selectinload(User.employee))
            .order_by(User.created_at.asc(), User.id.asc())
        )
        if limit is not None:
            statement = statement.limit(limit).offset(offset)
        result = await session.execute(statement)
        return list(result.scalars().unique().all())

    @staticmethod
    def _event_filters(
        statement,
        *,
        organization_id: str | None = None,
        event: str | None = None,
        since: datetime | None = None,
    ):
        if organization_id:
            statement = statement.where(AuditLog.organization_id == organization_id)
        if event:
            statement = statement.where(AuditLog.event == event)
        if since is not None:
            statement = statement.where(AuditLog.created_at >= _utc(since))
        return statement

    async def list_events(
        self,
        session: AsyncSession,
        limit: int = 50,
        *,
        offset: int = 0,
        organization_id: str | None = None,
        event: str | None = None,
        since: datetime | None = None,
    ) -> list[AuditLog]:
        statement = self._event_filters(
            select(AuditLog).options(selectinload(AuditLog.organization)),
            organization_id=organization_id,
            event=event,
            since=since,
        )
        result = await session.execute(
            statement.order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().unique().all())

    async def count_events(
        self,
        session: AsyncSession,
        *,
        organization_id: str | None = None,
        event: str | None = None,
        since: datetime | None = None,
    ) -> int:
        statement = self._event_filters(
            select(func.count()).select_from(AuditLog),
            organization_id=organization_id,
            event=event,
            since=since,
        )
        return int(await session.scalar(statement) or 0)

    async def event_names(self, session: AsyncSession) -> list[str]:
        result = await session.execute(select(AuditLog.event).distinct().order_by(AuditLog.event.asc()))
        return [str(name) for name in result.scalars().all()]

    async def connections(self, session: AsyncSession) -> list[dict]:
        rows = []
        for snap in await self.list_orgs(session):
            org = await self.get_org(session, snap["id"])
            gateway = mcp_gateway.snapshot(org.id)
            rows.append(
                {
                    "organization_id": org.id,
                    "organization_name": org.name,
                    "channels": [
                        {
                            "id": "gateway",
                            "name": "Saturn MCP",
                            "status": gateway["status"] if int(gateway["total"] or 0) else "none",
                            "last_heartbeat_at": None,
                            "detail": f"{gateway['connected']}/{gateway['total']} servers",
                        },
                    ],
                }
            )
        return rows

    async def runtimes(self, session: AsyncSession) -> list[dict]:
        running = (
            select(Run.organization_id, func.count(Run.id).label("active"))
            .where(Run.status.in_(("queued", "running", "waiting_approval")))
            .group_by(Run.organization_id)
        )
        active_map = {row[0]: int(row[1]) for row in (await session.execute(running)).all()}
        agents = list(
            (
                await session.execute(
                    select(Agent).where(Agent.runtime_id.isnot(None)).order_by(Agent.created_at.asc())
                )
            ).scalars().all()
        )
        grouped: dict[tuple[str, str], list[Agent]] = {}
        for agent in agents:
            runtime_id = str(agent.runtime_id or "").strip()
            if not runtime_id:
                continue
            grouped.setdefault((agent.organization_id, runtime_id), []).append(agent)
        orgs = {
            org.id: org
            for org in (await session.execute(select(Organization))).scalars().all()
        }
        rows = []
        for (organization_id, runtime_id), members in grouped.items():
            org = orgs.get(organization_id)
            if org is None:
                continue
            last_failed = (
                await session.execute(
                    select(AuditLog)
                    .where(
                        AuditLog.organization_id == org.id,
                        AuditLog.event == "run_failed",
                    )
                    .order_by(AuditLog.created_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            seen = [_aware(agent.last_seen_at) for agent in members]
            seen = [item for item in seen if item is not None]
            heartbeat = max(seen) if seen else None
            rows.append(
                {
                    "id": runtime_id,
                    "organization_id": org.id,
                    "organization_name": org.name,
                    "status": "disconnected",
                    "region": org.runtime_region,
                    "version": org.runtime_version,
                    "deployment_mode": org.deployment_mode,
                    "active_runs": active_map.get(org.id, 0),
                    "agent_count": len(members),
                    "last_heartbeat_at": heartbeat,
                    "last_error": last_failed.result if last_failed is not None else None,
                }
            )
        rows.sort(key=lambda item: (item["organization_name"], item["id"]))
        return rows

    async def mcp_summary(self, session: AsyncSession) -> dict:
        await self._bind_all_mcp(session)
        result = await session.execute(
            select(McpServer)
            .options(selectinload(McpServer.tools), selectinload(McpServer.organization))
            .order_by(McpServer.name.asc())
        )
        servers = list(result.scalars().unique().all())
        items = []
        healthy = 0
        errors = 0
        tools = 0
        for server in servers:
            link = mcp_gateway.link_for(server.id)
            tool_count = len(server.tools or [])
            tools += tool_count
            connected = bool(link and link.connected)
            if connected:
                healthy += 1
            else:
                errors += 1
            items.append(
                {
                    "id": server.id,
                    "name": server.name,
                    "organization_id": server.organization_id,
                    "organization_name": server.organization.name if server.organization else "",
                    "status": "connected" if connected else "error",
                    "tools": tool_count,
                    "endpoint": redact_url(server.endpoint),
                    "error": None if connected else (link.error if link else "Disconnected"),
                }
            )
        return {
            "servers": len(servers),
            "tools": tools,
            "healthy": healthy,
            "errors": errors,
            "items": items,
        }

    async def usage(self, session: AsyncSession, *, days: int | None = None) -> list[dict]:
        """Runs and tool calls per organization: all time, or only the last `days` days."""
        runs = select(Run.organization_id, func.count(Run.id))
        calls = select(Run.organization_id, func.count(Action.id)).join(Action, Action.run_id == Run.id)
        if days is not None:
            since = datetime.now(timezone.utc) - timedelta(days=days)
            runs = runs.where(Run.created_at >= since)
            calls = calls.where(Action.created_at >= since)
        run_rows = {
            row[0]: int(row[1])
            for row in (await session.execute(runs.group_by(Run.organization_id))).all()
        }
        call_rows = {
            row[0]: int(row[1])
            for row in (await session.execute(calls.group_by(Run.organization_id))).all()
        }
        orgs = (await session.execute(select(Organization).order_by(Organization.name.asc()))).scalars()
        rows = []
        for org in orgs:
            rows.append(
                {
                    "organization_id": org.id,
                    "organization_name": org.name,
                    "plan": canonical_plan(org.plan),
                    "kind": org.kind if org.kind in {"personal", "organization"} else kind_for_plan(org.plan),
                    "runs": run_rows.get(org.id, 0),
                    "tool_calls": call_rows.get(org.id, 0),
                }
            )
        return rows

    async def settings(self, session: AsyncSession) -> dict:
        admins = [user for user in await self.list_users(session) if user.is_platform_admin]
        return {
            "platform": {
                "name": "Saturn",
                "version": "0.1.0",
                "default_org_id": settings.default_org_id,
                "session_ttl_days": settings.session_ttl_days,
            },
            "security": {
                "authentication": "session",
                "admin_count": len(admins),
                "audit": "enabled",
            },
            "infrastructure": {
                "runtime": "in-process",
                "mcp": "mcp-gateway",
                "secrets": [
                    {"id": "database_url", "kind": "dsn", "configured": True},
                    {"id": "redis_url", "kind": "url", "configured": True},
                ],
            },
            "admins": admins,
        }

    async def create_member(
        self,
        session: AsyncSession,
        *,
        organization: Organization | None,
        org_name: str | None = None,
        plan: str = "free",
        email: str,
        name: str,
        password: str | None,
        title: str,
        role: str,
        permissions: dict | None,
        status: str,
        agent_ids: list[str],
        mcp_server_ids: list[str],
        actor: User | None = None,
        kind: str | None = None,
        self_service: bool = False,
    ) -> Employee:
        """Create a user, its employee row and (when organization is None) a new organization.

        self_service: the person is choosing their own password (sign-up).
        Otherwise a platform admin is creating the account. An admin-chosen password is used
        only in local development and tests; in production the admin never knows the password:
        the account gets an unusable one and the user is emailed a one-time reset code.
        """
        use_password = self_service or (runtime.local_dev_mode() and bool(password))
        if use_password:
            require_password_policy(password or "")
        normalized = email.strip().lower()
        if not normalized:
            raise HTTPException(http_status.HTTP_400_BAD_REQUEST, "Email is required")
        cleaned_name = name.strip()
        if not cleaned_name:
            raise HTTPException(http_status.HTTP_400_BAD_REQUEST, "Name is required")

        existing = await session.execute(select(User).where(User.email == normalized))
        if existing.scalar_one_or_none() is not None:
            raise HTTPException(http_status.HTTP_409_CONFLICT, "Email is already used")

        cleaned_status = (status or "active").strip().lower()
        if cleaned_status not in {"active", "disabled"}:
            raise HTTPException(http_status.HTTP_400_BAD_REQUEST, "Status must be active or disabled")

        resolved_role, resolved_perms = resolve_permissions(role, permissions)

        cleaned_plan = canonical_plan(plan, strict=True)
        if organization is not None and organization.kind == "personal":
            raise HTTPException(http_status.HTTP_403_FORBIDDEN, "Personal accounts cannot add members")
        resolved_kind = ""
        if organization is None:
            resolved_kind = (kind or "").strip().lower() or kind_for_plan(cleaned_plan)
            if resolved_kind not in {"personal", "organization"}:
                raise HTTPException(http_status.HTTP_400_BAD_REQUEST, "Account type must be personal or team")
            if resolved_kind == "personal" and cleaned_plan in {"team", "enterprise"}:
                raise HTTPException(http_status.HTTP_400_BAD_REQUEST, "A personal account uses Free or Pro")
            if resolved_kind == "organization" and cleaned_plan not in {"team", "enterprise"}:
                raise HTTPException(http_status.HTTP_400_BAD_REQUEST, "A team account uses Team or Enterprise")
        else:
            await member_service._validate_ids(session, organization.id, agent_ids, mcp_server_ids)

        reset_code: str | None = None
        if use_password:
            password_hash = await in_thread(hash_password, password or "")
        else:
            password_hash = unusable_password_hash()
            if cleaned_status == "active":
                if not runtime.email_configured():
                    raise HTTPException(http_status.HTTP_503_SERVICE_UNAVAILABLE, "Email delivery is not configured")
                # Sent before anything is written, so a failed send leaves no half-made account.
                reset_code = f"{secrets.randbelow(1_000_000):06d}"
                await mailer.send_reset_code(normalized, reset_code, None)

        if organization is None:
            organization = Organization(
                id=new_id("org"),
                name=(org_name or "").strip() or cleaned_name,
                status="active",
                plan=cleaned_plan,
                kind=resolved_kind,
            )
            session.add(organization)
            await session.flush()
            from app.features.policy.policies.services.default_policy import ensure_default_policy

            await ensure_default_policy(session, organization.id)

        user = User(
            id=new_id("user"),
            organization_id=organization.id,
            email=normalized,
            name=cleaned_name,
            password_hash=password_hash,
            status=cleaned_status,
            is_platform_admin=False,
        )
        session.add(user)
        await session.flush()
        employee = Employee(
            id=new_id("emp"),
            organization_id=organization.id,
            user_id=user.id,
            title=title.strip() or "Operator",
            role=resolved_role,
            permissions=resolved_perms or permissions_for_role(resolved_role),
            status=cleaned_status,
        )
        session.add(employee)
        await session.flush()
        loaded = await member_service.load_member(session, employee.id)
        if loaded is None:
            raise HTTPException(http_status.HTTP_500_INTERNAL_SERVER_ERROR, "Failed to create member")
        await member_service._set_assignments(
            session,
            loaded,
            organization_id=organization.id,
            agent_ids=agent_ids,
            # No servers given: the first workspace bind assigns the org's servers once.
            mcp_server_ids=list(mcp_server_ids or []) or None,
        )
        if reset_code is not None:
            await member_service.store_reset_code(session, normalized, reset_code)
        created = await member_service.load_member(session, loaded.id)
        assert created is not None
        if actor is not None:
            await audit_service.log(
                session,
                event=AuditEvent.MEMBER_CREATED,
                actor_type=ActorType.USER,
                actor_id=actor.id,
                organization_id=organization.id,
                payload={
                    "employee_id": created.id,
                    "email": created.user.email if created.user else normalized,
                    "role": created.role,
                    "platform_admin": True,
                },
            )
        return created

    async def register_self(
        self,
        session: AsyncSession,
        *,
        name: str,
        email: str,
        password: str,
        organization: str | None = None,
    ) -> User:
        """Public sign-up. With an organization name the account is a team the new user owns;
        otherwise it is personal."""
        org_name = (organization or "").strip()
        kind, plan = ("organization", "team") if org_name else ("personal", "free")
        employee = await self.create_member(
            session,
            organization=None,
            org_name=org_name or name.strip() or "Personal",
            plan=plan,
            email=email,
            name=name,
            password=password,
            title="Owner",
            role="admin",
            permissions=None,
            status="active",
            agent_ids=[],
            mcp_server_ids=[],
            kind=kind,
            self_service=True,
        )
        user = employee.user
        if user is None:
            raise HTTPException(http_status.HTTP_500_INTERNAL_SERVER_ERROR, "Failed to create account")
        loaded = await session.execute(
            select(User).options(selectinload(User.organization)).where(User.id == user.id)
        )
        account = loaded.scalar_one()
        await audit_service.log(
            session,
            event="org_registered",
            actor_type=ActorType.USER,
            actor_id=account.id,
            organization_id=account.organization_id,
            payload={"kind": kind, "plan": plan},
        )
        return account


admin_service = AdminService()
