from __future__ import annotations

from datetime import timedelta, timezone
from decimal import Decimal

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.core.ids import new_id, utcnow
from app.models import Action, Agent, Approval, Run, Tool, User
from app.core.enums import (
    ActionStatus,
    ActorType,
    ApprovalStatus,
    AuditEvent,
    PolicyDecision,
    RunStatus,
)
from app.features.execution.activity.services.audit_service import audit_service
from app.features.execution.activity.services.content_seal import plain_arguments, policy_fields
from app.features.execution.approvals.services.approval_arguments import ArgumentsUnavailable, stored_arguments
from app.features.organization.org.services.mapping_service import mapping_service
from app.features.mcp.servers.services.mcp_executor import MCPExecutionError, mcp_executor
from app.features.policy.policies.services.policy_engine import EvaluationResult, policy_engine
from app.features.execution.runs.services.simulator import agent_simulator

settings = get_settings()


def _aware(value):
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class RunService:
    async def list_runs(self, session: AsyncSession, user: User, *, limit: int = 200, offset: int = 0) -> list[Run]:
        """The newest runs of the agents this member is mapped to, one page at a time."""
        agent_ids = await mapping_service.agent_ids_for(session, user)
        if not agent_ids:
            return []
        result = await session.execute(
            select(Run)
            .options(selectinload(Run.actions), selectinload(Run.approvals))
            .where(Run.agent_id.in_(agent_ids))
            .order_by(Run.created_at.desc(), Run.id.desc())
            .limit(limit)
            .offset(offset)
        )
        runs = list(result.scalars().unique().all())
        for run in runs:
            await self.reconcile_run(session, run)
        return runs

    async def load_run(self, session: AsyncSession, run_id: str) -> Run:
        result = await session.execute(
            select(Run)
            .options(selectinload(Run.actions), selectinload(Run.approvals))
            .where(Run.id == run_id)
        )
        run = result.scalar_one_or_none()
        if run is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Run not found")
        return run

    async def get_run(self, session: AsyncSession, user: User, run_id: str) -> Run:
        run = await self.load_run(session, run_id)
        await mapping_service.require_agent(session, user, run.agent_id)
        await self.reconcile_run(session, run)
        return run

    async def create_run(
        self,
        session: AsyncSession,
        user: User,
        *,
        agent_id: str,
        prompt: str,
        actor_id: str,
    ) -> Run:
        agent = await mapping_service.require_agent(session, user, agent_id)
        run = Run(
            id=new_id("run"),
            organization_id=agent.organization_id,
            agent_id=agent.id,
            input=prompt,
            status=RunStatus.QUEUED,
        )
        session.add(run)
        await session.flush()
        await audit_service.log(
            session,
            event=AuditEvent.RUN_CREATED,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            organization_id=run.organization_id,
            run_id=run.id,
            payload={"input": prompt, "agent_id": agent.id},
        )
        if settings.in_process_runtime:
            await self._advance_run(session, run, agent)
        return await self.load_run(session, run.id)

    async def continue_run(self, session: AsyncSession, run: Run) -> Run:
        agent = await session.get(Agent, run.agent_id)
        if agent is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found")
        if run.status == RunStatus.WAITING_APPROVAL:
            run.status = RunStatus.RUNNING
            run.updated_at = utcnow()
            await session.flush()
        await self._advance_run(session, run, agent)
        return await self.load_run(session, run.id)

    async def fail_run(self, session: AsyncSession, run: Run, reason: str) -> Run:
        if run.status in {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED}:
            return run
        run.status = RunStatus.FAILED
        run.updated_at = utcnow()
        await session.flush()
        await audit_service.log(
            session,
            event=AuditEvent.RUN_FAILED,
            actor_type=ActorType.SYSTEM,
            actor_id="saturn",
            organization_id=run.organization_id,
            run_id=run.id,
            result=reason,
            payload={"error": reason},
        )
        await session.flush()
        return run

    async def reconcile_run(self, session: AsyncSession, run: Run) -> Run:
        if run.status not in {RunStatus.QUEUED, RunStatus.RUNNING}:
            return run
        created = _aware(run.created_at) or utcnow()
        age = utcnow() - created
        agent = await session.get(Agent, run.agent_id)
        raw = (agent.settings or {}).get("max_runtime_minutes") if agent else None
        try:
            minutes = max(1, int(raw or 30))
        except (TypeError, ValueError):
            minutes = 30
        if run.status == RunStatus.RUNNING and age > timedelta(minutes=minutes):
            return await self.fail_run(session, run, "Run timed out")
        return run

    async def evaluate_action_policy(
        self,
        session: AsyncSession,
        action: Action,
        *,
        agent: Agent,
        arguments: dict | None = None,
    ):
        tool = await self.get_tool(session, agent.organization_id, action.tool)
        from app.features.execution.activity.services.zero_access import action_digest, is_zero_access
        from app.models import Policy

        if arguments is None and (is_zero_access(action.arguments) or action_digest(action.arguments)):
            current_version = action.policy_version
            if action.policy_id:
                policy = await session.get(Policy, action.policy_id)
                if policy is not None:
                    current_version = policy.version
            decision = EvaluationResult(
                decision=PolicyDecision(action.policy_decision) if action.policy_decision in PolicyDecision._value2member_map_ else PolicyDecision.APPROVAL_REQUIRED,
                policy_id=action.policy_id,
                policy_version=current_version,
                matched_rule_id=action.policy_rule_id,
                reason=action.policy_reason,
            )
            return tool, decision
        if arguments is not None:
            resolved = arguments
        else:
            try:
                resolved = stored_arguments(agent.organization_id, action.arguments)
            except ArgumentsUnavailable:
                # Fail closed: never evaluate policy on {} because the stored arguments cannot be opened.
                return tool, EvaluationResult(
                    decision=PolicyDecision.DENY,
                    policy_id=action.policy_id,
                    policy_version=action.policy_version,
                    matched_rule_id=action.policy_rule_id,
                    reason="Stored arguments could not be opened",
                )
        decision = await policy_engine.evaluate(
            session,
            organization_id=agent.organization_id,
            agent=agent,
            tool=tool,
            arguments=resolved,
        )
        action.policy_decision = decision.decision.value
        action.policy_id = decision.policy_id
        action.policy_rule_id = decision.matched_rule_id
        action.policy_version = decision.policy_version
        action.policy_reason = decision.reason
        await session.flush()
        await audit_service.log(
            session,
            event=AuditEvent.POLICY_EVALUATED,
            actor_type=ActorType.SYSTEM,
            actor_id="policy_engine",
            organization_id=agent.organization_id,
            run_id=action.run_id,
            action_id=action.id,
            tool=action.tool,
            result=decision.decision.value,
            payload={
                "policy_id": decision.policy_id,
                "policy_name": decision.policy_name,
                "policy_version": decision.policy_version,
                "matched_rule_id": decision.matched_rule_id,
                "reason": decision.reason,
                "arguments": resolved,
                "policy_fields": policy_fields(decision.matched_rule),
            },
        )
        return tool, decision

    async def execute_action(
        self,
        session: AsyncSession,
        action: Action,
        *,
        agent: Agent,
        actor_type: ActorType | str,
        actor_id: str,
        approved: bool = False,
        skip_policy: bool = False,
    ) -> Action:
        if skip_policy:
            tool = await self.get_tool(session, agent.organization_id, action.tool)
        else:
            tool, decision = await self.evaluate_action_policy(session, action, agent=agent)
            if decision.decision == PolicyDecision.DENY:
                action.status = ActionStatus.DENIED
                await session.flush()
                return action
            if decision.decision == PolicyDecision.APPROVAL_REQUIRED and not approved:
                approval = Approval(
                    id=new_id("approval"),
                    run_id=action.run_id,
                    action_id=action.id,
                    status=ApprovalStatus.PENDING,
                    requested_amount=_requested_amount(plain_arguments(agent.organization_id, action.arguments)),
                )
                session.add(approval)
                action.status = ActionStatus.WAITING_APPROVAL
                await session.flush()
                from app.features.execution.approvals.services.approval_service import approval_service

                await approval_service.configure_request(
                    session,
                    approval,
                    organization_id=agent.organization_id,
                    decision=decision,
                    arguments=plain_arguments(agent.organization_id, action.arguments),
                    requester_user_id=None,
                )
                await audit_service.log(
                    session,
                    event=AuditEvent.APPROVAL_REQUESTED,
                    actor_type=ActorType.AGENT,
                    actor_id=agent.id,
                    organization_id=agent.organization_id,
                    run_id=action.run_id,
                    action_id=action.id,
                    tool=action.tool,
                    result="pending",
                    payload={"approval_id": approval.id, "arguments": plain_arguments(agent.organization_id, action.arguments)},
                )
                return action

        return await self.execute_tool(
            session,
            action,
            tool=tool,
            agent=agent,
            actor_type=actor_type,
            actor_id=actor_id,
        )

    async def execute_tool(
        self,
        session: AsyncSession,
        action: Action,
        *,
        tool: Tool,
        agent: Agent,
        actor_type: ActorType | str,
        actor_id: str,
    ) -> Action:
        try:
            if not settings.in_process_runtime:
                raise MCPExecutionError("In-process MCP runtime is disabled")
            try:
                arguments = stored_arguments(agent.organization_id, action.arguments)
            except ArgumentsUnavailable as exc:
                raise MCPExecutionError("Stored arguments could not be opened") from exc
            result = await mcp_executor.execute(tool.name, arguments)
        except MCPExecutionError as exc:
            action.status = ActionStatus.FAILED
            action.result = {"status": "error", "error": str(exc)}
            await session.flush()
            return action

        action.status = ActionStatus.COMPLETED
        action.result = result
        await session.flush()
        await audit_service.log(
            session,
            event=AuditEvent.TOOL_EXECUTED,
            actor_type=actor_type,
            actor_id=actor_id,
            organization_id=tool.organization_id,
            run_id=action.run_id,
            action_id=action.id,
            tool=action.tool,
            result="success",
            payload={"result": action.result},
        )
        return action

    async def _advance_run(self, session: AsyncSession, run: Run, agent: Agent) -> None:
        if run.status == RunStatus.QUEUED:
            run.status = RunStatus.RUNNING
            await session.flush()
            await audit_service.log(
                session,
                event=AuditEvent.AGENT_STARTED,
                actor_type=ActorType.AGENT,
                actor_id=agent.id,
                organization_id=run.organization_id,
                run_id=run.id,
            )
            await self._materialize_plan(session, run)

        result = await session.execute(
            select(Action).where(Action.run_id == run.id).order_by(Action.position.asc())
        )
        actions = list(result.scalars().all())

        for action in actions:
            if action.status != ActionStatus.PENDING:
                continue
            await audit_service.log(
                session,
                event=AuditEvent.TOOL_REQUESTED,
                actor_type=ActorType.AGENT,
                actor_id=agent.id,
                organization_id=run.organization_id,
                run_id=run.id,
                action_id=action.id,
                tool=action.tool,
                payload={"arguments": plain_arguments(agent.organization_id, action.arguments)},
            )
            await self.execute_action(
                session,
                action,
                agent=agent,
                actor_type=ActorType.AGENT,
                actor_id=agent.id,
            )
            if action.status == ActionStatus.WAITING_APPROVAL:
                run.status = RunStatus.WAITING_APPROVAL
                run.updated_at = utcnow()
                await session.flush()
                return
            if action.status in {ActionStatus.DENIED, ActionStatus.FAILED}:
                run.status = RunStatus.FAILED
                run.updated_at = utcnow()
                await session.flush()
                await audit_service.log(
                    session,
                    event=AuditEvent.RUN_FAILED,
                    actor_type=ActorType.SYSTEM,
                    actor_id="saturn",
                    organization_id=run.organization_id,
                    run_id=run.id,
                    action_id=action.id,
                    tool=action.tool,
                    result=action.status,
                )
                return

        if all(action.status == ActionStatus.COMPLETED for action in actions):
            run.status = RunStatus.COMPLETED
            run.updated_at = utcnow()
            await session.flush()
            await audit_service.log(
                session,
                event=AuditEvent.RUN_COMPLETED,
                actor_type=ActorType.SYSTEM,
                actor_id="saturn",
                organization_id=run.organization_id,
                run_id=run.id,
                result="success",
            )

    async def _materialize_plan(self, session: AsyncSession, run: Run) -> None:
        existing = await session.execute(select(Action.id).where(Action.run_id == run.id))
        if existing.first() is not None:
            return
        for position, step in enumerate(agent_simulator.plan(run.input)):
            session.add(
                Action(
                    id=new_id("action"),
                    run_id=run.id,
                    tool=step.tool,
                    arguments=step.arguments,
                    status=ActionStatus.PENDING,
                    position=position,
                )
            )
        await session.flush()

    async def get_tool(self, session: AsyncSession, organization_id: str, name: str) -> Tool:
        result = await session.execute(
            select(Tool).where(Tool.organization_id == organization_id, Tool.name == name)
        )
        tool = result.scalar_one_or_none()
        if tool is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"Tool not found: {name}")
        return tool


def _requested_amount(arguments: dict) -> Decimal | None:
    from app.features.policy.policies.services.policy_engine import strict_number

    # Anything but a plain number is not an amount; never a 500 on agent input.
    return strict_number(arguments.get("amount"))


def pending_approval_id(run: Run) -> str | None:
    for approval in run.approvals:
        if approval.is_pending:
            return approval.id
    return None


run_service = RunService()
