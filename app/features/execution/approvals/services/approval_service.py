from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.core.ids import new_id, utcnow
from app.features.execution.approvals.models.approval import ApprovalDecision, ApprovalPolicy, ApprovalRequirement
from app.features.execution.approvals.models.transitions import (
    APPROVE,
    APPROVE_AND_CLAIM,
    CANCEL,
    INVALIDATE,
    REJECT,
    Transition,
)
from app.features.execution.approvals.services.approval_arguments import (
    ArgumentsUnavailable,
    digest_matches,
    is_server_sealed,
    keyed_digest,
    open_sealed,
    stored_arguments,
)
from app.features.organization.org.models.group import Group, GroupMember
from app.features.organization.org.services.access import is_org_admin
from app.features.execution.activity.services.zero_access import action_digest, is_zero_access
from app.models import Action, Agent, Approval, Employee, Run, Tool, User
from app.core.enums import (
    ActionStatus,
    ActorType,
    AuditEvent,
    ExecutionState,
    PolicyDecision,
    RunStatus,
)
from app.features.execution.activity.services.audit_service import audit_service
from app.features.execution.approvals.services.expiration import (
    arm_pending,
    arm_resubmit,
    clamp_minutes,
    expire_due,
    expire_if_due,
    notify_transition,
)
from app.features.execution.approvals.services.claimed_call import ClaimedCall, Executed, OutcomeUncertain, OutcomeUnrecorded
from app.features.execution.approvals.services.lifecycle import approval_lifecycle
from app.features.execution.runs.services.run_service import run_service
from app.features.policy.policies.services.policy_engine import policy_engine

settings = get_settings()


class ApprovalService:
    async def list_approvals(self, session: AsyncSession, organization_id: str, page=None) -> list[Approval]:
        await expire_due(session, organization_id, now=utcnow())
        statement = (
            select(Approval)
            .options(selectinload(Approval.decisions))
            .join(Run, Approval.run_id == Run.id)
            .where(Run.organization_id == organization_id)
            .order_by(Approval.created_at.desc())
        )
        if page is not None:
            # Newest first, a page at a time, so a flooded queue cannot make one request load it all.
            statement = page.apply(statement)
        result = await session.execute(statement)
        return list(result.scalars().all())

    async def get_approval(
        self, session: AsyncSession, approval_id: str, organization_id: str
    ) -> Approval:
        result = await session.execute(
            select(Approval).options(selectinload(Approval.decisions)).where(Approval.id == approval_id)
        )
        approval = result.scalar_one_or_none()
        if approval is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Approval not found")
        run = await session.get(Run, approval.run_id)
        if run is None or run.organization_id != organization_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Approval not found")
        await expire_if_due(session, approval, utcnow())
        return approval

    async def approve(
        self,
        session: AsyncSession,
        approval_id: str,
        actor_id: str,
        *,
        organization_id: str,
        execution_arguments: dict | None = None,
    ) -> tuple[Run, Action, str, str | None]:
        approval, action, run, agent = await self._load_pending(
            session, approval_id, actor_id, organization_id=organization_id
        )
        # Every approval, including a single-approver one, checks who may vote.
        await self._ensure_open(session, approval)
        employee = await self._employee(session, actor_id, run.organization_id)
        await self._assert_voter(session, approval, employee, actor_id)
        if approval.votes_needed > 1:
            return await self._approve_quorum(
                session, approval, action, run, agent, actor_id, employee, execution_arguments=execution_arguments
            )
        mapped = action.policy_reason in {"tool_set_approval", "saturn_mcp"}

        _tool, decision = await run_service.evaluate_action_policy(
            session, action, agent=agent
        )
        if decision.decision == PolicyDecision.DENY:
            await self._decide(session, approval, REJECT, actor_id)
            action.status = ActionStatus.DENIED
            run.status = RunStatus.FAILED
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
                result="policy_deny_on_approve",
                payload={"source": "saturn_mcp"} if mapped else None,
            )
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "Policy no longer allows this action",
            )
        if decision.decision not in {
            PolicyDecision.ALLOW,
            PolicyDecision.APPROVAL_REQUIRED,
        }:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Policy decision is not executable")
        # A single approver is held to the same rules as a quorum: the policy and approval policy
        # people asked under must still be the ones in force.
        await self._revalidate_versions(session, approval, action, decision)

        # Atomic claim: of two concurrent approvals only one moves the row out of pending.
        await self._decide(session, approval, APPROVE, actor_id)
        await audit_service.log(
            session,
            event=AuditEvent.APPROVAL_GRANTED,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            organization_id=run.organization_id,
            run_id=run.id,
            action_id=action.id,
            tool=action.tool,
            result="approved",
            payload={"approval_id": approval.id, **({"source": "saturn_mcp"} if mapped else {})},
        )

        if mapped or not settings.in_process_runtime:
            await arm_resubmit(session, approval, run.organization_id)
        await notify_transition(session, run.organization_id, "approval.granted", approval, action.tool)

        if mapped or not settings.in_process_runtime:
            run.status = RunStatus.RUNNING
            run.updated_at = utcnow()
            await session.flush()
            return await run_service.load_run(session, run.id), action, "completed", None

        await run_service.execute_action(
            session,
            action,
            agent=agent,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            approved=True,
            skip_policy=True,
        )
        if action.status == ActionStatus.FAILED:
            run.status = RunStatus.FAILED
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Tool execution failed")

        await run_service.continue_run(session, run)
        return await run_service.load_run(session, run.id), action, "completed", None

    async def reject(
        self,
        session: AsyncSession,
        approval_id: str,
        actor_id: str,
        *,
        organization_id: str,
    ) -> tuple[Run, Action]:
        approval, action, run, _agent = await self._load_pending(
            session, approval_id, actor_id, organization_id=organization_id
        )
        await self._ensure_open(session, approval)
        employee = await self._employee(session, actor_id, organization_id)
        await self._assert_voter(session, approval, employee, actor_id)
        mapped = action.policy_reason in {"tool_set_approval", "saturn_mcp"}
        await self._decide(session, approval, REJECT, actor_id)
        action.status = ActionStatus.REJECTED
        run.status = RunStatus.CANCELLED
        run.updated_at = utcnow()
        await session.flush()
        await audit_service.log(
            session,
            event=AuditEvent.APPROVAL_REJECTED,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            organization_id=run.organization_id,
            run_id=run.id,
            action_id=action.id,
            tool=action.tool,
            result="rejected",
            payload={"approval_id": approval.id, **({"source": "saturn_mcp"} if mapped else {})},
        )
        await notify_transition(session, run.organization_id, "approval.rejected", approval, action.tool)
        return await run_service.load_run(session, run.id), action

    async def _load_pending(
        self,
        session: AsyncSession,
        approval_id: str,
        actor_id: str,
        organization_id: str,
    ) -> tuple[Approval, Action, Run, Agent]:
        if not actor_id:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User is required")

        result = await session.execute(
            select(Approval)
            .options(
                selectinload(Approval.action),
                selectinload(Approval.run).selectinload(Run.agent),
            )
            .where(Approval.id == approval_id)
        )
        approval = result.scalar_one_or_none()
        if approval is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Approval not found")
        if await expire_if_due(session, approval, utcnow()):
            raise HTTPException(status.HTTP_409_CONFLICT, "Approval expired")
        if not approval.is_pending:
            raise HTTPException(status.HTTP_409_CONFLICT, "Approval is not pending")

        action = approval.action or await session.get(Action, approval.action_id)
        if action is None:
            raise HTTPException(status.HTTP_409_CONFLICT, "Action not found")
        if action.status != ActionStatus.WAITING_APPROVAL:
            raise HTTPException(status.HTTP_409_CONFLICT, "Action is not waiting for approval")

        run = approval.run or await session.get(Run, approval.run_id)
        if run is None:
            raise HTTPException(status.HTTP_409_CONFLICT, "Run not found")
        if run.organization_id != organization_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Approval not found")

        agent = run.agent or await session.get(Agent, run.agent_id)
        if agent is None:
            raise HTTPException(status.HTTP_409_CONFLICT, "Agent not found")
        return approval, action, run, agent

    async def cancel(
        self,
        session: AsyncSession,
        approval_id: str,
        actor_id: str,
        *,
        organization_id: str,
    ) -> tuple[Run, Action]:
        approval, action, run, _agent = await self._load_pending(
            session, approval_id, actor_id, organization_id=organization_id
        )
        await self._ensure_open(session, approval)
        employee = await self._employee(session, actor_id, organization_id)
        # Only the person who asked, or a team admin, may withdraw a request.
        if approval.requester_user_id != actor_id and not is_org_admin(employee.permissions):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Only the requester or an admin can cancel this request")
        await self._decide(session, approval, CANCEL, actor_id)
        action.status = ActionStatus.REJECTED
        run.status = RunStatus.CANCELLED
        run.updated_at = utcnow()
        await session.flush()
        await audit_service.log(
            session,
            event=AuditEvent.APPROVAL_REJECTED,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            organization_id=run.organization_id,
            run_id=run.id,
            action_id=action.id,
            tool=action.tool,
            result="cancelled",
            payload={"approval_id": approval.id},
        )
        return await run_service.load_run(session, run.id), action

    async def configure_request(
        self,
        session: AsyncSession,
        approval: Approval,
        *,
        organization_id: str,
        decision,
        arguments: dict,
        requester_user_id: str | None,
    ) -> None:
        approval.parameter_digest = parameter_digest(organization_id, arguments if isinstance(arguments, dict) else {})
        approval.requester_user_id = requester_user_id
        approval.policy_id = getattr(decision, "policy_id", None)
        approval.policy_version = getattr(decision, "policy_version", None)
        approval.required_count = 1
        approval.allow_requester = True
        policy_id = getattr(decision, "approval_policy_id", None)
        if not policy_id:
            await arm_pending(session, approval, organization_id)
            await session.flush()
            return
        policy = await session.get(ApprovalPolicy, policy_id)
        if (
            policy is None
            or policy.organization_id != organization_id
            or not policy.is_active
        ):
            # The rule names an approval policy that is gone or turned off. Fall back to one
            # approver who is not the requester when anyone else can decide, and say so.
            approval.allow_requester = False
            await arm_pending(session, approval, organization_id)
            await session.flush()
            await audit_service.log(
                session,
                event=AuditEvent.APPROVAL_REQUESTED,
                actor_type=ActorType.SYSTEM,
                actor_id="saturn",
                organization_id=organization_id,
                run_id=approval.run_id,
                action_id=approval.action_id,
                result="approval_policy_unavailable",
                payload={"approval_id": approval.id, "approval_policy_id": policy_id},
            )
            return
        approval.approval_policy_id = policy.id
        approval.approval_policy_version = policy.version or 1
        approval.allow_requester = bool(policy.allow_requester)
        requirements = list(
            (
                await session.scalars(
                    select(ApprovalRequirement)
                    .where(ApprovalRequirement.approval_policy_id == policy.id)
                    .order_by(ApprovalRequirement.position)
                )
            ).all()
        )
        if requirements:
            approval.group_requirements = [
                {"group_id": item.group_id, "required_count": int(item.required_count)}
                for item in requirements
            ]
            approval.group_id = None
            approval.required_count = sum(int(item.required_count) for item in requirements)
        else:
            approval.group_requirements = []
            approval.required_count = int(policy.required_count or 1)
            approval.group_id = policy.group_id
        if policy.expires_minutes:
            approval.expires_at = utcnow() + timedelta(minutes=clamp_minutes(int(policy.expires_minutes)))
        else:
            await arm_pending(session, approval, organization_id)
        await session.flush()

    async def _decide(
        self,
        session: AsyncSession,
        approval: Approval,
        transition: Transition,
        actor_id: str,
        *,
        lost: str = "Approval is not pending",
    ) -> None:
        """Take the approval out of pending. Of two people deciding at once, the second is refused."""
        if await approval_lifecycle.move(session, approval, transition, actor_id=actor_id, now=utcnow()):
            return
        if approval.is_expired:
            raise HTTPException(status.HTTP_409_CONFLICT, "Approval expired")
        raise HTTPException(status.HTTP_409_CONFLICT, lost)

    async def _approve_quorum(
        self,
        session: AsyncSession,
        approval: Approval,
        action: Action,
        run: Run,
        agent: Agent,
        actor_id: str,
        employee: Employee,
        execution_arguments: dict | None = None,
    ) -> tuple[Run, Action, str, str | None]:
        # One vote at a time per approval. Two final votes counted side by side would each see
        # only themselves, both report "pending", and neither member could vote again.
        await session.execute(select(Approval.id).where(Approval.id == approval.id).with_for_update())
        duplicate = await session.scalar(
            select(ApprovalDecision).where(
                ApprovalDecision.approval_id == approval.id,
                ApprovalDecision.employee_id == employee.id,
            )
        )
        if duplicate is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, "This member already decided")
        vote = ApprovalDecision(
            id=new_id("vote"),
            approval_id=approval.id,
            employee_id=employee.id,
            decision="approved",
        )
        session.add(vote)
        await session.flush()
        counts = await self._tally(session, approval)
        prepared: _Prepared | None = None
        if _requirements_met(counts):
            try:
                prepared = await self._prepare_execution(session, approval, action, agent, execution_arguments)
            except HTTPException:
                # Keep the approval open so this member can vote again with the arguments.
                await session.delete(vote)
                await session.flush()
                raise
            # Policy is evaluated again on the exact arguments that are about to run.
            await self._revalidate_quorum(session, approval, action, agent, prepared.arguments)
            counts = await self._tally(session, approval)
            if not _requirements_met(counts):
                prepared = None
        progress = _progress_text(counts)
        await audit_service.log(
            session,
            event=AuditEvent.APPROVAL_GRANTED,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            organization_id=run.organization_id,
            run_id=run.id,
            action_id=action.id,
            tool=action.tool,
            result="recorded",
            payload={
                "approval_id": approval.id,
                "employee_id": employee.id,
                "approved_count": counts[0][0] if len(counts) == 1 else progress,
                "required_count": approval.votes_needed,
                "progress": progress,
                "source": "saturn_mcp",
            },
        )
        if prepared is None:
            return run, action, "pending", progress

        await self._decide(session, approval, APPROVE_AND_CLAIM, actor_id, lost="Execution already claimed")
        await audit_service.log(
            session,
            event=AuditEvent.APPROVAL_QUORUM,
            actor_type=ActorType.SYSTEM,
            actor_id="saturn",
            organization_id=run.organization_id,
            run_id=run.id,
            action_id=action.id,
            tool=action.tool,
            result="reached",
            payload={
                "approval_id": approval.id,
                "required_count": approval.votes_needed,
                "progress": progress,
                "source": "saturn_mcp",
            },
        )
        await audit_service.log(
            session,
            event=AuditEvent.EXECUTION_CLAIMED,
            actor_type=ActorType.SYSTEM,
            actor_id="saturn",
            organization_id=run.organization_id,
            run_id=run.id,
            action_id=action.id,
            tool=action.tool,
            result="claimed",
            payload={"approval_id": approval.id, "source": "saturn_mcp"},
        )
        await notify_transition(session, run.organization_id, "approval.granted", approval, action.tool)
        # The claim must survive anything that fails after the upstream call, so it is committed first.
        await session.commit()
        await self._execute_claimed(session, approval, action, run, agent, actor_id, prepared)
        return await run_service.load_run(session, run.id), action, "completed", "success"

    async def _prepare_execution(
        self,
        session: AsyncSession,
        approval: Approval,
        action: Action,
        agent: Agent,
        execution_arguments: dict | None,
    ) -> _Prepared:
        # The last vote runs the call on the requester's behalf, with nobody signed in as them.
        if approval.requester_user_id and not await self._still_active(session, approval.requester_user_id):
            await self._invalidate(session, approval, action, "requester is no longer active")
        tool = await run_service.get_tool(session, agent.organization_id, action.tool)
        gateway = bool(getattr(tool, "mcp_server_id", None) or getattr(tool, "mcp_endpoint", None))
        if not gateway and settings.in_process_runtime:
            return _Prepared(tool=tool, gateway=False, arguments=None)
        from app.features.mcp.saturn.services.saturn_mcp import saturn_mcp

        # The same check tools/call makes: active, and still in this agent's tool set.
        exposed = {item.id for item, _ in await saturn_mcp._exposed(session, agent)}
        if tool.id not in exposed:
            await self._invalidate(session, approval, action, "tool no longer available to this agent")
        return _Prepared(
            tool=tool,
            gateway=True,
            arguments=approved_arguments(agent.organization_id, approval, action, execution_arguments),
        )

    async def _execute_claimed(
        self,
        session: AsyncSession,
        approval: Approval,
        action: Action,
        run: Run,
        agent: Agent,
        actor_id: str,
        prepared: _Prepared,
    ) -> None:
        if prepared.gateway:
            await self._send_claimed(session, approval, action, run, agent, prepared)
            return
        await run_service.execute_action(
            session,
            action,
            agent=agent,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            approved=True,
            skip_policy=True,
        )
        if action.status == ActionStatus.FAILED:
            run.status = RunStatus.FAILED
            await approval_lifecycle.settle(session, approval, ExecutionState.FAILED)
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Tool execution failed")
        await approval_lifecycle.settle(session, approval, ExecutionState.EXECUTED, commit=False)
        await run_service.continue_run(session, run)

    async def _send_claimed(
        self,
        session: AsyncSession,
        approval: Approval,
        action: Action,
        run: Run,
        agent: Agent,
        prepared: _Prepared,
    ) -> None:
        """The last vote sends the approved call through the gateway."""
        from app.features.mcp.saturn.services.saturn_mcp import saturn_mcp

        arguments = prepared.arguments or {}

        async def audit(executed: Executed) -> None:
            await audit_service.log(
                session,
                event=AuditEvent.TOOL_EXECUTED,
                actor_type=ActorType.AGENT,
                actor_id=agent.id,
                organization_id=run.organization_id,
                run_id=run.id,
                action_id=action.id,
                tool=action.tool,
                result="completed",
                payload={
                    "approval_id": approval.id,
                    "arguments": arguments,
                    "server_result": executed.result,
                    "raw_response": executed.raw,
                    "source": "saturn_mcp",
                },
            )
            await audit_service.log(
                session,
                event=AuditEvent.RUN_COMPLETED,
                actor_type=ActorType.SYSTEM,
                actor_id="saturn",
                organization_id=run.organization_id,
                run_id=run.id,
                result="success",
            )

        call = ClaimedCall(session, approval, action, run, organization_id=run.organization_id)
        try:
            await call.run(lambda: saturn_mcp._proxy(session, prepared.tool, arguments), audit)
        except OutcomeUnrecorded as exc:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "The tool ran but Saturn could not record the outcome; treat it as uncertain",
            ) from exc
        except OutcomeUncertain as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, "Upstream outcome is uncertain") from exc

    async def _revalidate_quorum(
        self,
        session: AsyncSession,
        approval: Approval,
        action: Action,
        agent: Agent,
        opened: dict | None = None,
    ) -> None:
        arguments = opened
        if arguments is None and not action_digest(action.arguments) and not is_zero_access(action.arguments):
            try:
                arguments = stored_arguments(agent.organization_id, action.arguments)
            except ArgumentsUnavailable:
                await self._invalidate(session, approval, action, "parameters unreadable")
        if (
            arguments is not None
            and approval.parameter_digest
            and not digest_matches(agent.organization_id, approval.parameter_digest, arguments)
        ):
            await self._invalidate(session, approval, action, "parameters changed")
        if arguments is not None:
            # Every active policy, on the real arguments: a deny added since the request applies.
            fresh = await policy_engine.evaluate_named(
                session,
                organization_id=agent.organization_id,
                agent=agent,
                tool_name=action.tool,
                arguments=arguments,
            )
        else:
            _tool, fresh = await run_service.evaluate_action_policy(session, action, agent=agent)
        if fresh.decision == PolicyDecision.DENY:
            if await approval_lifecycle.move(session, approval, REJECT, now=utcnow()):
                action.status = ActionStatus.DENIED
                run = await session.get(Run, approval.run_id)
                if run is not None:
                    run.status = RunStatus.FAILED
                await session.flush()
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Policy no longer allows this action")
        await self._revalidate_versions(session, approval, action, fresh)
        await audit_service.log(
            session,
            event=AuditEvent.POLICY_EVALUATED,
            actor_type=ActorType.SYSTEM,
            actor_id="policy_engine",
            organization_id=agent.organization_id,
            run_id=action.run_id,
            action_id=action.id,
            tool=action.tool,
            result="revalidated",
            payload={"approval_id": approval.id, "policy_version": fresh.policy_version, "source": "saturn_mcp"},
        )

    async def _revalidate_versions(self, session: AsyncSession, approval: Approval, action: Action, fresh) -> None:
        """Invalidate when the policy or approval policy the request was made under has changed."""
        if approval.policy_changed(fresh.policy_id, fresh.policy_version):
            await self._invalidate(session, approval, action, "policy changed")
        if approval.approval_policy_id:
            policy = await session.get(ApprovalPolicy, approval.approval_policy_id)
            if approval.approval_policy_changed(policy):
                await self._invalidate(session, approval, action, "approval policy changed")

    async def _invalidate(self, session: AsyncSession, approval: Approval, action: Action, reason: str) -> None:
        """Close an approval that no longer matches what would run. Always raises."""
        transition = INVALIDATE.get(approval.state)
        # If someone else moved the approval first, their outcome stands and nothing is recorded here.
        if transition is not None and await approval_lifecycle.move(session, approval, transition, now=utcnow()):
            action.status = ActionStatus.DENIED
            run = await session.get(Run, approval.run_id)
            if run is not None:
                run.status = RunStatus.FAILED
                await audit_service.log(
                    session,
                    event=AuditEvent.APPROVAL_INVALIDATED,
                    actor_type=ActorType.SYSTEM,
                    actor_id="saturn",
                    organization_id=run.organization_id,
                    run_id=run.id,
                    action_id=action.id,
                    tool=action.tool,
                    result="invalidated",
                    payload={"approval_id": approval.id, "reason": reason},
                )
            await session.flush()
        raise HTTPException(status.HTTP_409_CONFLICT, "Approval no longer matches this operation")

    async def _still_active(self, session: AsyncSession, user_id: str) -> bool:
        user = await session.get(User, user_id)
        if user is None or user.status != "active":
            return False
        employee = await session.scalar(select(Employee).where(Employee.user_id == user_id))
        return employee is not None and employee.status == "active"

    async def _ensure_open(self, session: AsyncSession, approval: Approval) -> None:
        if await expire_if_due(session, approval, utcnow()):
            raise HTTPException(status.HTTP_409_CONFLICT, "Approval expired")
        if approval.execution_started:
            raise HTTPException(status.HTTP_409_CONFLICT, "Approval is not pending")

    async def _employee(self, session: AsyncSession, user_id: str, organization_id: str) -> Employee:
        employee = await session.scalar(
            select(Employee).where(
                Employee.user_id == user_id,
                Employee.organization_id == organization_id,
            )
        )
        if employee is None or employee.status != "active":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Not an eligible approver")
        return employee

    async def _assert_voter(
        self,
        session: AsyncSession,
        approval: Approval,
        employee: Employee,
        actor_id: str,
    ) -> None:
        if approval.requester_user_id == actor_id:
            if not approval.allow_requester:
                raise HTTPException(status.HTTP_403_FORBIDDEN, "Requester cannot approve this request")
            # Without an approval policy, a request needs a second person whenever one could
            # decide it. Only a policy that says so lets the requester approve their own agent.
            if not approval.approval_policy_id and await self._other_approver(session, employee):
                raise HTTPException(status.HTTP_403_FORBIDDEN, "Another approver must decide this request")
        specs = approval.requirements
        if not specs:
            return
        member = await session.scalar(
            select(GroupMember)
            .join(Group, Group.id == GroupMember.group_id)
            .where(
                GroupMember.group_id.in_([item["group_id"] for item in specs]),
                GroupMember.employee_id == employee.id,
                Group.status == "active",
            )
        )
        if member is None:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Not an eligible approver")

    async def _other_approver(self, session: AsyncSession, employee: Employee) -> bool:
        from app.features.organization.org.services.access import allows

        result = await session.scalars(
            select(Employee).where(
                Employee.organization_id == employee.organization_id,
                Employee.status == "active",
                Employee.id != employee.id,
            )
        )
        return any(allows(item.permissions, "approvals", "write") for item in result.all())

    async def requirement_progress(self, session: AsyncSession, approval: Approval) -> list[dict]:
        specs = approval.requirements
        if len(specs) < 2:
            return []
        counts = await self._tally(session, approval)
        group_ids = [item["group_id"] for item in specs]
        groups = await session.execute(select(Group).where(Group.id.in_(group_ids)))
        names = {item.id: item.name for item in groups.scalars().all()}
        return [
            {
                "group_id": spec["group_id"],
                "group_name": names.get(spec["group_id"], ""),
                "required_count": need,
                "approved_count": got,
            }
            for spec, (got, need) in zip(specs, counts, strict=True)
        ]

    async def _tally(self, session: AsyncSession, approval: Approval) -> list[tuple[int, int]]:
        result = await session.execute(
            select(ApprovalDecision).where(
                ApprovalDecision.approval_id == approval.id,
                ApprovalDecision.decision == "approved",
            )
            .order_by(ApprovalDecision.created_at, ApprovalDecision.id)
        )
        votes = list(result.scalars().all())
        specs = approval.requirements
        if not specs:
            return [(len(votes), approval.votes_needed)]
        # A disabled group fills no seats, so its requirement cannot be met until it is active again.
        rows = await session.execute(
            select(GroupMember)
            .join(Group, Group.id == GroupMember.group_id)
            .where(
                GroupMember.group_id.in_([item["group_id"] for item in specs]),
                GroupMember.employee_id.in_([item.employee_id for item in votes] or [""]),
                Group.status == "active",
            )
        )
        memberships: dict[str, set[str]] = {}
        for member in rows.scalars().all():
            memberships.setdefault(member.employee_id, set()).add(member.group_id)
        voters = list(dict.fromkeys(item.employee_id for item in votes))
        return _assign_votes(voters, memberships, specs)


def _assign_votes(
    voters: list[str],
    memberships: dict[str, set[str]],
    specs: list[dict],
) -> list[tuple[int, int]]:
    """Each vote fills at most one requirement seat (maximum bipartite matching).

    A person in Finance and Admin counts once, for whichever requirement still needs them.
    """
    seats: list[int] = []
    for index, spec in enumerate(specs):
        seats.extend([index] * int(spec["required_count"]))
    holder: list[str | None] = [None] * len(seats)

    def place(voter: str, visited: set[int]) -> bool:
        groups = memberships.get(voter, set())
        for seat, index in enumerate(seats):
            if seat in visited or specs[index]["group_id"] not in groups:
                continue
            visited.add(seat)
            current = holder[seat]
            if current is None or place(current, visited):
                holder[seat] = voter
                return True
        return False

    for voter in voters:
        place(voter, set())
    filled = [0] * len(specs)
    for seat, index in enumerate(seats):
        if holder[seat] is not None:
            filled[index] += 1
    return [(filled[index], int(spec["required_count"])) for index, spec in enumerate(specs)]


def _progress_text(counts: list[tuple[int, int]]) -> str:
    return "+".join(f"{got}/{need}" for got, need in counts)


def _requirements_met(counts: list[tuple[int, int]]) -> bool:
    return all(got >= need for got, need in counts)


def parameter_digest(organization_id: str, arguments: dict) -> str:
    """Keyed per organization, so a database copy cannot confirm guesses of the arguments."""
    return keyed_digest(organization_id, arguments)


@dataclass
class _Prepared:
    tool: Tool
    gateway: bool
    arguments: dict | None


def approved_arguments(
    organization_id: str,
    approval: Approval,
    action: Action,
    execution_arguments: dict | None,
) -> dict:
    """The exact arguments people approved. Never a digest stub."""
    stored = action.arguments
    digest = action_digest(stored)
    if is_zero_access(stored):
        if not isinstance(execution_arguments, dict):
            raise HTTPException(status.HTTP_409_CONFLICT, "Encrypted arguments are required to execute this approval")
        arguments = execution_arguments
    elif is_server_sealed(stored):
        try:
            arguments = open_sealed(organization_id, stored)
        except ArgumentsUnavailable as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, "Approved parameters can no longer be read") from exc
    elif digest:
        # Written before arguments were sealed server-side: only the digest was kept.
        if not isinstance(execution_arguments, dict):
            raise HTTPException(status.HTTP_409_CONFLICT, "Approved parameters are required to execute this approval")
        arguments = execution_arguments
    else:
        try:
            arguments = stored_arguments(organization_id, stored)
        except ArgumentsUnavailable as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, "Approved parameters can no longer be read") from exc
    for expected in (digest, approval.parameter_digest):
        if expected and not digest_matches(organization_id, expected, arguments):
            raise HTTPException(status.HTTP_409_CONFLICT, "Approved parameters no longer match this call")
    return arguments


approval_service = ApprovalService()
