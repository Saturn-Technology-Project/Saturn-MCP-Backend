from __future__ import annotations

import logging
from datetime import datetime

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import set_committed_value

from app.core.enums import ExecutionState
from app.features.execution.approvals.models.approval import Approval
from app.features.execution.approvals.models.transitions import SETTLE, Transition

logger = logging.getLogger(__name__)


class ApprovalLifecycle:
    """The one place an approval changes state.

    Each change is a single conditional UPDATE: it is written only if the stored row is still
    where the transition starts. Two requests racing for the same approval (two approvers, an
    approver and the expiry worker, the same call sent twice) therefore cannot both win, whatever
    each of them read beforehand.
    """

    async def move(
        self,
        session: AsyncSession,
        approval: Approval,
        transition: Transition,
        *,
        actor_id: str | None = None,
        now: datetime | None = None,
    ) -> bool:
        """Apply the transition. False means someone else moved the approval first.

        After False the approval has been read again, so the caller can see where it went.
        The caller says when it happened; this class never reads the clock.
        """
        values = transition.changes(now=now, actor_id=actor_id)
        if not await self._write(session, approval.id, transition, values):
            await session.refresh(approval)
            return False
        for column, value in values.items():
            set_committed_value(approval, column, value)
        return True

    async def settle(
        self,
        session: AsyncSession,
        approval: Approval,
        outcome: ExecutionState,
        *,
        commit: bool = True,
    ) -> None:
        """Record how a claimed call ended. Only a claimed approval moves."""
        await self.move(session, approval, SETTLE[outcome])
        await session.flush()
        if commit:
            await session.commit()

    async def mark_unrecorded(self, session: AsyncSession, approval_id: str) -> None:
        """The upstream ran but saving its outcome failed. Keep the committed claim, as uncertain.

        Takes the id, not the object: the failed transaction is rolled back first, and nothing
        loaded in it can be trusted afterwards.
        """
        try:
            await session.rollback()
        except Exception:
            logger.exception("Rollback after an executed approval failed")
        try:
            transition = SETTLE[ExecutionState.UNCERTAIN]
            await self._write(session, approval_id, transition, transition.changes())
            await session.commit()
        except Exception:
            # The claim is already committed, so the call still cannot run again automatically.
            logger.exception("Could not mark approval %s uncertain", approval_id)

    async def _write(self, session: AsyncSession, approval_id: str, transition: Transition, values: dict) -> bool:
        still_there = [Approval.id == approval_id, Approval.execution_state == transition.execution_from.value]
        if transition.status_from is not None:
            still_there.append(Approval.status == transition.status_from.value)
        result = await session.execute(update(Approval).where(*still_there).values(**values))
        return result.rowcount == 1


approval_lifecycle = ApprovalLifecycle()
