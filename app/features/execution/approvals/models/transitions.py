"""Every change an approval may go through.

    pending ── approve ──▶ approved ── claim ──▶ claimed ── settle ──▶ executed
       │                      │                                      │ uncertain
       ├─ reject              ├─ invalidate                          └ failed
       ├─ cancel              └─ expire (resubmit window)
       ├─ invalidate
       └─ expire

A quorum's last vote approves and claims in one step. Nothing else is allowed: a change that is
not listed here cannot be made, and ApprovalLifecycle applies each one only while the stored row
is still where the change starts.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.core.enums import ApprovalStatus, ExecutionState, ExpiryPhase


@dataclass(frozen=True)
class Transition:
    name: str
    execution_from: ExecutionState
    # None: whatever the status is. Settling a claim looks only at the claim.
    status_from: ApprovalStatus | None = None
    status_to: ApprovalStatus | None = None
    execution_to: ExecutionState | None = None
    expiry: ExpiryPhase | None = None

    def changes(self, *, now: datetime | None = None, actor_id: str | None = None) -> dict[str, object]:
        """The column values this change writes. Leaving pending needs the moment it happened."""
        values: dict[str, object] = {}
        if self.status_to is not None:
            values["status"] = self.status_to.value
        if self.execution_to is not None:
            values["execution_state"] = self.execution_to.value
        if self.expiry is not None:
            values["expired_phase"] = self.expiry.value
        if self.status_from is ApprovalStatus.PENDING:
            # Resolved means it stopped waiting for a decision. Later changes keep that moment.
            if now is None:
                raise ValueError(f"{self.name} needs the time it happened")
            values["resolved_at"] = now
            if actor_id:
                values["resolved_by"] = actor_id
        return values


def _from_pending(name: str, target: ApprovalStatus, **more) -> Transition:
    return Transition(name, ExecutionState.NONE, ApprovalStatus.PENDING, target, **more)


def _from_approved(name: str, target: ApprovalStatus | None = None, **more) -> Transition:
    return Transition(name, ExecutionState.NONE, ApprovalStatus.APPROVED, target, **more)


APPROVE = _from_pending("approve", ApprovalStatus.APPROVED)
APPROVE_AND_CLAIM = _from_pending("approve_and_claim", ApprovalStatus.APPROVED, execution_to=ExecutionState.CLAIMED)
REJECT = _from_pending("reject", ApprovalStatus.REJECTED)
CANCEL = _from_pending("cancel", ApprovalStatus.CANCELLED)

# The agent sent an approved call again: only one sender may run it.
CLAIM = _from_approved("claim", execution_to=ExecutionState.CLAIMED)

INVALIDATE = {
    ApprovalStatus.PENDING: _from_pending("invalidate_request", ApprovalStatus.INVALIDATED),
    ApprovalStatus.APPROVED: _from_approved("invalidate_grant", ApprovalStatus.INVALIDATED),
}

EXPIRE = {
    ExpiryPhase.PENDING: _from_pending("expire_request", ApprovalStatus.EXPIRED, expiry=ExpiryPhase.PENDING),
    ExpiryPhase.RESUBMIT: _from_approved("expire_grant", ApprovalStatus.EXPIRED, expiry=ExpiryPhase.RESUBMIT),
}

# How a claimed call ended.
SETTLE = {
    outcome: Transition(f"settle_{outcome.value}", ExecutionState.CLAIMED, execution_to=outcome)
    for outcome in (ExecutionState.EXECUTED, ExecutionState.UNCERTAIN, ExecutionState.FAILED)
}
