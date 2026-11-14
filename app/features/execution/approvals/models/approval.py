from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, Numeric, String, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import ApprovalStatus, ExecutionState, ExpiryPhase
from app.core.ids import utcnow
from app.db.database import Base


def _text(value) -> str:
    """Columns hold plain text, but a value just assigned may still be the enum member."""
    return value.value if hasattr(value, "value") else str(value or "")


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class Approval(Base):
    __tablename__ = "approvals"
    __table_args__ = (
        # What the expiry worker looks for every few seconds: open approvals past a deadline.
        Index("ix_approvals_pending_expiry", "expires_at", postgresql_where=text("status = 'pending'"), sqlite_where=text("status = 'pending'")),
        Index(
            "ix_approvals_resubmit_expiry",
            "resubmit_expires_at",
            postgresql_where=text("status = 'approved' AND execution_state = 'none'"),
            sqlite_where=text("status = 'approved' AND execution_state = 'none'"),
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), nullable=False, index=True)
    action_id: Mapped[str] = mapped_column(
        ForeignKey("actions.id"), nullable=False, unique=True, index=True
    )
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False, index=True)
    requested_amount: Mapped[Optional[float]] = mapped_column(Numeric(12, 2), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    required_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    approval_policy_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    group_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    allow_requester: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    parameter_digest: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    policy_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    policy_version: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    approval_policy_version: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resubmit_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expired_phase: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    execution_state: Mapped[str] = mapped_column(String(32), default="none", nullable=False)
    requester_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    group_requirements: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    run = relationship("Run", back_populates="approvals")
    action = relationship("Action", back_populates="approval")
    decisions = relationship(
        "ApprovalDecision",
        back_populates="approval",
        cascade="all, delete-orphan",
    )

    # What the approval is now. status, execution_state and expired_phase are written only by
    # ApprovalLifecycle.move; everything else reads them through these.

    @property
    def state(self) -> ApprovalStatus:
        return ApprovalStatus(_text(self.status) or ApprovalStatus.PENDING.value)

    @property
    def execution(self) -> ExecutionState:
        return ExecutionState(_text(self.execution_state) or ExecutionState.NONE.value)

    @property
    def is_pending(self) -> bool:
        return self.state is ApprovalStatus.PENDING

    @property
    def is_expired(self) -> bool:
        return self.state is ApprovalStatus.EXPIRED

    @property
    def awaits_resubmit(self) -> bool:
        """Approved, and the agent has not sent the call again yet."""
        return self.state is ApprovalStatus.APPROVED and self.execution is ExecutionState.NONE

    @property
    def execution_started(self) -> bool:
        return self.execution is not ExecutionState.NONE

    def due_phase(self, now: datetime) -> ExpiryPhase | None:
        """The deadline that has passed, if one has. Nothing expires once its call has started."""
        if self.is_pending:
            deadline, phase = _as_utc(self.expires_at), ExpiryPhase.PENDING
        elif self.awaits_resubmit:
            deadline, phase = _as_utc(self.resubmit_expires_at), ExpiryPhase.RESUBMIT
        else:
            return None
        return phase if deadline is not None and deadline <= now else None

    # Who has to approve.

    @property
    def votes_needed(self) -> int:
        return int(self.required_count or 1)

    @property
    def requirements(self) -> list[dict]:
        """The groups that must approve, each with how many of its members. Empty: anyone eligible."""
        raw = self.group_requirements if isinstance(self.group_requirements, list) else []
        found = [
            {"group_id": str(item["group_id"]), "required_count": int(item.get("required_count") or 1)}
            for item in raw
            if isinstance(item, dict) and item.get("group_id")
        ]
        if found:
            return found
        if self.group_id:
            return [{"group_id": self.group_id, "required_count": self.votes_needed}]
        return []

    # Whether it was asked under rules that are still in force.

    def policy_changed(self, policy_id: str | None, policy_version: int | None) -> bool:
        if self.policy_version is None:
            return False
        if policy_version != self.policy_version:
            return True
        return bool(self.policy_id and policy_id and policy_id != self.policy_id)

    def approval_policy_changed(self, policy: ApprovalPolicy | None) -> bool:
        if policy is None or not policy.is_active:
            return True
        return (policy.version or 1) != (self.approval_policy_version or 1)


class ApprovalPolicy(Base):
    __tablename__ = "approval_policies"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    required_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    group_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    allow_requester: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    expires_minutes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    resubmit_minutes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    requirements = relationship(
        "ApprovalRequirement",
        back_populates="policy",
        cascade="all, delete-orphan",
        order_by="ApprovalRequirement.position",
    )

    @property
    def is_active(self) -> bool:
        return _text(self.status) == "active"


class ApprovalRequirement(Base):
    __tablename__ = "approval_requirements"
    __table_args__ = (
        UniqueConstraint("approval_policy_id", "group_id", name="uq_approval_requirement_group"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    approval_policy_id: Mapped[str] = mapped_column(
        ForeignKey("approval_policies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    group_id: Mapped[str] = mapped_column(ForeignKey("groups.id"), nullable=False, index=True)
    required_count: Mapped[int] = mapped_column(Integer, nullable=False)
    position: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    policy = relationship("ApprovalPolicy", back_populates="requirements")
    group = relationship("Group")


class ApprovalWindow(Base):
    __tablename__ = "approval_windows"

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), primary_key=True)
    pending_ttl_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=1440)
    resubmit_ttl_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=1440)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class ApprovalDecision(Base):
    __tablename__ = "approval_decisions"
    __table_args__ = (UniqueConstraint("approval_id", "employee_id", name="uq_approval_vote"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    approval_id: Mapped[str] = mapped_column(
        ForeignKey("approvals.id", ondelete="CASCADE"), nullable=False, index=True
    )
    employee_id: Mapped[str] = mapped_column(ForeignKey("employees.id"), nullable=False, index=True)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    approval = relationship("Approval", back_populates="decisions")
