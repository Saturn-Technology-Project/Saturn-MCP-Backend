from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import select, update

from app.core.enums import ApprovalStatus, ExecutionState, ExpiryPhase
from app.core.ids import new_id
from app.features.execution.approvals.models.approval import Approval, ApprovalPolicy
from app.features.execution.approvals.models.transitions import (
    APPROVE,
    APPROVE_AND_CLAIM,
    CANCEL,
    CLAIM,
    EXPIRE,
    INVALIDATE,
    REJECT,
    SETTLE,
)
from app.features.execution.approvals.services.lifecycle import approval_lifecycle

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)
EVERY = [APPROVE, APPROVE_AND_CLAIM, REJECT, CANCEL, CLAIM, *INVALIDATE.values(), *EXPIRE.values(), *SETTLE.values()]


def _approval(status="pending", execution="none", **more) -> Approval:
    return Approval(id="apr_1", run_id="run_1", action_id="act_1", status=status, execution_state=execution, **more)


# The approval itself: what it is, and which deadline applies.


def test_a_new_approval_is_pending_and_not_started():
    blank = Approval(id="apr_1", run_id="run_1", action_id="act_1")
    assert blank.state is ApprovalStatus.PENDING and blank.execution is ExecutionState.NONE
    assert blank.is_pending and not blank.execution_started and not blank.awaits_resubmit
    # A value just assigned may still be the enum member, not its text.
    assert _approval(status=ApprovalStatus.APPROVED).awaits_resubmit


def test_only_the_deadline_of_the_current_step_can_pass():
    past, future = NOW - timedelta(seconds=1), NOW + timedelta(seconds=1)
    assert _approval(expires_at=past).due_phase(NOW) is ExpiryPhase.PENDING
    assert _approval(expires_at=NOW).due_phase(NOW) is ExpiryPhase.PENDING
    assert _approval(expires_at=future).due_phase(NOW) is None
    assert _approval(expires_at=None).due_phase(NOW) is None
    # Once approved, the pending deadline no longer counts; the resubmit one does.
    assert _approval("approved", expires_at=past).due_phase(NOW) is None
    assert _approval("approved", resubmit_expires_at=past).due_phase(NOW) is ExpiryPhase.RESUBMIT
    # A call that has started never expires under whoever is running it.
    for started in ("claimed", "executed", "uncertain", "failed"):
        assert _approval("approved", started, resubmit_expires_at=past).due_phase(NOW) is None
    for closed in ("rejected", "cancelled", "invalidated", "expired"):
        assert _approval(closed, expires_at=past, resubmit_expires_at=past).due_phase(NOW) is None
    # SQLite hands back times without a zone; they are UTC.
    assert _approval(expires_at=past.replace(tzinfo=None)).due_phase(NOW) is ExpiryPhase.PENDING


def test_requirements_come_from_the_group_list_then_the_single_group():
    assert _approval().requirements == []
    assert _approval(group_id="g1", required_count=2).requirements == [{"group_id": "g1", "required_count": 2}]
    listed = _approval(group_id="ignored", group_requirements=[{"group_id": "g1", "required_count": 2}, {"group_id": "g2"}, {}, "x"])
    assert listed.requirements == [{"group_id": "g1", "required_count": 2}, {"group_id": "g2", "required_count": 1}]
    assert _approval(required_count=None).votes_needed == 1


def test_an_approval_knows_when_its_rules_changed():
    unversioned = _approval(policy_id="p1")
    assert not unversioned.policy_changed("p2", 9)
    asked = _approval(policy_id="p1", policy_version=3)
    assert not asked.policy_changed("p1", 3)
    assert asked.policy_changed("p1", 4)
    assert asked.policy_changed("p2", 3)
    assert not asked.policy_changed(None, 3)

    under = _approval(approval_policy_id="ap1", approval_policy_version=2)
    assert under.approval_policy_changed(None)
    assert under.approval_policy_changed(ApprovalPolicy(status="disabled", version=2))
    assert under.approval_policy_changed(ApprovalPolicy(status="active", version=3))
    assert not under.approval_policy_changed(ApprovalPolicy(status="active", version=2))


# The table of allowed changes.


def test_nothing_leaves_a_closed_or_finished_approval():
    open_statuses = {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}
    for transition in EVERY:
        if transition.status_from is None:
            # Settling: only a claimed call can end, and its status does not change.
            assert transition.execution_from is ExecutionState.CLAIMED and transition.status_to is None
        else:
            assert transition.status_from in open_statuses, transition.name
            assert transition.execution_from is ExecutionState.NONE, transition.name
    assert len({item.name for item in EVERY}) == len(EVERY)


def test_resolved_is_stamped_once_when_it_stops_waiting():
    decided = REJECT.changes(now=NOW, actor_id="user_1")
    assert decided == {"status": "rejected", "resolved_at": NOW, "resolved_by": "user_1"}
    # The system closing it names nobody.
    assert "resolved_by" not in EXPIRE[ExpiryPhase.PENDING].changes(now=NOW)
    assert EXPIRE[ExpiryPhase.PENDING].changes(now=NOW)["expired_phase"] == "pending"
    # After approval the moment it was resolved stays the moment it was approved.
    for later in (CLAIM, INVALIDATE[ApprovalStatus.APPROVED], EXPIRE[ExpiryPhase.RESUBMIT], *SETTLE.values()):
        assert "resolved_at" not in later.changes(now=NOW, actor_id="user_1"), later.name
    with pytest.raises(ValueError):
        APPROVE.changes()


# Applying a change to the stored row.


async def _stored(client, status="pending", execution="none"):
    from app.db.database import get_session
    from app.main import app
    from app.models import Action, Run, User

    generator = app.dependency_overrides[get_session]()
    session = await anext(generator)
    user = (await session.scalars(select(User).where(User.email == "rick@saturn.ai"))).one()
    run = Run(id=new_id("run"), organization_id=user.organization_id, agent_id="agent_customer_ops", input="billing.refund", status="waiting_approval")
    action = Action(id=new_id("act"), run_id=run.id, tool="billing.refund", arguments={}, status="waiting_approval")
    approval = Approval(id=new_id("apr"), run_id=run.id, action_id=action.id, status=status, execution_state=execution)
    session.add_all([run, action, approval])
    await session.commit()
    return generator, session, approval, action


async def _row(session, approval_id):
    found = await session.execute(
        select(Approval.status, Approval.execution_state, Approval.resolved_at, Approval.resolved_by, Approval.expired_phase).where(
            Approval.id == approval_id
        )
    )
    return found.one()


async def test_a_decision_is_written_once(client):
    generator, session, approval, _action = await _stored(client)
    try:
        assert await approval_lifecycle.move(session, approval, APPROVE, actor_id="user_1", now=NOW)
        assert approval.state is ApprovalStatus.APPROVED and approval.resolved_by == "user_1"
        stored = await _row(session, approval.id)
        assert (stored.status, stored.execution_state, stored.resolved_by) == ("approved", "none", "user_1")

        # A second decision finds it gone from pending, whoever asks and whatever they ask for.
        for late in (APPROVE, REJECT, CANCEL, APPROVE_AND_CLAIM, INVALIDATE[ApprovalStatus.PENDING], EXPIRE[ExpiryPhase.PENDING]):
            assert not await approval_lifecycle.move(session, approval, late, actor_id="user_2", now=NOW + timedelta(hours=1))
        stored = await _row(session, approval.id)
        assert (stored.status, stored.resolved_by) == ("approved", "user_1")
    finally:
        await generator.aclose()


async def test_an_approved_call_is_claimed_by_one_sender_and_then_only_settled(client):
    generator, session, approval, _action = await _stored(client, "approved")
    try:
        assert await approval_lifecycle.move(session, approval, CLAIM)
        assert approval.execution is ExecutionState.CLAIMED
        assert not await approval_lifecycle.move(session, approval, CLAIM)
        # Running: it can no longer expire or be invalidated under whoever holds the claim.
        assert not await approval_lifecycle.move(session, approval, EXPIRE[ExpiryPhase.RESUBMIT], now=NOW)
        assert not await approval_lifecycle.move(session, approval, INVALIDATE[ApprovalStatus.APPROVED])

        await approval_lifecycle.settle(session, approval, ExecutionState.EXECUTED, commit=False)
        assert approval.execution is ExecutionState.EXECUTED
        # What happened is recorded once: a later report cannot rewrite it.
        await approval_lifecycle.settle(session, approval, ExecutionState.FAILED, commit=False)
        assert approval.execution is ExecutionState.EXECUTED
        assert (await _row(session, approval.id)).execution_state == "executed"
    finally:
        await generator.aclose()


async def test_a_refused_change_shows_where_the_approval_went(client):
    generator, session, approval, _action = await _stored(client)
    try:
        # Another request expires it; this session still holds the pending copy.
        await session.execute(
            update(Approval).where(Approval.id == approval.id).values(status="expired", expired_phase="pending"),
            execution_options={"synchronize_session": False},
        )
        assert approval.is_pending
        assert not await approval_lifecycle.move(session, approval, APPROVE, actor_id="user_1", now=NOW)
        assert approval.is_expired and approval.resolved_by is None
    finally:
        await generator.aclose()


async def test_an_unrecorded_outcome_keeps_the_claim_as_uncertain(client):
    generator, session, approval, _action = await _stored(client, "approved", "claimed")
    try:
        await approval_lifecycle.mark_unrecorded(session, approval.id)
        assert (await _row(session, approval.id)).execution_state == "uncertain"
        # Only a claim is rewritten; a call nobody started is left alone.
        other_generator, other_session, untouched, _ = await _stored(client, "approved")
        try:
            await approval_lifecycle.mark_unrecorded(other_session, untouched.id)
            assert (await _row(other_session, untouched.id)).execution_state == "none"
        finally:
            await other_generator.aclose()
    finally:
        await generator.aclose()


async def test_invalidating_does_not_overwrite_a_call_someone_else_started(client):
    """Found while moving the rules here: this used to assign the status whatever the row held."""
    from app.features.execution.approvals.services.approval_service import approval_service

    generator, session, approval, action = await _stored(client, "approved")
    try:
        # Another sender claims the call after this request loaded the approval.
        await session.execute(
            update(Approval).where(Approval.id == approval.id).values(execution_state="claimed"),
            execution_options={"synchronize_session": False},
        )
        with pytest.raises(HTTPException) as refused:
            await approval_service._invalidate(session, approval, action, "policy changed")
        assert refused.value.status_code == 409
        stored = await _row(session, approval.id)
        assert (stored.status, stored.execution_state) == ("approved", "claimed")
        assert action.status == "waiting_approval"
    finally:
        await generator.aclose()


async def test_invalidating_an_open_approval_closes_it_and_its_call(client):
    from app.features.execution.approvals.services.approval_service import approval_service

    generator, session, approval, action = await _stored(client)
    try:
        with pytest.raises(HTTPException):
            await approval_service._invalidate(session, approval, action, "policy changed")
        stored = await _row(session, approval.id)
        assert stored.status == "invalidated" and stored.resolved_at is not None and stored.resolved_by is None
        assert action.status == "denied"
    finally:
        await generator.aclose()


# Sending a claimed call: one flow for a quorum's last vote and for an agent's resubmit.


async def _claimed(client):
    from app.models import Run

    generator, session, approval, action = await _stored(client, "approved", "claimed")
    run = await session.get(Run, approval.run_id)
    return generator, session, approval, action, run


def _call(session, approval, action, run):
    from app.features.execution.approvals.services.claimed_call import ClaimedCall

    return ClaimedCall(session, approval, action, run, organization_id=run.organization_id)


async def test_a_claimed_call_that_answers_is_executed_and_its_answer_sealed(client):
    from app.features.execution.approvals.services.approval_arguments import open_result

    generator, session, approval, action, run = await _claimed(client)
    try:
        audited = []

        async def send():
            return {"jsonrpc": "2.0", "id": 1, "result": {"paid": True}}

        async def audit(executed):
            audited.append(executed)

        executed = await _call(session, approval, action, run).run(send, audit)
        assert executed.result == {"paid": True} and executed.raw["id"] == 1
        assert audited == [executed]
        assert (await _row(session, approval.id)).execution_state == "executed"
        assert (action.status, run.status) == ("completed", "completed")
        assert "paid" not in str(action.result)
        assert open_result(run.organization_id, action.result) == {"paid": True}
    finally:
        await generator.aclose()


async def test_a_claimed_call_that_is_refused_is_failed_and_the_error_is_kept(client):
    generator, session, approval, action, run = await _claimed(client)
    try:

        async def send():
            raise HTTPException(502, "MCP server returned HTTP 500")

        async def audit(_executed):
            raise AssertionError("nothing ran, so nothing is audited as executed")

        with pytest.raises(HTTPException) as refused:
            await _call(session, approval, action, run).run(send, audit)
        assert refused.value.status_code == 502
        assert (await _row(session, approval.id)).execution_state == "failed"
        assert (action.status, run.status) == ("failed", "failed")
    finally:
        await generator.aclose()


async def test_a_claimed_call_that_times_out_is_uncertain_and_leaves_the_action_open(client, monkeypatch):
    from app.features.execution.approvals.services.claimed_call import OutcomeUncertain, OutcomeUnrecorded
    from app.features.identity.auth.services import notices

    told = []

    async def notify(_session, run, outcome):
        told.append((run.id, outcome))

    monkeypatch.setattr(notices, "notify_task_outcome", notify)
    generator, session, approval, action, run = await _claimed(client)
    try:

        async def send():
            raise TimeoutError()

        async def audit(_executed):
            raise AssertionError("an unknown outcome is not audited as executed")

        with pytest.raises(OutcomeUncertain) as unknown:
            await _call(session, approval, action, run).run(send, audit)
        assert not isinstance(unknown.value, OutcomeUnrecorded)
        assert isinstance(unknown.value.__cause__, TimeoutError)
        assert (await _row(session, approval.id)).execution_state == "uncertain"
        # Nobody knows whether it ran, so the action is not marked either way.
        assert action.status == "waiting_approval"
        assert told == [(run.id, "failed")]
    finally:
        await generator.aclose()


async def test_an_answer_that_cannot_be_saved_keeps_the_claim_as_uncertain(client):
    from app.features.execution.approvals.services.claimed_call import OutcomeUnrecorded

    generator, session, approval, action, run = await _claimed(client)
    approval_id, action_id = approval.id, action.id
    try:
        sent = []

        async def send():
            sent.append(1)
            return {"paid": True}

        async def audit(_executed):
            raise ValueError("audit log refused")

        with pytest.raises(OutcomeUnrecorded) as unsaved:
            await _call(session, approval, action, run).run(send, audit)
        assert isinstance(unsaved.value.__cause__, ValueError)
        assert sent == [1]
        stored = await _row(session, approval_id)
        assert (stored.status, stored.execution_state) == ("approved", "uncertain")
        # The half-written success was rolled back with the audit entry that failed.
        from app.models import Action

        kept = (await session.execute(select(Action.status, Action.result).where(Action.id == action_id))).one()
        assert kept.status == "waiting_approval" and kept.result is None
    finally:
        await generator.aclose()
