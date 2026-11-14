from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import ExecutionState, RunStatus
from app.core.ids import new_id
from app.features.identity.auth.models.notice_delivery import NoticeDelivery
from app.features.identity.auth.models.user import User
from app.features.identity.auth.services.mailer import console_origin, is_english, send_notice
from app.models import Agent, Approval, AuditLog, Group, Run

logger = logging.getLogger(__name__)

_SECRET = re.compile(
    r"(secret|token|password|passwd|api[_-]?key|authorization|credential|private[_-]?key|session)",
    re.IGNORECASE,
)
_OK = {"completed", "success"}


async def notify_audit(session: AsyncSession, entry: AuditLog) -> None:
    try:
        await _dispatch(session, entry)
    except Exception:
        logger.exception("Could not prepare a notice for %s", entry.id)


async def notify_task_outcome(session: AsyncSession, run: Run, outcome: str) -> None:
    try:
        rows = await _task_rows(session, run.organization_id, run.id)
        await _send_task(session, run.organization_id, run.id, outcome, rows, run)
    except Exception:
        logger.exception("Could not send a task notice for %s", run.id)


async def finish_task_notice(
    session: AsyncSession,
    organization_id: str,
    execution_id: str,
    requested: str,
    summary: str = "",
) -> None:
    # Only a real run of this organization; ids that appear only in audit payloads are agent-chosen.
    run = await session.get(Run, execution_id)
    if run is None or run.organization_id != organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Task not found")
    if run.status == RunStatus.WAITING_APPROVAL:
        raise HTTPException(status.HTTP_409_CONFLICT, "Task is waiting for approval")
    if run.status in {RunStatus.QUEUED, RunStatus.RUNNING} and requested == "completed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Task is still running")
    rows = await _task_rows(session, organization_id, execution_id)
    outcome = requested
    if run.status in {RunStatus.FAILED, RunStatus.CANCELLED}:
        outcome = "failed"
    if _blocked(rows):
        outcome = "failed"
    await _send_task(
        session,
        organization_id,
        execution_id,
        outcome,
        rows,
        run,
        summary=_summary_text(summary),
    )


async def _dispatch(session: AsyncSession, entry: AuditLog) -> None:
    event = str(entry.event or "")
    result = str(entry.result or "")
    if event == "approval_requested":
        await _send_approval(session, entry)
        return
    if event == "tool_requested" and result == "denied":
        await _send_security(session, entry, "denied")
        return
    if event == "policy_evaluated" and result == "deny":
        await _send_security(session, entry, "deny")
        return
    if event in {"run_completed", "run_failed", "approval_rejected", "approval_expired"}:
        if not entry.run_id or not entry.organization_id:
            return
        outcome = "completed" if event == "run_completed" else "failed"
        rows = await _task_rows(session, entry.organization_id, entry.run_id)
        run = await session.get(Run, entry.run_id)
        if outcome == "completed" and _blocked(rows):
            outcome = "failed"
        await _send_task(session, entry.organization_id, entry.run_id, outcome, rows, run)


async def _send_approval(session: AsyncSession, entry: AuditLog) -> None:
    if not entry.organization_id:
        return
    payload = entry.payload if isinstance(entry.payload, dict) else {}
    approval_id = str(payload.get("approval_id") or entry.id)
    approval = await session.get(Approval, approval_id)
    agent = await _agent_name(session, entry)
    tool = entry.tool or ""
    lines = _approval_lines(entry, approval, await _group_names(session, approval))
    detail = _public_text(str(payload.get("reason") or ""), 160)
    await _deliver(
        session,
        entry.organization_id,
        "approval",
        f"approval:{approval_id}",
        User.notify_approval,
        tool=tool,
        agent=agent,
        link=f"{console_origin()}/approvals",
        lines=lines,
        detail=detail,
        localize_lines=True,
    )


async def _send_security(session: AsyncSession, entry: AuditLog, decision: str) -> None:
    if not entry.organization_id:
        return
    payload = entry.payload if isinstance(entry.payload, dict) else {}
    task_id = str(entry.run_id or payload.get("run_id") or entry.id)
    agent = await _agent_name(session, entry)
    tool = entry.tool or ""
    english_lines = (
        f"Decision · {decision}",
        "Response · Saturn did not run this action",
    )
    await _deliver(
        session,
        entry.organization_id,
        "security",
        f"security:{task_id}:{tool}:{decision}",
        User.notify_audit,
        tool=tool,
        agent=agent,
        link=f"{console_origin()}/activity?event={entry.id}",
        lines=english_lines,
        detail=_public_text(str(payload.get("reason") or ""), 160),
        localize_lines=True,
    )


async def _send_task(
    session: AsyncSession,
    organization_id: str,
    execution_id: str,
    outcome: str,
    rows: list[AuditLog],
    run: Run | None,
    summary: str = "",
) -> None:
    kind = "completed" if outcome == "completed" else "failed"
    agent = ""
    if run is not None:
        loaded = await session.get(Agent, run.agent_id)
        agent = loaded.name if loaded is not None else ""
    if not agent:
        agent = await _agent_name(session, rows[-1] if rows else None)
    title = _task_title(run, rows, summary)
    lines = _task_lines(rows, execution_id, run)
    extra = summary if summary and summary != title else ""
    uncertain = False
    if run is not None:
        state = await session.scalar(
            select(Approval.execution_state).where(
                Approval.run_id == run.id,
                Approval.execution_state == ExecutionState.UNCERTAIN.value,
            )
        )
        uncertain = state is not None
    link_id = execution_id if run is not None else (rows[-1].id if rows else execution_id)

    def detail_for(locale: str | None) -> str:
        note = _failure_note(rows, run, is_english(locale), uncertain) if kind == "failed" else ""
        return " ".join(part for part in (extra, note) if part).strip()

    await _deliver(
        session,
        organization_id,
        kind,
        f"task:{execution_id}:{kind}",
        User.notify_execute,
        tool=title,
        agent=agent,
        link=f"{console_origin()}/activity?event={link_id}",
        lines=tuple(lines),
        detail="",
        detail_for=detail_for,
        localize_lines=True,
    )


async def _deliver(
    session: AsyncSession,
    organization_id: str,
    kind: str,
    key: str,
    column,
    *,
    tool: str,
    agent: str,
    link: str,
    lines: tuple[str, ...],
    detail: str,
    detail_for=None,
    localize_lines: bool = False,
) -> None:
    users = list(
        (
            await session.scalars(
                select(User).where(
                    User.organization_id == organization_id,
                    User.status == "active",
                    column.is_(True),
                )
            )
        ).all()
    )
    for user in users:
        shown = _localized_lines(lines, user.locale) if localize_lines else lines
        body = detail_for(user.locale) if detail_for is not None else detail
        if not await _claim(session, organization_id, user.email, key, kind):
            continue
        try:
            sent = await send_notice(
                user.email,
                kind=kind,
                tool=tool,
                agent=agent,
                link=link,
                locale=user.locale,
                lines=shown,
                detail=body,
            )
        except Exception:
            logger.exception("Could not send %s notice to %s", kind, user.email)
            sent = False
        if not sent:
            await _release(session, user.email, key)


async def _claim(session: AsyncSession, organization_id: str, email: str, key: str, kind: str) -> bool:
    try:
        async with session.begin_nested():
            session.add(
                NoticeDelivery(
                    id=new_id("notice"),
                    organization_id=organization_id,
                    email=email,
                    idempotency_key=key,
                    kind=kind,
                )
            )
            await session.flush()
    except IntegrityError:
        return False
    return True


async def _release(session: AsyncSession, email: str, key: str) -> None:
    row = await session.scalar(
        select(NoticeDelivery).where(
            NoticeDelivery.email == email,
            NoticeDelivery.idempotency_key == key,
        )
    )
    if row is not None:
        await session.delete(row)
        await session.flush()


async def _task_rows(session: AsyncSession, organization_id: str, execution_id: str) -> list[AuditLog]:
    rows = await session.scalars(
        select(AuditLog)
        .where(
            AuditLog.organization_id == organization_id,
            or_(
                AuditLog.run_id == execution_id,
                AuditLog.payload["run_id"].as_string() == execution_id,
            ),
        )
        .order_by(AuditLog.created_at.asc())
    )
    return list(rows.all())


def _blocked(rows: list[AuditLog]) -> bool:
    for row in rows:
        if row.event == "tool_requested" and row.result == "denied":
            return True
        if row.event == "policy_evaluated" and row.result == "deny":
            return True
    return False


async def _agent_name(session: AsyncSession, entry: AuditLog | None) -> str:
    if entry is None or not entry.actor_id:
        return ""
    agent = await session.get(Agent, entry.actor_id)
    if agent is None or agent.organization_id != entry.organization_id:
        return ""
    return agent.name


async def _group_names(session: AsyncSession, approval: Approval | None) -> dict[str, str]:
    if approval is None:
        return {}
    raw = approval.group_requirements if isinstance(approval.group_requirements, list) else []
    ids = [str(item.get("group_id")) for item in raw if isinstance(item, dict) and item.get("group_id")]
    if approval.group_id:
        ids.append(approval.group_id)
    if not ids:
        return {}
    groups = await session.scalars(select(Group).where(Group.id.in_(ids)))
    return {item.id: item.name for item in groups.all()}


def _approval_lines(entry: AuditLog, approval: Approval | None, names: dict[str, str]) -> tuple[str, ...]:
    lines = ["Status · Pending"]
    if approval is not None:
        raw = approval.group_requirements if isinstance(approval.group_requirements, list) else []
        parts = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            label = names.get(str(item.get("group_id") or ""), "") or str(item.get("group_id") or "")
            count = int(item.get("required_count") or 0)
            if label and count:
                parts.append(f"{label} {count}")
        if parts:
            lines.append(f"Approvers · {' + '.join(parts)}")
        elif approval.group_id:
            label = names.get(approval.group_id, approval.group_id)
            lines.append(f"Approvers · {label} {int(approval.required_count or 1)}")
        elif int(approval.required_count or 1) > 1:
            lines.append(f"Approvers · {int(approval.required_count)}")
        if approval.expires_at is not None:
            lines.append(f"Deadline · {_stamp(approval.expires_at)}")
    return tuple(lines)


def _task_title(run: Run | None, rows: list[AuditLog], summary: str) -> str:
    if run is not None and run.input.strip():
        return _public_text(run.input.strip(), 80) or "Task"
    if summary:
        return _public_text(summary, 80) or "Task"
    names = []
    for row in rows:
        if row.event in {"tool_executed", "tool_requested"} and row.tool and row.tool not in names:
            names.append(row.tool)
    if names:
        return _public_text(", ".join(names[:3]), 80) or "Task"
    return "Task"


def _task_lines(rows: list[AuditLog], execution_id: str, run: Run | None) -> list[str]:
    executed = [row for row in rows if row.event == "tool_executed"]
    failed = [row for row in executed if str(row.result or "") not in _OK]
    denied = [
        row
        for row in rows
        if (row.event == "tool_requested" and row.result == "denied")
        or (row.event == "policy_evaluated" and row.result == "deny")
    ]
    names = [row.tool for row in executed if row.tool]
    retries = len(names) - len(set(names))
    lines = [
        f"Tools · {len(executed)}",
        f"Task · {execution_id}",
    ]
    if failed or denied:
        lines.insert(1, f"Failed · {len(failed) + len(denied)}")
    if retries > 0:
        lines.insert(1, f"Retries · {retries}")
    if run is not None:
        lines.append(f"Status · {run.status}")
    when = run.updated_at if run is not None else (rows[-1].created_at if rows else None)
    if when is not None:
        lines.append(f"When · {_stamp(when)}")
    return lines


def _failure_note(rows: list[AuditLog], run: Run | None, english: bool, uncertain: bool) -> str:
    executed = [row for row in rows if row.event == "tool_executed"]
    failed = [row for row in executed if str(row.result or "") not in _OK]
    denied = [row for row in rows if row.event == "policy_evaluated" and row.result == "deny"]
    denied += [row for row in rows if row.event == "tool_requested" and row.result == "denied"]
    step = (failed or denied)[-1].tool if (failed or denied) else ""
    succeeded = [row for row in executed if str(row.result or "") in _OK]
    notes = []
    if step:
        notes.append(f"Stopped at {step}." if english else f"停在 {step}。")
    if succeeded and (failed or denied):
        notes.append(
            "Some steps already ran, so an external change may already have happened."
            if english
            else "有些步驟已經執行，外部系統可能已經被改動。"
        )
    if uncertain:
        notes.append("The final outcome is uncertain." if english else "最後結果還不確定。")
    elif failed or denied or (run is not None and run.status in {RunStatus.FAILED, RunStatus.CANCELLED}):
        notes.append("The final outcome is known." if english else "最後結果已經確定。")
    return " ".join(notes)


def _localized_lines(lines: tuple[str, ...], locale: str | None) -> tuple[str, ...]:
    if is_english(locale):
        return lines
    labels = {
        "Tools": "工具",
        "Failed": "失敗",
        "Retries": "重試",
        "Task": "任務",
        "Status": "狀態",
        "When": "時間",
        "Decision": "決定",
        "Response": "系統回應",
        "Approvers": "核准者",
        "Parameters": "參數",
        "Deadline": "期限",
    }
    values = {
        "Pending": "等待核准",
        "Saturn did not run this action": "Saturn 沒有執行這個操作",
        "denied": "拒絕",
        "deny": "政策拒絕",
        "completed": "已完成",
        "failed": "失敗",
        "cancelled": "已取消",
        "waiting_approval": "等待核准",
        "running": "執行中",
    }
    translated = []
    for line in lines:
        label, _, value = line.partition(" · ")
        translated.append(f"{labels.get(label, label)} · {values.get(value, value)}")
    return tuple(translated)


def _public_text(value: str, limit: int) -> str:
    text = " ".join(str(value or "").split())
    if not text:
        return ""
    if _SECRET.search(text) or (" " not in text and len(text) > 80):
        return ""
    if len(text) > limit:
        return text[:limit].rstrip() + "…"
    return text


_LINKISH = re.compile(
    r"(://|www\.|@|\b[a-z0-9-]+\.(?:[a-z]{2,24})(?:/|\b)|[<>\[\]{}`\\])",
    re.IGNORECASE,
)


def _summary_text(value: str) -> str:
    """A caller-written summary goes to every member by email, so it may not carry links, addresses or markup."""
    text = _public_text(value, 240)
    if not text or _LINKISH.search(text) or any(not char.isprintable() for char in text):
        return ""
    return text


def _stamp(value: datetime) -> str:
    moment = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
