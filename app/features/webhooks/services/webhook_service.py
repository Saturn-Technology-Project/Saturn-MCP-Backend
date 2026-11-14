from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ids import new_id, utcnow
from app.features.credentials.vault.services.pq_crypto import KeyUnavailable
from app.features.credentials.vault.services.secret_vault import get_secret, put_secret
from app.features.organization.org.services.plans import PRO_REQUIRED, allows_pro
from app.models import Organization
from app.features.webhooks.models.webhook import WebhookAttempt, WebhookDelivery, WebhookEndpoint
from app.features.webhooks.services.destinations import (
    WebhookUnresolved,
    pin_webhook_url,
    require_webhook_shape,
    require_webhook_url,
)
from app.features.webhooks.services.signing import SCHEMA, canonical_body, signed_headers

logger = logging.getLogger(__name__)

ALLOWED_EVENTS = ("approval.granted", "approval.rejected", "approval.expired")
TIMEOUT_SECONDS = 5
# Whole request, including a server that trickles its response headers.
TOTAL_TIMEOUT_SECONDS = 10
# We only need the status code. At most this much of a response body is ever read.
MAX_RESPONSE_BYTES = 64 * 1024
MAX_ENDPOINTS_PER_ORG = 20
# One worker cycle: at most BATCH_LIMIT deliveries, at most PER_ORG_LIMIT from one org, sent
# CONCURRENCY at a time. A tenant with slow endpoints delays only its own deliveries.
BATCH_LIMIT = 50
PER_ORG_LIMIT = 5
CONCURRENCY = 10
SCAN_LIMIT = 500
# A delivery being sent is pushed this far into the future before its transaction commits, so no
# row lock or transaction is open during the HTTP request and no other worker picks it meanwhile.
# If this process dies mid-send the delivery simply becomes due again: at least once, as before.
CLAIM_SECONDS = TOTAL_TIMEOUT_SECONDS * 6


def max_attempts() -> int:
    return 5


def backoff_seconds(attempt: int) -> float:
    # Jitter so retries do not line up. Not a secret, so the ordinary generator is right.
    return min(300, 2 ** min(attempt, 8)) + random.random()  # noqa: S311


def disabled_delay_seconds() -> int:
    return 60


def key_unavailable_delay_seconds() -> int:
    return 60


def clean_events(events: list[str]) -> list[str]:
    cleaned: list[str] = []
    for item in events:
        if item not in ALLOWED_EVENTS:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unknown webhook event")
        if item not in cleaned:
            cleaned.append(item)
    if not cleaned:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Choose at least one event")
    return cleaned


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    moment = _as_utc(value)
    if moment is None:
        return None
    return moment.isoformat()


def _public_error(text: str, secret: str) -> str:
    cleaned = (text or "").replace(secret, "••••") if secret else (text or "")
    return cleaned[:180]


async def _post_pinned(url: str, body: bytes, headers: dict[str, str]) -> int:
    try:
        target = await asyncio.to_thread(pin_webhook_url, url)
    except WebhookUnresolved:
        # A name that does not resolve right now is a network failure like any other.
        raise
    except HTTPException as exc:
        raise _DestinationRefused() from exc
    sent_headers = dict(headers)
    sent_headers["Host"] = target.host
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS, follow_redirects=False, trust_env=False) as client:
        request = client.build_request(
            "POST",
            target.url,
            content=body,
            headers=sent_headers,
            # TLS is negotiated and the certificate verified for the hostname, not the IP.
            extensions={"sni_hostname": target.host},
        )
        response = await client.send(request, stream=True)
        try:
            read = 0
            async for chunk in response.aiter_raw():
                read += len(chunk)
                if read >= MAX_RESPONSE_BYTES:
                    break
        finally:
            await response.aclose()
        return response.status_code


class _DestinationRefused(Exception):
    pass


async def send_webhook(url: str, body: bytes, headers: dict[str, str]) -> tuple[int | None, str]:
    try:
        code = await asyncio.wait_for(_post_pinned(url, body, headers), TOTAL_TIMEOUT_SECONDS)
    except _DestinationRefused:
        return None, "destination not allowed"
    except WebhookUnresolved:
        return None, "host did not resolve"
    except (httpx.TimeoutException, asyncio.TimeoutError):
        return None, "timeout"
    except Exception as exc:
        return None, type(exc).__name__
    if 300 <= code < 400:
        return code, "redirect not followed"
    return code, ""


async def _webhooks_allowed(session: AsyncSession, organization_id: str) -> bool:
    org = await session.get(Organization, organization_id)
    return org is not None and allows_pro(org.plan)


async def _endpoint(session: AsyncSession, organization_id: str, endpoint_id: str) -> WebhookEndpoint:
    row = await session.get(WebhookEndpoint, endpoint_id)
    if row is None or row.organization_id != organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Webhook endpoint not found")
    return row


async def list_endpoints(session: AsyncSession, organization_id: str) -> list[WebhookEndpoint]:
    result = await session.scalars(
        select(WebhookEndpoint)
        .where(WebhookEndpoint.organization_id == organization_id)
        .order_by(WebhookEndpoint.created_at.desc())
    )
    return list(result.all())


async def create_endpoint(
    session: AsyncSession,
    organization_id: str,
    *,
    url: str,
    events: list[str],
) -> tuple[WebhookEndpoint, str]:
    count = await session.scalar(
        select(func.count())
        .select_from(WebhookEndpoint)
        .where(WebhookEndpoint.organization_id == organization_id)
    )
    if int(count or 0) >= MAX_ENDPOINTS_PER_ORG:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"An organization can have at most {MAX_ENDPOINTS_PER_ORG} webhook endpoints",
        )
    # The lookup blocks, and the host is the caller's choice: a name server that never answers
    # must tie up a worker thread, not the event loop every other request runs on.
    checked = await asyncio.to_thread(require_webhook_url, url)
    chosen = clean_events(events)
    import secrets

    secret = secrets.token_urlsafe(32)
    endpoint_id = new_id("wh")
    secret_id = f"whsec_{endpoint_id}"
    await put_secret(session, secret_id, secret, organization_id)
    row = WebhookEndpoint(
        id=endpoint_id,
        organization_id=organization_id,
        url=checked,
        events=chosen,
        enabled=True,
        secret_id=secret_id,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    session.add(row)
    await session.flush()
    return row, secret


async def update_endpoint(
    session: AsyncSession,
    organization_id: str,
    endpoint_id: str,
    *,
    url: str | None = None,
    events: list[str] | None = None,
    enabled: bool | None = None,
) -> WebhookEndpoint:
    row = await _endpoint(session, organization_id, endpoint_id)
    if url is not None:
        row.url = await asyncio.to_thread(require_webhook_url, url)
    if events is not None:
        row.events = clean_events(events)
    if enabled is not None:
        row.enabled = enabled
    row.updated_at = utcnow()
    await session.flush()
    return row


async def reveal_secret(session: AsyncSession, organization_id: str, endpoint_id: str) -> str:
    row = await _endpoint(session, organization_id, endpoint_id)
    from app.features.credentials.vault.services.pq_crypto import SecretNeedsReconnect

    try:
        secret = await get_secret(session, row.secret_id, organization_id)
    except SecretNeedsReconnect as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "Signing secret needs to be rotated") from exc
    if not secret:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Signing secret is not available")
    return secret


async def rotate_secret(session: AsyncSession, organization_id: str, endpoint_id: str) -> str:
    import secrets

    row = await _endpoint(session, organization_id, endpoint_id)
    secret = secrets.token_urlsafe(32)
    await put_secret(session, row.secret_id, secret, organization_id)
    row.updated_at = utcnow()
    await session.flush()
    return secret


async def publish_approval(
    session: AsyncSession,
    *,
    organization_id: str,
    event_type: str,
    approval_id: str,
    run_id: str,
    action_id: str,
    tool: str,
    phase: str | None,
    expires_at: datetime | None,
    resubmit_expires_at: datetime | None,
    approval_status: str,
) -> None:
    key = f"{event_type}:{approval_id}"
    if phase:
        key = f"{key}:{phase}"
    data = {
        "approval_id": approval_id,
        "run_id": run_id,
        "action_id": action_id,
        "tool": tool,
        "status": approval_status,
        "phase": phase,
        "expires_at": _iso(expires_at),
        "resubmit_expires_at": _iso(resubmit_expires_at),
    }
    if not await _webhooks_allowed(session, organization_id):
        return
    await emit(session, organization_id, event_type, key, data)


async def emit(
    session: AsyncSession,
    organization_id: str,
    event_type: str,
    event_key: str,
    data: dict,
) -> None:
    endpoints = list(
        await session.scalars(
            select(WebhookEndpoint).where(
                WebhookEndpoint.organization_id == organization_id,
                WebhookEndpoint.enabled.is_(True),
            )
        )
    )
    for endpoint in endpoints:
        subscribed = list(endpoint.events or [])
        if event_type != "webhook.test" and event_type not in subscribed:
            continue
        event_id = new_id("whe")
        payload = {
            "schema": SCHEMA,
            "id": event_id,
            "type": event_type,
            "created_at": _iso(utcnow()),
            "data": data,
        }
        await _enqueue(session, organization_id, endpoint.id, event_type, event_key, event_id, payload)


async def _already_queued(session: AsyncSession, endpoint_id: str, event_key: str) -> bool:
    found = await session.scalar(
        select(WebhookDelivery.id).where(
            WebhookDelivery.endpoint_id == endpoint_id,
            WebhookDelivery.event_key == event_key,
        )
    )
    return found is not None


async def _enqueue(
    session: AsyncSession,
    organization_id: str,
    endpoint_id: str,
    event_type: str,
    event_key: str,
    event_id: str,
    payload: dict,
) -> None:
    """Queue one delivery. Only a duplicate (endpoint, event_key) is dropped, on purpose.

    Any other integrity error (an id collision) is retried with fresh ids and, if it keeps
    failing, logged loudly instead of silently losing the delivery.
    """
    for attempt in range(3):
        try:
            async with session.begin_nested():
                session.add(
                    WebhookDelivery(
                        id=new_id("whd"),
                        organization_id=organization_id,
                        endpoint_id=endpoint_id,
                        event_type=event_type,
                        event_key=event_key,
                        event_id=event_id,
                        payload=payload,
                        status="pending",
                        attempt_count=0,
                        next_attempt_at=utcnow(),
                        last_error="",
                        created_at=utcnow(),
                        updated_at=utcnow(),
                    )
                )
                await session.flush()
            return
        except IntegrityError:
            if await _already_queued(session, endpoint_id, event_key):
                return
            event_id = new_id("whe")
            payload = {**payload, "id": event_id}
            logger.warning(
                "Webhook delivery insert collided; retrying with new ids (endpoint=%s, attempt=%d)",
                endpoint_id,
                attempt + 1,
            )
    logger.error(
        "Webhook delivery could not be queued (endpoint=%s, event_key=%s)", endpoint_id, event_key
    )


async def send_test(session: AsyncSession, organization_id: str, endpoint_id: str) -> WebhookDelivery:
    endpoint = await _endpoint(session, organization_id, endpoint_id)
    if not endpoint.enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "Endpoint is disabled")
    event_id = new_id("whe")
    payload = {
        "schema": SCHEMA,
        "id": event_id,
        "type": "webhook.test",
        "created_at": _iso(utcnow()),
        "data": {"note": "Saturn webhook test"},
    }
    row = WebhookDelivery(
        id=new_id("whd"),
        organization_id=organization_id,
        endpoint_id=endpoint.id,
        event_type="webhook.test",
        event_key=f"webhook.test:{event_id}",
        event_id=event_id,
        payload=payload,
        status="pending",
        attempt_count=0,
        next_attempt_at=utcnow(),
        last_error="",
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    session.add(row)
    await session.flush()
    await deliver_one(session, row, utcnow())
    await session.refresh(row, attribute_names=["attempts"])
    return row


async def list_deliveries(
    session: AsyncSession,
    organization_id: str,
    endpoint_id: str,
) -> list[WebhookDelivery]:
    await _endpoint(session, organization_id, endpoint_id)
    result = await session.scalars(
        select(WebhookDelivery)
        .options(selectinload(WebhookDelivery.attempts))
        .where(
            WebhookDelivery.organization_id == organization_id,
            WebhookDelivery.endpoint_id == endpoint_id,
        )
        .order_by(WebhookDelivery.created_at.desc())
        .limit(50)
    )
    return list(result.all())


async def retry_delivery(session: AsyncSession, organization_id: str, delivery_id: str) -> WebhookDelivery:
    row = await session.scalar(
        select(WebhookDelivery)
        .options(selectinload(WebhookDelivery.attempts))
        .where(WebhookDelivery.id == delivery_id, WebhookDelivery.organization_id == organization_id)
    )
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Webhook delivery not found")
    if row.status == "delivered":
        raise HTTPException(status.HTTP_409_CONFLICT, "Delivery already succeeded")
    row.status = "pending"
    row.attempt_count = 0
    row.next_attempt_at = utcnow()
    row.last_error = ""
    await deliver_one(session, row, utcnow())
    await session.refresh(row, attribute_names=["attempts"])
    return row


def _retryable(code: int | None) -> bool:
    if code is None:
        return True
    if code == 429 or code >= 500:
        return True
    return False


@dataclass
class _Job:
    row: WebhookDelivery
    url: str
    body: bytes
    headers: dict[str, str]
    secret: str


def _fair_pick(rows: list[WebhookDelivery], *, per_org: int, total: int) -> list[WebhookDelivery]:
    """Round-robin across organizations, oldest first within each, at most per_org from any one."""
    queues: dict[str, list[WebhookDelivery]] = {}
    for row in rows:
        queues.setdefault(row.organization_id, []).append(row)
    picked: list[WebhookDelivery] = []
    taken: dict[str, int] = {}
    while len(picked) < total:
        progressed = False
        for org_id, queue in queues.items():
            if not queue or taken.get(org_id, 0) >= per_org:
                continue
            picked.append(queue.pop(0))
            taken[org_id] = taken.get(org_id, 0) + 1
            progressed = True
            if len(picked) >= total:
                break
        if not progressed:
            break
    return picked


async def deliver_due(
    session: AsyncSession,
    now: datetime | None = None,
    *,
    organization_id: str | None = None,
) -> int:
    """Send due deliveries. With organization_id, only that organization's queue is touched."""
    moment = now or utcnow()
    scope = []
    if organization_id is not None:
        scope.append(WebhookDelivery.organization_id == organization_id)
    exhausted = list(
        await session.scalars(
            select(WebhookDelivery)
            .where(
                WebhookDelivery.status.in_(("pending", "failed")),
                WebhookDelivery.attempt_count >= max_attempts(),
                *scope,
            )
            .limit(SCAN_LIMIT)
        )
    )
    for row in exhausted:
        row.status = "dead"
        row.updated_at = moment
    # Take at most PER_ORG_LIMIT due rows from each organization, so one tenant's backlog
    # cannot fill the scan and starve everyone else.
    ranked = (
        select(
            WebhookDelivery.id.label("id"),
            func.row_number()
            .over(
                partition_by=WebhookDelivery.organization_id,
                order_by=(WebhookDelivery.next_attempt_at, WebhookDelivery.id),
            )
            .label("rank"),
        )
        .where(
            WebhookDelivery.status.in_(("pending", "failed")),
            WebhookDelivery.attempt_count < max_attempts(),
            WebhookDelivery.next_attempt_at <= moment,
            *scope,
        )
        .subquery()
    )
    rows = list(
        await session.scalars(
            select(WebhookDelivery)
            .where(
                WebhookDelivery.id.in_(select(ranked.c.id).where(ranked.c.rank <= PER_ORG_LIMIT))
            )
            .order_by(WebhookDelivery.next_attempt_at, WebhookDelivery.id)
            .limit(SCAN_LIMIT)
            # Several workers can run at once; each takes rows no other worker holds.
            .with_for_update(of=WebhookDelivery, skip_locked=True)
        )
    )
    # SQLite may hand back naive datetimes; keep the Python check as well.
    rows = [row for row in rows if (_as_utc(row.next_attempt_at) or moment) <= moment]
    picked = _fair_pick(rows, per_org=PER_ORG_LIMIT, total=BATCH_LIMIT)
    jobs: list[_Job] = []
    for row in picked:
        job = await _prepare(session, row, moment)
        if job is not None:
            jobs.append(job)
    await _claim(session, jobs, moment)
    gate = asyncio.Semaphore(CONCURRENCY)

    async def run(job: _Job) -> tuple[int | None, str]:
        async with gate:
            return await send_webhook(job.url, job.body, job.headers)

    results = await asyncio.gather(*(run(job) for job in jobs))
    for job, (code, error) in zip(jobs, results, strict=True):
        if await _still_there(session, job):
            await _record(session, job, moment, code, error)
    await session.flush()
    return len(picked)


async def deliver_one(session: AsyncSession, row: WebhookDelivery, now: datetime) -> None:
    job = await _prepare(session, row, now)
    if job is None:
        return
    await _claim(session, [job], now)
    code, error = await send_webhook(job.url, job.body, job.headers)
    if not await _still_there(session, job):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Webhook delivery not found")
    await _record(session, job, now, code, error)


async def _claim(session: AsyncSession, jobs: list[_Job], now: datetime) -> None:
    """Commit what was decided so far and release the rows before anything is sent.

    Sending used to happen inside the transaction that had locked the rows, so a slow receiver
    held row locks and a pooled connection for the whole request.
    """
    for job in jobs:
        job.row.next_attempt_at = now + timedelta(seconds=CLAIM_SECONDS)
        job.row.updated_at = now
    await session.commit()


async def _still_there(session: AsyncSession, job: _Job) -> bool:
    """Lock the row again to record the outcome. False when it was deleted while the request was out."""
    fresh = await session.get(WebhookDelivery, job.row.id, populate_existing=True, with_for_update=True)
    if fresh is None:
        return False
    job.row = fresh
    return True


async def _prepare(session: AsyncSession, row: WebhookDelivery, now: datetime) -> _Job | None:
    """Check the delivery and build the signed request. Returns None when it was settled here."""
    endpoint = await session.get(WebhookEndpoint, row.endpoint_id)
    if endpoint is None or endpoint.organization_id != row.organization_id:
        row.status = "dead"
        row.last_error = "endpoint missing"
        row.updated_at = now
        return None
    if not await _webhooks_allowed(session, row.organization_id):
        row.status = "dead"
        row.last_error = PRO_REQUIRED
        row.updated_at = now
        return None
    if not endpoint.enabled and row.event_type != "webhook.test":
        row.next_attempt_at = now + timedelta(seconds=disabled_delay_seconds())
        row.updated_at = now
        return None
    secret = ""
    try:
        # No lookup here. The send resolves the name once, off the event loop, and connects to
        # the address it checked; a name that does not resolve then counts as a failed attempt.
        require_webhook_shape(endpoint.url)
        secret = await get_secret(session, endpoint.secret_id, row.organization_id)
    except HTTPException:
        await _finish(session, row, now, None, "destination not allowed", secret, dead=True)
        return None
    except KeyUnavailable:
        # The key service did not answer. The secret itself is fine: wait, and do not count an attempt.
        row.next_attempt_at = now + timedelta(seconds=key_unavailable_delay_seconds())
        row.updated_at = now
        return None
    except Exception:
        await _finish(session, row, now, None, "signing secret unavailable", "", dead=True)
        return None
    if not secret:
        await _finish(session, row, now, None, "signing secret unavailable", "", dead=True)
        return None
    body = canonical_body(row.payload if isinstance(row.payload, dict) else {})
    timestamp = str(int(_as_utc(now).timestamp()))
    headers = signed_headers(secret, row.event_id, timestamp, body)
    return _Job(row=row, url=endpoint.url, body=body, headers=headers, secret=secret)


async def _record(
    session: AsyncSession,
    job: _Job,
    now: datetime,
    code: int | None,
    error: str,
) -> None:
    row = job.row
    if code is not None and 200 <= code < 300:
        row.status = "delivered"
        row.last_status_code = code
        row.last_error = ""
        row.attempt_count = int(row.attempt_count or 0) + 1
        row.updated_at = now
        session.add(
            WebhookAttempt(
                id=new_id("wha"),
                delivery_id=row.id,
                status_code=code,
                error="",
                created_at=now,
            )
        )
        await session.flush()
        return
    dead = not _retryable(code) or error == "destination not allowed"
    await _finish(
        session,
        row,
        now,
        code,
        error or (f"http {code}" if code else "delivery failed"),
        job.secret,
        dead=dead,
    )


async def _finish(
    session: AsyncSession,
    row: WebhookDelivery,
    now: datetime,
    code: int | None,
    error: str,
    secret: str,
    *,
    dead: bool,
) -> None:
    row.attempt_count = int(row.attempt_count or 0) + 1
    row.last_status_code = code
    row.last_error = _public_error(error, secret)
    row.updated_at = now
    if dead or row.attempt_count >= max_attempts():
        row.status = "dead"
    else:
        row.status = "failed"
        row.next_attempt_at = now + timedelta(seconds=backoff_seconds(row.attempt_count))
    session.add(
        WebhookAttempt(
            id=new_id("wha"),
            delivery_id=row.id,
            status_code=code,
            error=row.last_error,
            created_at=now,
        )
    )
    await session.flush()
