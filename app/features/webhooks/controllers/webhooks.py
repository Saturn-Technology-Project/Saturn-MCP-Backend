from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, Response, status
from pydantic import BaseModel, Field

from app.features.execution.approvals.services.expiration import save_window, window_minutes
from app.features.identity.auth.controllers.deps import ProPlan, SessionDep, TeamRead, TeamWrite
from app.features.webhooks.models.webhook import WebhookDelivery, WebhookEndpoint
from app.features.webhooks.services.webhook_service import (
    create_endpoint,
    deliver_due,
    list_deliveries,
    list_endpoints,
    retry_delivery,
    reveal_secret,
    rotate_secret,
    send_test,
    update_endpoint,
)

router = APIRouter(prefix="/org", tags=["webhooks"])


class WebhookCreate(BaseModel):
    url: str = Field(max_length=2000)
    events: list[Annotated[str, Field(max_length=64)]] = Field(
        default_factory=lambda: ["approval.granted", "approval.rejected", "approval.expired"],
        max_length=16,
    )


class WebhookUpdate(BaseModel):
    url: str | None = Field(default=None, max_length=2000)
    events: list[Annotated[str, Field(max_length=64)]] | None = Field(default=None, max_length=16)
    enabled: bool | None = None


class WebhookRead(BaseModel):
    id: str
    url: str
    events: list[str]
    enabled: bool
    has_secret: bool
    created_at: datetime
    updated_at: datetime


class WebhookCreated(WebhookRead):
    secret: str


class WebhookSecret(BaseModel):
    secret: str


class AttemptRead(BaseModel):
    id: str
    status_code: int | None = None
    error: str = ""
    created_at: datetime


class DeliveryRead(BaseModel):
    id: str
    event_type: str
    event_id: str
    status: str
    attempt_count: int
    last_status_code: int | None = None
    last_error: str = ""
    created_at: datetime
    updated_at: datetime
    attempts: list[AttemptRead] = []


class WindowRead(BaseModel):
    pending_ttl_minutes: int
    resubmit_ttl_minutes: int


class WindowUpdate(BaseModel):
    pending_ttl_minutes: int | None = None
    resubmit_ttl_minutes: int | None = None


class DispatchRead(BaseModel):
    processed: int


def _endpoint_read(row: WebhookEndpoint, secret: str | None = None) -> WebhookRead | WebhookCreated:
    payload = dict(
        id=row.id,
        url=row.url,
        events=list(row.events or []),
        enabled=bool(row.enabled),
        has_secret=bool(row.secret_id),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )
    if secret is None:
        return WebhookRead(**payload)
    return WebhookCreated(**payload, secret=secret)


def _delivery_read(row: WebhookDelivery) -> DeliveryRead:
    return DeliveryRead(
        id=row.id,
        event_type=row.event_type,
        event_id=row.event_id,
        status=row.status,
        attempt_count=int(row.attempt_count or 0),
        last_status_code=row.last_status_code,
        last_error=row.last_error or "",
        created_at=row.created_at,
        updated_at=row.updated_at,
        attempts=[
            AttemptRead(
                id=item.id,
                status_code=item.status_code,
                error=item.error or "",
                created_at=item.created_at,
            )
            for item in list(getattr(row, "attempts", None) or [])
        ],
    )


@router.get("/approval-window", response_model=WindowRead)
async def get_approval_window(session: SessionDep, member: TeamRead):
    pending, resubmit = await window_minutes(session, member.organization_id)
    return WindowRead(pending_ttl_minutes=pending, resubmit_ttl_minutes=resubmit)


@router.patch("/approval-window", response_model=WindowRead)
async def patch_approval_window(body: WindowUpdate, session: SessionDep, member: TeamWrite):
    row = await save_window(
        session,
        member.organization_id,
        pending_ttl_minutes=body.pending_ttl_minutes,
        resubmit_ttl_minutes=body.resubmit_ttl_minutes,
    )
    return WindowRead(
        pending_ttl_minutes=row.pending_ttl_minutes,
        resubmit_ttl_minutes=row.resubmit_ttl_minutes,
    )


@router.get("/webhooks", response_model=list[WebhookRead])
async def get_webhooks(session: SessionDep, member: TeamRead, _pro: ProPlan):
    rows = await list_endpoints(session, member.organization_id)
    return [_endpoint_read(row) for row in rows]


@router.post("/webhooks", response_model=WebhookCreated, status_code=201)
async def post_webhook(body: WebhookCreate, session: SessionDep, member: TeamWrite, _pro: ProPlan):
    row, secret = await create_endpoint(session, member.organization_id, url=body.url, events=body.events)
    created = _endpoint_read(row, secret)
    assert isinstance(created, WebhookCreated)
    return created


@router.patch("/webhooks/{endpoint_id}", response_model=WebhookRead)
async def patch_webhook(endpoint_id: str, body: WebhookUpdate, session: SessionDep, member: TeamWrite, _pro: ProPlan):
    row = await update_endpoint(
        session,
        member.organization_id,
        endpoint_id,
        url=body.url,
        events=body.events,
        enabled=body.enabled,
    )
    return _endpoint_read(row)


@router.get("/webhooks/{endpoint_id}/secret")
async def download_secret(endpoint_id: str, session: SessionDep, member: TeamWrite, _pro: ProPlan):
    secret = await reveal_secret(session, member.organization_id, endpoint_id)
    filename = f"saturn-webhook-{endpoint_id}.txt"
    return Response(
        content=f"{secret}\n",
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/webhooks/{endpoint_id}/rotate", response_model=WebhookSecret)
async def post_rotate(endpoint_id: str, session: SessionDep, member: TeamWrite, _pro: ProPlan):
    secret = await rotate_secret(session, member.organization_id, endpoint_id)
    return WebhookSecret(secret=secret)


@router.post("/webhooks/{endpoint_id}/test", response_model=DeliveryRead)
async def post_test(endpoint_id: str, session: SessionDep, member: TeamWrite, _pro: ProPlan):
    from app.core.rate_limit import allow

    # A test is a signed POST to an address the organization chose, retried like any delivery.
    # Without a limit it is a way to send traffic at someone else's server.
    if not await allow(f"webhook-test:{member.organization_id}", limit=30, window=600):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many test deliveries", headers={"Retry-After": "600"})
    row = await send_test(session, member.organization_id, endpoint_id)
    return _delivery_read(row)


@router.get("/webhooks/{endpoint_id}/deliveries", response_model=list[DeliveryRead])
async def get_deliveries(endpoint_id: str, session: SessionDep, member: TeamRead, _pro: ProPlan):
    rows = await list_deliveries(session, member.organization_id, endpoint_id)
    return [_delivery_read(row) for row in rows]


@router.post("/webhooks/deliveries/{delivery_id}/retry", response_model=DeliveryRead)
async def post_retry(delivery_id: str, session: SessionDep, member: TeamWrite, _pro: ProPlan):
    from app.core.rate_limit import allow

    # Each retry restarts the attempt count, so it is limited rather than repeatable at will.
    if not await allow(f"webhook-retry:{member.organization_id}", limit=30, window=600):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many retries", headers={"Retry-After": "600"})
    row = await retry_delivery(session, member.organization_id, delivery_id)
    return _delivery_read(row)


@router.post("/webhooks/dispatch", response_model=DispatchRead)
async def post_dispatch(session: SessionDep, member: TeamWrite, _pro: ProPlan):
    # Only the caller's own queue; the global queue belongs to the background worker.
    processed = await deliver_due(session, organization_id=member.organization_id)
    return DispatchRead(processed=processed)
