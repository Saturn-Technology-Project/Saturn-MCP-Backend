"""Regression tests for webhook fairness, scoping, connection pinning and enqueue safety."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.core.ids import new_id as real_new_id
from app.core.ids import utcnow
from app.db.database import get_session
from app.main import app
from app.models import Organization
from app.features.webhooks.models.webhook import WebhookDelivery, WebhookEndpoint
from app.features.webhooks.services import webhook_service
from app.features.webhooks.services.destinations import pin_webhook_url, require_webhook_url


async def _with_session(fn):
    gen = app.dependency_overrides[get_session]()
    session = await gen.__anext__()
    try:
        result = await fn(session)
        await session.commit()
        return result
    finally:
        await gen.aclose()


async def _stage_org(session, org_id: str, deliveries: int) -> None:
    session.add(Organization(id=org_id, name=org_id, plan="team", kind="organization"))
    await session.flush()
    session.add(
        WebhookEndpoint(
            id=f"wh_{org_id}",
            organization_id=org_id,
            url=f"https://{org_id}.example.com/hook",
            events=["approval.granted"],
            enabled=True,
            secret_id=f"whsec_{org_id}",
        )
    )
    await session.flush()
    for index in range(deliveries):
        session.add(
            WebhookDelivery(
                id=f"whd_{org_id}_{index}",
                organization_id=org_id,
                endpoint_id=f"wh_{org_id}",
                event_type="approval.granted",
                event_key=f"approval.granted:{org_id}:{index}",
                event_id=f"whe_{org_id}_{index}",
                payload={"id": f"whe_{org_id}_{index}"},
                status="pending",
                attempt_count=0,
                next_attempt_at=utcnow(),
                last_error="",
            )
        )
    await session.flush()


@pytest.fixture
def fake_secret(monkeypatch):
    async def secret(*_args, **_kwargs):
        return "webhook-secret"

    monkeypatch.setattr("app.features.webhooks.services.webhook_service.get_secret", secret)


# M-26


async def test_endpoints_per_org_are_capped(client):
    for index in range(webhook_service.MAX_ENDPOINTS_PER_ORG):
        created = await client.post(
            "/org/webhooks",
            json={"url": f"https://hooks.example.com/{index}", "events": ["approval.granted"]},
        )
        assert created.status_code == 201, created.text
    over = await client.post(
        "/org/webhooks", json={"url": "https://hooks.example.com/over", "events": ["approval.granted"]}
    )
    assert over.status_code == 409


def test_fair_pick_round_robins_and_caps_each_org():
    class Row:
        def __init__(self, org, n):
            self.organization_id = org
            self.n = n

    rows = [Row("a", n) for n in range(10)] + [Row("b", 0), Row("c", 0), Row("c", 1)]
    picked = webhook_service._fair_pick(rows, per_org=3, total=6)
    assert [(row.organization_id, row.n) for row in picked] == [
        ("a", 0), ("b", 0), ("c", 0), ("a", 1), ("c", 1), ("a", 2)
    ]


async def test_one_slow_tenant_cannot_starve_others(client, monkeypatch, fake_secret):
    async def stage(session):
        await _stage_org(session, "org_noisy", 12)
        await _stage_org(session, "org_quiet", 1)

    await _with_session(stage)
    in_flight = 0
    peak = 0
    seen: list[str] = []

    async def slow(url, body, headers):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.05)
        in_flight -= 1
        seen.append(url)
        return 200, ""

    monkeypatch.setattr("app.features.webhooks.services.webhook_service.send_webhook", slow)
    processed = await _with_session(lambda session: webhook_service.deliver_due(session))
    assert processed == webhook_service.PER_ORG_LIMIT + 1
    assert sum("org_quiet" in url for url in seen) == 1
    assert sum("org_noisy" in url for url in seen) == webhook_service.PER_ORG_LIMIT
    assert peak > 1


# L-24


async def test_dispatch_only_touches_the_callers_org(client, monkeypatch, fake_secret):
    await _with_session(lambda session: _stage_org(session, "org_foreign", 1))
    seen: list[str] = []

    async def record(url, body, headers):
        seen.append(url)
        return 200, ""

    monkeypatch.setattr("app.features.webhooks.services.webhook_service.send_webhook", record)
    dispatched = await client.post("/org/webhooks/dispatch")
    assert dispatched.status_code == 200, dispatched.text
    assert seen == []

    async def status(session):
        row = await session.get(WebhookDelivery, "whd_org_foreign_0")
        return row.status

    assert await _with_session(status) == "pending"


# L-25


def test_webhooks_only_use_port_443():
    assert require_webhook_url("https://hooks.example.com:443/x") == "https://hooks.example.com:443/x"
    for url in ("https://hooks.example.com:8443/x", "https://hooks.example.com:22/x", "https://1.1.1.1:6379/"):
        with pytest.raises(HTTPException) as caught:
            require_webhook_url(url)
        assert caught.value.status_code == 400


def test_pinned_url_connects_to_the_checked_address():
    target = pin_webhook_url("https://Hooks.Example.com/path?q=1")
    assert target.url == "https://1.1.1.1/path?q=1"
    assert target.host == "hooks.example.com"
    assert target.address == "1.1.1.1"


class _Endless(httpx.AsyncByteStream):
    def __init__(self):
        self.sent = 0

    async def __aiter__(self):
        for _ in range(10_000):
            self.sent += 1024
            yield b"x" * 1024

    async def aclose(self):
        return None


async def test_send_pins_ip_keeps_hostname_and_caps_the_body(monkeypatch):
    seen: list[httpx.Request] = []
    stream = _Endless()

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, stream=stream)

    real = httpx.AsyncClient

    def client(**kwargs):
        return real(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client)
    code, error = await webhook_service.send_webhook(
        "https://hooks.example.com/saturn", b"{}", {"Content-Type": "application/json"}
    )
    assert (code, error) == (200, "")
    request = seen[0]
    assert request.url.host == "1.1.1.1"
    assert request.headers["host"] == "hooks.example.com"
    assert request.extensions["sni_hostname"] == "hooks.example.com"
    assert stream.sent <= webhook_service.MAX_RESPONSE_BYTES + 1024


async def test_send_refuses_a_name_that_now_resolves_inside(monkeypatch):
    calls: list[httpx.Request] = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200)

    real = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr(
        "app.features.mcp.servers.services.mcp_endpoint.addresses_for", lambda _host, _port: ["10.0.0.5"]
    )
    code, error = await webhook_service.send_webhook("https://hooks.example.com/saturn", b"{}", {})
    assert (code, error) == (None, "destination not allowed")
    assert calls == []


# M-24


async def test_enqueue_retries_an_id_collision_and_only_drops_true_duplicates(client):
    await _with_session(lambda session: _stage_org(session, "org_enqueue", 1))
    calls = {"n": 0}

    def colliding(prefix):
        if prefix == "whd" and calls["n"] == 0:
            calls["n"] += 1
            return "whd_org_enqueue_0"
        return real_new_id(prefix)

    async def enqueue(session):
        webhook_service.new_id = colliding
        try:
            await webhook_service._enqueue(
                session, "org_enqueue", "wh_org_enqueue", "approval.granted",
                "approval.granted:fresh", "whe_fresh", {"id": "whe_fresh"},
            )
        finally:
            webhook_service.new_id = real_new_id

    await _with_session(enqueue)
    assert calls["n"] == 1

    async def keys(session):
        rows = await session.scalars(
            select(WebhookDelivery.event_key).where(WebhookDelivery.endpoint_id == "wh_org_enqueue")
        )
        return sorted(rows.all())

    assert await _with_session(keys) == ["approval.granted:fresh", "approval.granted:org_enqueue:0"]

    async def duplicate(session):
        await webhook_service._enqueue(
            session, "org_enqueue", "wh_org_enqueue", "approval.granted",
            "approval.granted:fresh", real_new_id("whe"), {},
        )

    await _with_session(duplicate)
    assert await _with_session(keys) == ["approval.granted:fresh", "approval.granted:org_enqueue:0"]


# Sending must not hold the rows: a slow receiver used to keep row locks and a transaction open.


async def test_nothing_is_locked_or_uncommitted_while_a_webhook_is_out(client, monkeypatch, fake_secret):
    await _with_session(lambda session: _stage_org(session, "org_slow", 2))
    during: list[tuple[bool, list[bool]]] = []
    holder = {}

    async def observe(_url, _body, _headers):
        # A second session sees the claim, so it is committed, and the sending one holds no transaction.
        async def claimed(other):
            rows = list(await other.scalars(select(WebhookDelivery).where(WebhookDelivery.organization_id == "org_slow")))
            return [webhook_service._as_utc(row.next_attempt_at) > utcnow() and row.status == "pending" for row in rows]

        during.append((holder["session"].in_transaction(), await _with_session(claimed)))
        return 200, ""

    monkeypatch.setattr("app.features.webhooks.services.webhook_service.send_webhook", observe)

    async def deliver(session):
        holder["session"] = session
        return await webhook_service.deliver_due(session)

    assert await _with_session(deliver) == 2
    assert during == [(False, [True, True]), (False, [True, True])]

    async def settled(session):
        rows = list(await session.scalars(select(WebhookDelivery).where(WebhookDelivery.organization_id == "org_slow")))
        return sorted((row.status, row.attempt_count) for row in rows)

    assert await _with_session(settled) == [("delivered", 1), ("delivered", 1)]


async def test_a_delivery_deleted_while_it_is_out_does_not_break_the_batch(client, monkeypatch, fake_secret):
    async def stage(session):
        await _stage_org(session, "org_gone", 1)
        await _stage_org(session, "org_stays", 1)

    await _with_session(stage)

    async def send(url, _body, _headers):
        if "org_gone" in url:

            async def remove(other):
                await other.delete(await other.get(WebhookDelivery, "whd_org_gone_0"))

            await _with_session(remove)
        return 200, ""

    monkeypatch.setattr("app.features.webhooks.services.webhook_service.send_webhook", send)
    assert await _with_session(lambda session: webhook_service.deliver_due(session)) == 2

    async def left(session):
        rows = list(await session.scalars(select(WebhookDelivery).where(WebhookDelivery.organization_id.in_(("org_gone", "org_stays")))))
        return [(row.id, row.status) for row in rows]

    assert await _with_session(left) == [("whd_org_stays_0", "delivered")]


async def test_a_key_service_outage_postpones_a_delivery_instead_of_killing_it(client, monkeypatch):
    from app.features.credentials.vault.services.pq_crypto import KeyUnavailable

    await _with_session(lambda session: _stage_org(session, "org_outage", 1))

    async def outage(*_args, **_kwargs):
        raise KeyUnavailable()

    sent: list[str] = []

    async def send(url, _body, _headers):
        sent.append(url)
        return 200, ""

    monkeypatch.setattr("app.features.webhooks.services.webhook_service.get_secret", outage)
    monkeypatch.setattr("app.features.webhooks.services.webhook_service.send_webhook", send)
    await _with_session(lambda session: webhook_service.deliver_due(session))

    async def state(session):
        row = await session.get(WebhookDelivery, "whd_org_outage_0")
        return row.status, row.attempt_count, webhook_service._as_utc(row.next_attempt_at) > utcnow()

    assert await _with_session(state) == ("pending", 0, True)
    assert sent == []


async def test_a_key_service_outage_answers_503_not_reconnect(client, monkeypatch):
    from app.features.credentials.vault.services import pq_crypto

    created = await client.post("/org/webhooks", json={"url": "https://hooks.example.com/a", "events": ["approval.granted"]})
    assert created.status_code == 201, created.text

    def down(_data):
        raise ConnectionError("kms did not answer")

    monkeypatch.setattr(pq_crypto, "_mac", down)
    monkeypatch.setattr(pq_crypto, "_keys", {})
    answer = await client.get(f"/org/webhooks/{created.json()['id']}/secret")
    monkeypatch.undo()
    assert answer.status_code == 503, answer.text
    assert answer.headers["retry-after"] == "30"
