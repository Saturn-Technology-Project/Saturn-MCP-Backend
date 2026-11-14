"""What GET /status reports: whether the API can reach what it depends on.

GET /health is a different question. It answers "is this process serving requests" and
touches nothing else, so a probe never fails, or restarts the service, because a dependency
is slow.

The worker also takes a sample once a minute and counts it into that day's row, which is where
GET /status/history gets the uptime of the last ninety days.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import date, timedelta
from typing import Any

import httpx
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ids import utcnow
from app.core.public_origin import configured_origin
from app.shared.models.status_day import StatusDay

logger = logging.getLogger(__name__)

# One slow dependency must not hold the report, or the request, for long.
CHECK_SECONDS = 2.0
# The report is public and each one costs a database round trip. Reusing it for a few seconds
# keeps a burst of requests from becoming a burst of queries.
CACHE_SECONDS = 5.0

# How often the worker samples, how far back the page looks, and how long a day's row is kept.
SAMPLE_SECONDS = 60.0
HISTORY_DAYS = 90
KEEP_DAYS = 400
NAMES = {"api": "API", "database": "Database", "redis": "Redis"}

_cached: tuple[float, dict[str, Any]] | None = None
_lock = asyncio.Lock()
_history: dict[int, tuple[float, dict[str, Any]]] = {}
# Samples not written yet, by (day, service): [checks, failures]. A sample taken while the
# database is down cannot be stored then, and it is exactly the one that must not be lost.
_pending: dict[tuple[date, str], list[int]] = {}
_record_lock = asyncio.Lock()
_pruned_on: date | None = None


async def _database() -> str:
    from app.db.database import engine

    try:
        async with asyncio.timeout(CHECK_SECONDS):
            async with engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
    except Exception:
        return "down"
    return "operational"


async def _redis() -> str | None:
    """None when this deployment keeps limits and sessions in the process and has no Redis."""
    from app.core import rate_limit

    if not rate_limit._use_redis():
        return None
    try:
        async with asyncio.timeout(CHECK_SECONDS):
            await rate_limit._redis_client().ping()
    except Exception:
        return "down"
    return "operational"


async def _check() -> dict[str, Any]:
    database, redis = await asyncio.gather(_database(), _redis())
    services = [
        {"id": "api", "name": NAMES["api"], "status": "operational"},
        {"id": "database", "name": NAMES["database"], "status": database},
    ]
    if redis is not None:
        # Sign-in limits and agent sessions live here; without it sign-in and /mcp refuse.
        services.append({"id": "redis", "name": NAMES["redis"], "status": redis})
    healthy = all(item["status"] == "operational" for item in services)
    return {
        "status": "ok" if healthy else "error",
        "checked_at": utcnow().isoformat(),
        "services": services,
    }


async def report() -> dict[str, Any]:
    global _cached
    async with _lock:
        now = time.monotonic()
        if _cached is not None and now - _cached[0] < CACHE_SECONDS:
            return _cached[1]
        result = await _check()
        _cached = (time.monotonic(), result)
        return result


async def _api_from_outside() -> str:
    """Whether the API answers at its public address, asked the way a visitor would.

    The worker is a separate service, so it can see the API being down. Without a public
    address (local development) the worker runs inside the API, which is then up by definition.
    """
    origin = configured_origin()
    if not origin:
        return "operational"
    try:
        async with httpx.AsyncClient(timeout=CHECK_SECONDS * 2, follow_redirects=False, trust_env=False) as client:
            answer = await client.get(f"{origin}/health")
    except httpx.HTTPError:
        return "down"
    return "operational" if answer.status_code == 200 else "down"


async def sample() -> dict[str, str]:
    """A fresh reading of every service this deployment has. Never the cached report."""
    api, database, redis = await asyncio.gather(_api_from_outside(), _database(), _redis())
    found = {"api": api, "database": database}
    if redis is not None:
        found["redis"] = redis
    return found


def _count(found: dict[str, str], day: date) -> None:
    for service_id, state in found.items():
        slot = _pending.setdefault((day, service_id), [0, 0])
        slot[0] += 1
        slot[1] += 0 if state == "operational" else 1


async def _store(session: AsyncSession, day: date, service_id: str, checks: int, failures: int) -> None:
    added = update(StatusDay).where(StatusDay.day == day, StatusDay.service_id == service_id).values(
        checks=StatusDay.checks + checks, failures=StatusDay.failures + failures
    )
    if (await session.execute(added)).rowcount:
        return
    try:
        async with session.begin_nested():
            session.add(StatusDay(day=day, service_id=service_id, checks=checks, failures=failures))
    except IntegrityError:
        # Another worker made the row between the two statements.
        await session.execute(added)


async def record(session: AsyncSession, found: dict[str, str] | None = None) -> None:
    """Count one sample into today's rows. What cannot be written now is kept and written later."""
    if found is None:
        found = await sample()
    # One at a time: the samples waiting to be written are shared, and two writers working
    # from the same list would each write the other's sample as well as their own.
    async with _record_lock:
        await _record(session, found)


async def _record(session: AsyncSession, found: dict[str, str]) -> None:
    global _pruned_on
    today = utcnow().date()
    _count(found, today)
    waiting = {key: (checks, failures) for key, (checks, failures) in _pending.items()}
    try:
        for (day, service_id), (checks, failures) in waiting.items():
            await _store(session, day, service_id, checks, failures)
        if _pruned_on != today:
            await session.execute(delete(StatusDay).where(StatusDay.day < today - timedelta(days=KEEP_DAYS)))
        await session.commit()
    except Exception:
        await session.rollback()
        # Bounded: one entry per service per day, and only the retained days are worth keeping.
        for key in [key for key in _pending if key[0] < today - timedelta(days=KEEP_DAYS)]:
            del _pending[key]
        logger.warning("status sample kept in memory: the database did not take it")
        return
    _pruned_on = today
    for key in waiting:
        del _pending[key]


def _percent(checks: int, failures: int) -> float | None:
    if checks <= 0:
        return None
    # Three decimals: 99.999 must not be shown as 100.
    return round(100 * (checks - failures) / checks, 3)


async def history(session: AsyncSession, days: int = HISTORY_DAYS) -> dict[str, Any]:
    """Per service, the days that have samples within the window, oldest first, and the uptime over them."""
    now = time.monotonic()
    cached = _history.get(days)
    if cached is not None and now - cached[0] < SAMPLE_SECONDS:
        return cached[1]
    today = utcnow().date()
    first = today - timedelta(days=days - 1)
    rows = (
        await session.execute(
            select(StatusDay.day, StatusDay.service_id, StatusDay.checks, StatusDay.failures)
            .where(StatusDay.day >= first, StatusDay.day <= today)
            .order_by(StatusDay.day)
        )
    ).all()
    by_service: dict[str, list[Any]] = {}
    for row in rows:
        by_service.setdefault(row.service_id, []).append(row)
    services = []
    # Known services in a fixed order; anything else recorded comes after, by id.
    for service_id in [*[item for item in NAMES if item in by_service], *sorted(set(by_service) - set(NAMES))]:
        listed = by_service[service_id]
        services.append(
            {
                "id": service_id,
                "name": NAMES.get(service_id, service_id),
                "uptime": _percent(sum(row.checks for row in listed), sum(row.failures for row in listed)),
                "days": [
                    {
                        "day": row.day.isoformat(),
                        "uptime": _percent(row.checks, row.failures),
                        "checks": row.checks,
                        "failures": row.failures,
                    }
                    for row in listed
                ],
            }
        )
    result = {"days": days, "from": first.isoformat(), "to": today.isoformat(), "services": services}
    _history[days] = (now, result)
    return result


def reset() -> None:
    global _cached, _lock, _pruned_on, _record_lock
    _cached = None
    _history.clear()
    _pending.clear()
    _pruned_on = None
    # A lock belongs to the event loop it was first used on; tests use a new loop each time.
    _lock = asyncio.Lock()
    _record_lock = asyncio.Lock()
