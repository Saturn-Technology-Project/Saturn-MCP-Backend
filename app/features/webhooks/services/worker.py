from __future__ import annotations

import asyncio
import logging

from app.db.database import SessionLocal
from app.features.execution.approvals.services.expiration import expire_due
from app.features.webhooks.services.webhook_service import deliver_due

logger = logging.getLogger(__name__)

POLL_SECONDS = 5


async def run_webhook_worker() -> None:
    while True:
        try:
            async with SessionLocal() as session:
                await expire_due(session)
                await deliver_due(session)
                await session.commit()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Webhook worker failed")
        await asyncio.sleep(POLL_SECONDS)


async def run_status_sampler() -> None:
    """Once a minute, check each service and count the result into the day's uptime."""
    from app.core import status

    while True:
        try:
            found = await status.sample()
            async with SessionLocal() as session:
                await status.record(session, found)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Status sampler failed")
        await asyncio.sleep(status.SAMPLE_SECONDS)
