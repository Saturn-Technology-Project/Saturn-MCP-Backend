import asyncio
import logging
import os
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import get_settings
from app.core.body_limit import BodyLimitMiddleware
from app.core.http_security import HttpSecurityMiddleware
from app.core.logs import RequestLogMiddleware, configure_logging
from app.core.origin_auth import OriginAuthMiddleware
from app.core import status as service_status
from app.features.identity.auth.controllers.deps import SessionDep
from app.features.agent.agents.routes import router as agents_router
from app.features.billing.payments.routes import router as payments_router
from app.features.credentials.vault.services.pq_crypto import KeyUnavailable
from app.features.credentials.vault.routes import router as credentials_router
from app.features.execution.activity.routes import router as activity_router
from app.features.execution.activity.controllers.payload_keys import router as payload_keys_router
from app.features.execution.approvals.controllers.approval_policies import router as approval_policies_router
from app.features.execution.approvals.routes import router as approvals_router
from app.features.execution.runs.routes import router as runs_router
from app.features.identity.auth.routes import router as auth_router
from app.features.identity.oauth.routes import router as oauth_router
from app.features.mcp.saturn.routes import router as saturn_mcp_router
from app.features.mcp.servers.routes import router as mcp_servers_router
from app.features.organization.org.controllers.groups import router as groups_router
from app.features.organization.org.routes import router as org_router
from app.features.webhooks.controllers.webhooks import router as webhooks_router
from app.features.platform.admin.routes import router as admin_router
from app.features.policy.policies.routes import router as policies_router
from app.features.tooling.tool_sets.routes import router as tool_sets_router
from app.features.tooling.tools.routes import router as tools_router
from app.db.database import SessionLocal, engine
from app.db.seed import seed_if_empty
from app.models import *  # noqa: F401,F403

settings = get_settings()
configure_logging()
_logger = logging.getLogger(__name__)


def _cors_origins() -> list[str]:
    raw = (settings.cors_origins or "").strip()
    if not raw:
        # On Cloud Run the setting keeps https origins only. If that leaves nothing, trust
        # nothing: falling back to localhost would trust any page a user runs on their own machine.
        if os.environ.get("K_SERVICE", "").strip():
            return []
        return ["http://localhost:3000", "http://localhost:3001"]
    if raw == "*":
        return ["*"]
    return [item.strip() for item in raw.split(",") if item.strip()]


def _sqlite() -> bool:
    return settings.database_url.startswith("sqlite")


async def _report_agents_without_policy() -> None:
    from app.features.policy.policies.services.default_policy import log_agents_without_policy

    try:
        async with SessionLocal() as session:
            await log_agents_without_policy(session)
    except asyncio.CancelledError:
        raise
    except Exception:
        _logger.exception("could not list agents without a policy")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    from app.features.credentials.vault.services.pq_crypto import require_root

    require_root()
    from app.features.mcp.saturn.services.mcp_sessions import mcp_sessions

    await mcp_sessions.start()
    worker = report = sampler = None
    try:
        if not settings.skip_db_bootstrap:
            # Postgres schema is owned by Alembic (`alembic upgrade head` in Docker).
            # create_all races with those migrations and crashes on existing tables.
            if _sqlite():
                from app.db.database import Base

                async with engine.begin() as connection:
                    await connection.run_sync(Base.metadata.create_all)
            async with SessionLocal() as session:
                from app.features.identity.auth.services.throttle import purge_expired

                await purge_expired(session)
                await seed_if_empty(session)
                await session.commit()
            # A log line only. It runs beside the first requests instead of holding up the start.
            report = asyncio.create_task(_report_agents_without_policy())
        if settings.saturn_embed_worker and not settings.skip_db_bootstrap:
            from app.features.webhooks.services.worker import run_status_sampler, run_webhook_worker

            worker = asyncio.create_task(run_webhook_worker())
            sampler = asyncio.create_task(run_status_sampler())
        yield
    finally:
        for task in (worker, report, sampler):
            if task is not None:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
        await mcp_sessions.stop()
        from app.features.mcp.servers.services.mcp_remote import close_clients

        await close_clients()
        await engine.dispose()


app = FastAPI(
    title="Saturn Backend",
    version="0.1.0",
    description="Saturn MCP gateway and team permissions",
    lifespan=lifespan,
)

_origins = _cors_origins()
# Added first, so it is the innermost layer: it runs after the origin check, the security
# headers and CORS, and its 413 answers carry their headers.
app.add_middleware(BodyLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials="*" not in _origins,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(HttpSecurityMiddleware)
app.add_middleware(OriginAuthMiddleware)
# Added last, so it is the outermost layer: every request gets an id and a log line,
# including the ones the origin check refuses.
app.add_middleware(RequestLogMiddleware)


@app.exception_handler(KeyUnavailable)
async def key_unavailable(_request: Request, _exc: KeyUnavailable):
    # An outage of the key service, not a fault in the stored secret: the same request works later.
    return JSONResponse(
        status_code=503,
        content={"detail": "Temporarily unavailable. Try again shortly."},
        headers={"Retry-After": "30"},
    )


@app.exception_handler(Exception)
async def unhandled_error(_request: Request, exc: Exception):
    # RequestLogMiddleware answers and logs unexpected errors. This stays as the last resort for
    # anything raised outside it.
    if isinstance(exc, (HTTPException, StarletteHTTPException)):
        raise exc
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(org_router)
app.include_router(webhooks_router)
app.include_router(groups_router)
app.include_router(approval_policies_router)
app.include_router(agents_router)
app.include_router(credentials_router)
app.include_router(mcp_servers_router)
app.include_router(oauth_router)
app.include_router(tool_sets_router)
app.include_router(saturn_mcp_router)
app.include_router(runs_router)
app.include_router(tools_router)
app.include_router(policies_router)
app.include_router(approvals_router)
app.include_router(payments_router)
app.include_router(activity_router)
app.include_router(payload_keys_router)


@app.get("/")
async def root():
    return {"status": "ok"}


@app.get("/health")
@app.get("/healthz", include_in_schema=False)
async def health():
    """Whether this process is serving requests. Nothing else is checked, by design.

    Load balancers and uptime monitors call this, without the origin secret. Looking at the
    database here would report an outage of the database as an outage of the API, and a
    platform that restarts unhealthy instances would restart them for it. GET /status is where
    dependencies are reported.

    /healthz is the older name. Cloud Run keeps some paths ending in "z" for itself and never
    passes that one on, so it only ever worked locally.
    """
    return {"status": "ok"}


@app.get("/status")
async def status():
    """Which parts of the service are working. Always 200: the answer is in the body."""
    return await service_status.report()


@app.get("/status/history")
async def status_history(session: SessionDep, days: int = Query(service_status.HISTORY_DAYS, ge=1, le=service_status.HISTORY_DAYS)):
    """Uptime per service and day, from the samples the worker takes every minute."""
    return await service_status.history(session, days)
