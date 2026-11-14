import hashlib
import hmac
import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

# Reachable without the origin secret, so a probe can tell the service is up. Each answers
# only {"status": "ok"}. Everything else, GET /status included, needs the secret.
EXEMPT_PATHS = {"/health", "/healthz"}
DEFAULT_HEADER = "X-Saturn-Origin-Auth"


def request_path(request: Request) -> str:
    """The routed path. request.url is rebuilt from the Host header, which a client controls."""
    return request.scope.get("path") or "/"


def origin_allowed(path: str, headers) -> bool:
    if path in EXEMPT_PATHS:
        return True
    expected = os.environ.get("ORIGIN_AUTH_SECRET", "")
    if not expected:
        # Local and tests leave the secret unset. Cloud Run must fail closed.
        return not os.environ.get("K_SERVICE")
    name = os.environ.get("ORIGIN_AUTH_HEADER", DEFAULT_HEADER)
    presented = hashlib.sha256(headers.get(name, "").encode()).digest()
    # During a rotation the previous secret is still accepted, so Cloudflare and Cloud Run
    # can be updated one after the other without a window of 403s.
    accepted = [expected, os.environ.get("ORIGIN_AUTH_SECRET_PREVIOUS", "")]
    matches = [hmac.compare_digest(presented, hashlib.sha256(value.encode()).digest()) for value in accepted if value]
    return any(matches)


class OriginAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not origin_allowed(request_path(request), request.headers):
            return JSONResponse(status_code=403, content={"detail": "Forbidden"})
        return await call_next(request)
