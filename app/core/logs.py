"""Structured logs and one line per request.

Nothing configured logging before, so everything below WARNING was dropped and nothing tied
a log line to the request that caused it. On Cloud Run each line is one JSON object with the
fields Cloud Logging understands (severity, message, trace). Elsewhere it is plain text.

The request line carries the routed path only, never the query string: OAuth callbacks and
authorize requests put codes and state values there.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import sys
import time
from contextvars import ContextVar
from datetime import datetime, timezone

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

request_id_var: ContextVar[str] = ContextVar("request_id", default="")
_trace_var: ContextVar[str] = ContextVar("trace", default="")

REQUEST_ID_HEADER = "X-Request-Id"
_QUIET_PATHS = frozenset({"/healthz", "/health", "/status", "/status/history", "/"})
_requests = logging.getLogger("saturn.request")
_errors = logging.getLogger("saturn.error")

# Attributes every LogRecord has. Anything else was passed as extra= and belongs in the output.
# color_message is uvicorn's copy of the message with terminal colour codes.
_STANDARD = frozenset(vars(logging.LogRecord("", 0, "", 0, "", (), None))) | {"message", "asctime", "taskName", "color_message"}


def current_request_id() -> str:
    return request_id_var.get()


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict = {
            "severity": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "time": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
        }
        request_id = request_id_var.get()
        if request_id:
            entry["request_id"] = request_id
        trace = _trace_var.get()
        if trace:
            entry["logging.googleapis.com/trace"] = trace
        for key, value in vars(record).items():
            if key not in _STANDARD and not key.startswith("_"):
                entry[key] = value
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str, ensure_ascii=False)


class TextFormatter(logging.Formatter):
    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)s %(name)s %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        line = super().format(record)
        request_id = request_id_var.get()
        return f"{line} request_id={request_id}" if request_id else line


def configure_logging() -> None:
    """Send every logger to stdout in one format. Safe to call more than once."""
    level_name = os.environ.get("LOG_LEVEL", "INFO").strip().upper()
    level = logging.getLevelName(level_name) if level_name in logging._nameToLevel else logging.INFO
    style = os.environ.get("LOG_FORMAT", "").strip().lower()
    if style not in {"json", "text"}:
        style = "json" if os.environ.get("K_SERVICE", "").strip() else "text"
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if style == "json" else TextFormatter())
    root = logging.getLogger()
    for existing in list(root.handlers):
        if getattr(existing, "_saturn", False):
            root.removeHandler(existing)
    handler._saturn = True  # type: ignore[attr-defined]
    root.addHandler(handler)
    root.setLevel(level)
    # uvicorn installs its own handlers; route its loggers through ours instead of twice.
    for name in ("uvicorn", "uvicorn.error"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True
    # Its access log repeats the request line with the query string included.
    access = logging.getLogger("uvicorn.access")
    access.handlers.clear()
    access.propagate = False
    # One line per upstream request at INFO, with full URLs. Keep warnings only.
    logging.getLogger("httpx").setLevel(max(level, logging.WARNING))
    logging.getLogger("httpcore").setLevel(max(level, logging.WARNING))


def _trace(scope: Scope) -> str:
    project = os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip()
    if not project:
        return ""
    for key, value in scope.get("headers") or []:
        if key == b"x-cloud-trace-context":
            trace_id = value.decode("latin-1").split("/", 1)[0].strip()
            if trace_id and all(char in "0123456789abcdefABCDEF" for char in trace_id):
                return f"projects/{project}/traces/{trace_id}"
    return ""


async def _internal_error(scope: Scope, send: Send, request_id: str) -> None:
    """The caller gets no detail; the id lets their report be matched to the log line."""
    from app.core.http_security import apply_security_headers

    body = json.dumps({"detail": "Internal server error", "request_id": request_id}).encode()
    headers = MutableHeaders()
    headers["content-type"] = "application/json"
    headers["content-length"] = str(len(body))
    headers[REQUEST_ID_HEADER] = request_id
    apply_security_headers(headers, scope, scope.get("path") or "")
    await send({"type": "http.response.start", "status": 500, "headers": headers.raw})
    await send({"type": "http.response.body", "body": body})


class RequestLogMiddleware:
    """Give each request an id, return it in a header, and log how the request ended."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        # Always generated here. A caller-chosen id could forge or collide with another request's.
        request_id = secrets.token_hex(8)
        id_token = request_id_var.set(request_id)
        trace_token = _trace_var.set(_trace(scope))
        started = time.perf_counter()
        status_code = 0

        async def send_with_id(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
                MutableHeaders(raw=message["headers"])[REQUEST_ID_HEADER] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        except Exception as exc:
            # Handled here rather than by the app's catch-all handler: that one runs outside
            # every middleware, after this request's id is gone and without the security headers.
            _errors.error(
                "Unhandled error on %s %s",
                scope.get("method", ""),
                scope.get("path") or "",
                exc_info=(type(exc), exc, exc.__traceback__),
            )
            if status_code:
                # The response had already started; there is nothing left to send.
                raise
            status_code = 500
            await _internal_error(scope, send, request_id)
        finally:
            path = scope.get("path") or ""
            if path not in _QUIET_PATHS:
                elapsed = round((time.perf_counter() - started) * 1000, 1)
                level = logging.ERROR if status_code >= 500 else logging.INFO
                _requests.log(
                    level,
                    "%s %s %s",
                    scope.get("method", ""),
                    path,
                    status_code,
                    extra={
                        "http_method": scope.get("method", ""),
                        "http_path": path,
                        "http_status": status_code,
                        "duration_ms": elapsed,
                    },
                )
            request_id_var.reset(id_token)
            _trace_var.reset(trace_token)
