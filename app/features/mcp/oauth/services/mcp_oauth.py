from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import secrets
from dataclasses import dataclass
from datetime import timedelta
from html import escape
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx
from fastapi import HTTPException, status
from fastapi.responses import HTMLResponse
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ids import new_id, utcnow
from app.models import McpOAuthPending, McpServer, User
from app.features.identity.auth.services.auth_service import hash_token
from app.features.execution.activity.services.audit_service import audit_service
from app.features.credentials.vault.services.credential_service import open_secret, seal
from app.features.mcp.servers.services.mcp_grant import read_grant, write_grant
from app.features.mcp.servers.services import mcp_endpoint as _endpoint_checks
from app.features.mcp.servers.services.mcp_endpoint import require_mcp_endpoint
from app.features.mcp.servers.services.mcp_remote import McpUnauthorized, list_remote_tools
from app.features.identity.oauth.services.oauth_service import pkce_s256

PENDING_TTL = timedelta(minutes=10)
# What a refresh reads from the connection row, reloaded once the row is locked.
_GRANT_COLUMNS = ("credential_id", "token_expires_at", "oauth_token_endpoint", "oauth_client_id", "oauth_resource")
_refresh_locks: dict[str, asyncio.Lock] = {}


def _refresh_lock(server_id: str) -> asyncio.Lock:
    """One lock per connection in this process. Dropped once nobody holds or waits for it."""
    for key in [key for key, lock in _refresh_locks.items() if key != server_id and not lock.locked()]:
        del _refresh_locks[key]
    return _refresh_locks.setdefault(server_id, asyncio.Lock())
MAX_OAUTH_RESPONSE_BYTES = 256 * 1024
BROWSER_COOKIE_PREFIX = "saturn_mcp_"
CALLBACK_PATH = "/mcp-servers/oauth/callback"


@dataclass(frozen=True)
class BrowserBinding:
    """A cookie the starting browser must present on the callback."""

    name: str
    value: str


def browser_cookie_name(pending_id: str) -> str:
    return f"{BROWSER_COOKIE_PREFIX}{pending_id}"


def browser_cookie_domain(console_origin: str, api_origin: str) -> str | None:
    """The cookie domain both the console and the API callback receive, or None for host-only.

    The console starts the sign-in on its own host (through /saturn-api), and the provider redirects
    to the API host. A cookie for their common parent domain reaches the callback; the same host
    needs no Domain at all.
    """
    override = os.environ.get("MCP_OAUTH_COOKIE_DOMAIN", "").strip().lstrip(".").lower()
    if override:
        return override
    console = (urlparse(console_origin).hostname or "").lower().rstrip(".")
    api = (urlparse(api_origin).hostname or "").lower().rstrip(".")
    if not console or not api or console == api:
        return None
    try:
        ipaddress.ip_address(console)
        return None
    except ValueError:
        pass
    shared: list[str] = []
    # The two host names can have different numbers of labels; compare from the right as far as the shorter goes.
    for left, right in zip(reversed(console.split(".")), reversed(api.split(".")), strict=False):
        if left != right:
            break
        shared.insert(0, left)
    # Never a bare public suffix: a registrable name needs at least two labels.
    if len(shared) < 2:
        return None
    return ".".join(shared)
_NONCE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
_METADATA = re.compile(r'resource_metadata=(?:"([^"]+)"|([^\s,]+))', re.IGNORECASE)


@dataclass
class Discovery:
    authorization_endpoint: str
    token_endpoint: str
    registration_endpoint: str
    resource: str
    scope: str
    issuer: str
    endpoint: str = ""


def _aware(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=utcnow().tzinfo)
    return value


def url_allowed(url: str) -> bool:
    """Every URL an MCP server's metadata points us at gets the same checks as the endpoint itself.

    HTTPS on the default port, no credentials, no literal or metadata hosts, and every resolved
    address public. The authorization code and Saturn's client secret are posted to these URLs.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or parsed.username or parsed.password or parsed.scheme != "https":
        return False
    if host in _endpoint_checks._METADATA_HOSTS or host.endswith(".internal") or host == "localhost":
        return False
    try:
        port = parsed.port or 443
    except ValueError:
        return False
    if port != 443:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    try:
        found = _endpoint_checks.addresses_for(host, port)
    except HTTPException:
        return False
    return bool(found) and not any(_endpoint_checks.address_blocked(item) for item in found)


def metadata_url(header: str) -> str:
    match = _METADATA.search(header or "")
    if match is None:
        return ""
    return (match.group(1) or match.group(2) or "").strip()


def resource_candidates(endpoint: str) -> list[str]:
    parsed = urlparse(endpoint)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.strip("/")
    urls = []
    if path:
        urls.append(f"{origin}/.well-known/oauth-protected-resource/{path}")
    urls.append(f"{origin}/.well-known/oauth-protected-resource")
    return urls


def authorization_candidates(issuer: str) -> list[str]:
    url = issuer.rstrip("/")
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.rstrip("/")
    names = ("oauth-authorization-server", "openid-configuration")
    if not path:
        return [f"{url}/.well-known/{name}" for name in names]
    found = []
    for name in names:
        found.append(f"{origin}/.well-known/{name}{path}")
        found.append(f"{url}/.well-known/{name}")
    return found


async def _request(method: str, url: str, **kwargs: Any) -> httpx.Response:
    if not url_allowed(url):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MCP authorization URL is not allowed")
    from app.features.webhooks.services.destinations import pin_webhook_url

    # Connect to the address that was checked. Resolving again when connecting would let a
    # DNS answer change in between and send the code and client secret to an internal host.
    try:
        target = await asyncio.to_thread(pin_webhook_url, url)
    except HTTPException as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MCP authorization URL is not allowed") from exc
    headers = dict(kwargs.pop("headers", None) or {})
    headers["Host"] = target.host
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=False, trust_env=False) as client:
            request = client.build_request(
                method,
                target.url,
                headers=headers,
                extensions={"sni_hostname": target.host},
                **kwargs,
            )
            response = await client.send(request, stream=True)
            try:
                # Metadata, registration and token answers are small. A server (or a metadata URL
                # it points at) that streams more is cut off rather than buffered into memory.
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_OAUTH_RESPONSE_BYTES:
                        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "MCP authorization server response is too large")
            finally:
                await response.aclose()
            # The body was already decoded while it was read. Keeping content-encoding would make
            # httpx decode it a second time and fail on every server that compresses its answers.
            kept = {
                key: value
                for key, value in response.headers.items()
                if key.lower() not in {"content-encoding", "content-length", "transfer-encoding"}
            }
            return httpx.Response(
                response.status_code,
                headers=kept,
                content=bytes(body),
                request=request,
            )
    except httpx.HTTPError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Could not reach the MCP authorization server") from exc


def _json(response: httpx.Response) -> dict[str, Any] | None:
    if response.status_code not in {200, 201}:
        return None
    try:
        body = response.json()
    except json.JSONDecodeError:
        return None
    return body if isinstance(body, dict) else None


async def _get_json(url: str) -> dict[str, Any] | None:
    if not url_allowed(url):
        return None
    return _json(await _request("GET", url, headers={"accept": "application/json"}))


async def discover(endpoint: str, www_authenticate: str) -> Discovery:
    pointed = metadata_url(www_authenticate)
    candidates = ([pointed] if pointed else []) + resource_candidates(endpoint)
    resource_doc = None
    for url in candidates:
        resource_doc = await _get_json(url)
        if resource_doc and resource_doc.get("authorization_servers"):
            break
        resource_doc = None
    if resource_doc is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This MCP server did not offer a sign-in page")
    issuers = resource_doc.get("authorization_servers")
    issuer = issuers[0] if isinstance(issuers, list) and issuers else ""
    if not isinstance(issuer, str) or not url_allowed(issuer):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This MCP server did not offer a sign-in page")
    auth_doc = None
    for url in authorization_candidates(issuer):
        auth_doc = await _get_json(url)
        if auth_doc and auth_doc.get("authorization_endpoint") and auth_doc.get("token_endpoint"):
            break
        auth_doc = None
    if auth_doc is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This MCP server did not offer a sign-in page")
    registration = str(auth_doc.get("registration_endpoint") or "")
    scopes = resource_doc.get("scopes_supported")
    issuer_value = issuer.rstrip("/")
    scope = granted_scope(issuer_value, scopes if isinstance(scopes, list) else [])
    resource = str(resource_doc.get("resource") or endpoint).strip()
    if not url_allowed(str(auth_doc["authorization_endpoint"])) or not url_allowed(str(auth_doc["token_endpoint"])):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This MCP server did not offer a sign-in page")
    if registration and not url_allowed(registration):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This MCP server did not offer a sign-in page")
    return Discovery(
        authorization_endpoint=str(auth_doc["authorization_endpoint"]),
        token_endpoint=str(auth_doc["token_endpoint"]),
        registration_endpoint=registration,
        resource=resource,
        scope=scope,
        issuer=issuer_value,
        endpoint=endpoint,
    )


def callback_origin(request_origin: str) -> str:
    """Use the configured public origin so both Cloud Run hostnames share one callback."""
    configured = os.environ.get("PUBLIC_WS_URL", "").strip()
    if configured.startswith("wss://"):
        configured = "https://" + configured.removeprefix("wss://")
    elif configured.startswith("ws://"):
        configured = "http://" + configured.removeprefix("ws://")
    parsed = urlparse(configured)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return request_origin.rstrip("/")


GOOGLE_ISSUER = "https://accounts.google.com"
GITHUB_ISSUER = "https://github.com/login/oauth"
# Saturn's own OAuth apps. Each one is used only for the MCP hosts it was registered for, so a server
# cannot borrow it just by naming that issuer in its metadata.
_PRESET_CLIENTS = (
    (GITHUB_ISSUER, "SATURN_GITHUB_OAUTH_CLIENT_ID", "SATURN_GITHUB_OAUTH_CLIENT_SECRET", ("api.githubcopilot.com",)),
    (GOOGLE_ISSUER, "SATURN_GOOGLE_OAUTH_CLIENT_ID", "SATURN_GOOGLE_OAUTH_CLIENT_SECRET", (".googleapis.com",)),
)
_GOOGLE_SCOPES = frozenset(
    {
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.compose",
        "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
        "https://www.googleapis.com/auth/calendar.events.freebusy",
        "https://www.googleapis.com/auth/calendar.events.readonly",
    }
)
# Never requested through Saturn's GitHub app, whatever the server advertises.
_GITHUB_DENIED_SCOPES = frozenset({"delete_repo", "delete:packages", "site_admin", "admin:enterprise"})


def _host_matches(endpoint: str, hosts: tuple[str, ...]) -> bool:
    host = (urlparse(endpoint).hostname or "").lower().rstrip(".")
    return any(host == item or (item.startswith(".") and host.endswith(item)) for item in hosts)


def preset_client(issuer: str, endpoint: str = "") -> dict[str, str] | None:
    normalized = issuer.rstrip("/")
    for known, client_id_env, client_secret_env, hosts in _PRESET_CLIENTS:
        if normalized != known:
            continue
        if not _host_matches(endpoint, hosts):
            return None
        client_id = os.environ.get(client_id_env, "").strip()
        if not client_id:
            return None
        return {"client_id": client_id, "client_secret": os.environ.get(client_secret_env, "").strip()}
    return None


def granted_scope(issuer: str, scopes: list[Any]) -> str:
    chosen = [str(item).strip() for item in scopes if str(item).strip()]
    normalized = issuer.rstrip("/")
    if normalized == GOOGLE_ISSUER:
        chosen = [item for item in chosen if item in _GOOGLE_SCOPES]
    elif normalized == GITHUB_ISSUER:
        chosen = [item for item in chosen if item not in _GITHUB_DENIED_SCOPES and not item.startswith("admin:")]
    return " ".join(chosen)


class McpOAuth:
    async def begin(
        self,
        session: AsyncSession,
        user: User,
        *,
        name: str,
        endpoint: str,
        origin: str,
        nonce: str,
    ) -> dict[str, Any]:
        label = name.strip()
        url = endpoint.strip()
        if not label or not url:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Name and endpoint are required")
        from app.features.mcp.servers.services.mcp_endpoint import split_url_credential

        if split_url_credential(url)[1]:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Put the API key in the authorization field, not the URL")
        url = require_mcp_endpoint(url)
        if not _NONCE.match(nonce):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Sign-in nonce is invalid")
        try:
            await list_remote_tools(url, "")
        except McpUnauthorized as denied:
            authorization_url, binding = await self._authorize(session, user, label, url, origin, nonce, denied)
            return {"authorization_url": authorization_url, "binding": binding}
        if await self._requires_preset_sign_in(url):
            authorization_url, binding = await self._authorize(
                session, user, label, url, origin, nonce, McpUnauthorized("", url)
            )
            return {"authorization_url": authorization_url, "binding": binding}
        from app.features.mcp.servers.services.mcp_connect import mcp_connect_service

        server = await mcp_connect_service.connect(session, user, name=label, endpoint=url, authorization="")
        return {"server": server}

    async def _authorize(
        self,
        session: AsyncSession,
        user: User,
        name: str,
        endpoint: str,
        origin: str,
        nonce: str,
        denied: McpUnauthorized,
    ) -> tuple[str, BrowserBinding]:
        found = await discover(endpoint, denied.www_authenticate)
        redirect_uri = f"{origin.rstrip('/')}/mcp-servers/oauth/callback"
        registered = await self._register(found, redirect_uri)
        verifier = secrets.token_urlsafe(48)
        state = secrets.token_urlsafe(32)
        browser_secret = secrets.token_urlsafe(32)
        pending_id = new_id("moa")
        await session.execute(delete(McpOAuthPending).where(McpOAuthPending.expires_at < utcnow()))
        session.add(
            McpOAuthPending(
                id=pending_id,
                state_hash=hash_token(state),
                browser_hash=hash_token(browser_secret),
                user_id=user.id,
                organization_id=user.organization_id,
                name=name,
                endpoint=endpoint,
                nonce=nonce,
                verifier_ciphertext=await asyncio.to_thread(seal, verifier, user.organization_id, user.id),
                client_id=registered["client_id"],
                client_secret_ciphertext=(
                    await asyncio.to_thread(seal, registered["client_secret"], user.organization_id, user.id)
                    if registered["client_secret"]
                    else ""
                ),
                token_endpoint=found.token_endpoint,
                resource=found.resource,
                scope=found.scope,
                redirect_uri=redirect_uri,
                expires_at=utcnow() + PENDING_TTL,
            )
        )
        await session.flush()
        query = {
            "response_type": "code",
            "client_id": registered["client_id"],
            "redirect_uri": redirect_uri,
            "code_challenge": pkce_s256(verifier),
            "code_challenge_method": "S256",
            "state": state,
        }
        if found.resource:
            query["resource"] = found.resource
        if found.scope:
            query["scope"] = found.scope
        if found.issuer == GOOGLE_ISSUER:
            query["access_type"] = "offline"
        binding = BrowserBinding(name=browser_cookie_name(pending_id), value=browser_secret)
        return f"{found.authorization_endpoint}?{urlencode(query)}", binding

    async def _requires_preset_sign_in(self, endpoint: str) -> bool:
        """Google publishes its tool list before sign-in. A preset client still has to authorize."""
        try:
            found = await discover(endpoint, "")
        except HTTPException:
            return False
        if preset_client(found.issuer, found.endpoint or endpoint) is not None:
            return True
        if found.issuer == GOOGLE_ISSUER:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "This MCP server does not let Saturn start sign-in")
        return False

    async def _register(self, found: Discovery, redirect_uri: str) -> dict[str, str]:
        preset = preset_client(found.issuer, found.endpoint)
        if preset is not None:
            return preset
        if not found.registration_endpoint:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "This MCP server does not let Saturn start sign-in")
        body: dict[str, Any] = {
            "client_name": "Saturn",
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        }
        if found.scope:
            body["scope"] = found.scope
        response = await _request(
            "POST",
            found.registration_endpoint,
            headers={"accept": "application/json", "content-type": "application/json"},
            json=body,
        )
        registered = _json(response)
        client_id = str((registered or {}).get("client_id") or "").strip()
        if not client_id:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, "MCP provider did not accept Saturn as a client")
        secret = str((registered or {}).get("client_secret") or "")
        return {"client_id": client_id, "client_secret": secret}

    async def finish(
        self,
        session: AsyncSession,
        *,
        code: str,
        state: str,
        error: str,
        cookies: dict[str, str] | None = None,
    ) -> HTMLResponse:
        pending = await session.scalar(select(McpOAuthPending).where(McpOAuthPending.state_hash == hash_token(state)))
        if pending is None or _aware(pending.expires_at) <= utcnow():
            return _page(False, "", "This sign-in expired. Close the window and connect again.")
        presented = (cookies or {}).get(browser_cookie_name(pending.id), "")
        if not pending.browser_hash or not secrets.compare_digest(hash_token(presented), pending.browser_hash):
            # Someone else's browser opened this sign-in link. Never store their account for the
            # person who started it; end the sign-in so the link cannot be retried.
            from app.core.enums import ActorType, AuditEvent

            await session.execute(delete(McpOAuthPending).where(McpOAuthPending.id == pending.id))
            await audit_service.log(
                session,
                event=AuditEvent.MCP_OAUTH_REFUSED,
                actor_type=ActorType.SYSTEM,
                actor_id="saturn",
                organization_id=pending.organization_id,
                result="browser_mismatch",
                payload={"user_id": pending.user_id, "endpoint_host": urlparse(pending.endpoint).hostname or ""},
            )
            return _page(
                False,
                "",
                "This sign-in was started in another browser. Start it again from the Saturn console.",
                notify=False,
            )
        # Claim the sign-in before using its code. A browser can load this callback twice; only
        # one load may exchange the code, and the other must not tell the console it failed.
        claimed = await session.execute(
            delete(McpOAuthPending)
            .where(McpOAuthPending.id == pending.id)
            .execution_options(synchronize_session=False)
        )
        if claimed.rowcount != 1:
            return _page(False, "", "", notify=False)
        session.expunge(pending)
        nonce = pending.nonce
        if error:
            return _page(False, nonce, "The MCP provider did not grant access.")
        if not code:
            return _page(False, nonce, "The MCP provider did not return an authorization code.")
        from app.features.credentials.vault.services.pq_crypto import SecretNeedsReconnect

        try:
            verifier = await asyncio.to_thread(open_secret, pending.verifier_ciphertext, pending.organization_id, pending.user_id)
            secret = (
                await asyncio.to_thread(open_secret, pending.client_secret_ciphertext, pending.organization_id, pending.user_id)
                if pending.client_secret_ciphertext
                else ""
            )
        except SecretNeedsReconnect:
            return _page(False, nonce, "This sign-in expired. Close the window and connect again.")
        try:
            token = await self._exchange(pending, code=code, verifier=verifier, client_secret=secret)
            from app.features.mcp.servers.services.mcp_connect import mcp_connect_service

            user = await session.get(User, pending.user_id)
            if user is None:
                return _page(False, nonce, "This sign-in expired. Close the window and connect again.")
            server = await mcp_connect_service.connect(
                session,
                user,
                name=pending.name,
                endpoint=pending.endpoint,
                authorization=token["access_token"],
            )
            await self._remember(session, server, pending, token, secret)
            await session.flush()
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, str) else "Could not finish sign-in."
            return _page(False, nonce, detail)
        return _page(True, nonce, "")

    async def _exchange(self, pending: McpOAuthPending, *, code: str, verifier: str, client_secret: str) -> dict[str, Any]:
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": pending.redirect_uri,
            "client_id": pending.client_id,
            "code_verifier": verifier,
        }
        if pending.resource:
            form["resource"] = pending.resource
        if client_secret:
            form["client_secret"] = client_secret
        return await _token(pending.token_endpoint, form)

    async def _remember(
        self,
        session: AsyncSession,
        server: McpServer,
        pending: McpOAuthPending,
        token: dict[str, Any],
        client_secret: str,
    ) -> None:
        server.oauth_client_id = pending.client_id
        server.oauth_token_endpoint = pending.token_endpoint
        server.oauth_resource = pending.resource
        server.oauth_scope = str(token.get("scope") or pending.scope or "")
        server.token_expires_at = _expires_at(token)
        await write_grant(
            session,
            server,
            {
                "access_token": str(token.get("access_token") or ""),
                "refresh_token": str(token.get("refresh_token") or ""),
                "client_secret": client_secret,
            },
        )

    async def authorization_for(self, session: AsyncSession, server: McpServer | None) -> str:
        if server is None:
            return ""
        from app.features.credentials.vault.services.pq_crypto import SecretNeedsReconnect

        try:
            grant = await read_grant(session, server)
        except SecretNeedsReconnect as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, "This connection needs to be signed in again") from exc
        secret = grant["access_token"]
        expires = server.token_expires_at
        if expires is not None and _aware(expires) <= utcnow() + timedelta(seconds=60):
            refreshed = await self._refresh(session, server, used=secret)
            if refreshed:
                return refreshed
        if secret:
            await self._audit_open(session, server, "upstream_mcp")
        return secret

    async def refresh_after_reject(self, session: AsyncSession, server: McpServer | None, rejected: str = "") -> str:
        """A new access token after the upstream refused `rejected`."""
        if server is None:
            return ""
        return await self._refresh(session, server, used=rejected)

    async def _refresh(self, session: AsyncSession, server: McpServer, *, used: str = "") -> str:
        """Exchange the refresh token, one caller at a time per connection.

        A provider that rotates refresh tokens revokes the grant when an old one is presented
        again, so two calls refreshing at once could leave the connection signed out. The second
        caller waits, then takes the token the first one stored. The new tokens are committed
        before this returns: the provider has already retired the old ones, and a request that
        failed afterwards would otherwise roll the only valid refresh token away.
        """
        from app.features.credentials.vault.services.pq_crypto import SecretNeedsReconnect

        async with _refresh_lock(server.id):
            # Other processes: the row lock makes them wait here, and the reload shows what they stored.
            await session.refresh(server, attribute_names=_GRANT_COLUMNS, with_for_update=True)
            try:
                grant = await read_grant(session, server, fresh=True)
            except SecretNeedsReconnect as exc:
                await session.commit()
                raise HTTPException(status.HTTP_409_CONFLICT, "This connection needs to be signed in again") from exc
            current = grant["access_token"]
            if used and current and current != used:
                await self._audit_open(session, server, "upstream_mcp")
                await session.commit()
                return current
            access = await self._exchange_refresh(session, server, grant)
            # Also on failure: it releases the row for the next caller.
            await session.commit()
            return access

    async def _exchange_refresh(self, session: AsyncSession, server: McpServer, grant: dict[str, str]) -> str:
        refresh = grant["refresh_token"]
        if not refresh or not server.oauth_token_endpoint or not server.oauth_client_id:
            return ""
        await self._audit_open(session, server, "refresh")
        form = {
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": server.oauth_client_id,
        }
        if server.oauth_resource:
            form["resource"] = server.oauth_resource
        if grant["client_secret"]:
            form["client_secret"] = grant["client_secret"]
        try:
            token = await _token(server.oauth_token_endpoint, form)
        except HTTPException:
            return ""
        access = str(token.get("access_token") or "")
        if not access:
            return ""
        rotated = str(token.get("refresh_token") or "")
        if rotated:
            grant["refresh_token"] = rotated
        grant["access_token"] = access
        server.token_expires_at = _expires_at(token)
        await write_grant(session, server, grant)
        return access

    async def _audit_open(self, session: AsyncSession, server: McpServer, purpose: str) -> None:
        from app.core.enums import ActorType, AuditEvent

        await audit_service.log(
            session,
            event=AuditEvent.CREDENTIAL_ACCESSED,
            actor_type=ActorType.SYSTEM,
            actor_id="saturn",
            organization_id=server.organization_id,
            result=server.name,
            payload={"credential_id": server.credential_id, "purpose": purpose},
        )


def _expires_at(token: dict[str, Any]):
    raw = token.get("expires_in")
    if isinstance(raw, bool) or raw is None:
        return None
    try:
        seconds = int(raw)
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    return utcnow() + timedelta(seconds=seconds)


async def _token(url: str, form: dict[str, str]) -> dict[str, Any]:
    response = await _request(
        "POST",
        url,
        headers={"accept": "application/json", "content-type": "application/x-www-form-urlencoded"},
        data=form,
    )
    body = _json(response)
    access = str((body or {}).get("access_token") or "")
    if not access:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "MCP provider did not return an access token")
    return body or {}


def _page(ok: bool, nonce: str, error: str, *, notify: bool = True) -> HTMLResponse:
    from app.core.http_security import current_csp_nonce

    # Escape "<" so text from an upstream error can never close the script element.
    payload = json.dumps({"type": "saturn-mcp-oauth", "ok": ok, "nonce": nonce, "error": error}).replace("<", "\\u003c")
    # Only the console that opened this window may read the result. postMessage takes one target
    # origin, so it is sent once per allowed console origin and the others are dropped by the browser.
    from app.core.config import get_settings

    origins = [item.strip() for item in get_settings().cors_origins.split(",") if item.strip() and item.strip() != "*"]
    targets = json.dumps(origins).replace("<", "\\u003c")
    script_nonce = escape(current_csp_nonce())
    title = "Connected" if ok else "Not connected"
    note = "已連線，可以關閉這個視窗。" if ok else escape(error)
    lead = "You can close this window." if ok else ""
    return HTMLResponse(
        f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{title}</title></head>
<body style="margin:0;background:#f7f7f5;color:#111110;font:14px/1.5 -apple-system,BlinkMacSystemFont,sans-serif">
<main style="max-width:360px;margin:48px auto;padding:0 24px">
<h1 style="font-size:18px;font-weight:600">{title}</h1>
<p>{lead}</p>
<p>{note}</p>
</main>
<script nonce="{script_nonce}">if ({"true" if notify else "false"} && window.opener) {{ for (const origin of {targets}) {{ try {{ window.opener.postMessage({payload}, origin); }} catch (e) {{}} }} }} window.close();</script>
</body></html>"""
    )


mcp_oauth = McpOAuth()
