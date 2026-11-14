from __future__ import annotations

import re

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.ids import new_id
from app.models import McpServer, Tool, User
from app.core.enums import ToolStatus, ToolType
from app.features.mcp.servers.services.mcp_endpoint import require_mcp_endpoint, split_url_credential
from app.features.credentials.vault.services.pq_crypto import SecretNeedsReconnect
from app.features.mcp.servers.services.mcp_grant import read_grant, write_grant
from app.features.mcp.servers.services.mcp_remote import McpUnauthorized, list_remote_tools


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return cleaned or "mcp"


def _exposed(server_name: str, upstream: str, taken: set[str]) -> str:
    if upstream not in taken:
        return upstream
    prefixed = f"{_slug(server_name)}.{upstream}"
    if prefixed not in taken:
        return prefixed
    index = 2
    while f"{prefixed}-{index}" in taken:
        index += 1
    return f"{prefixed}-{index}"


class McpConnectService:
    async def connect(
        self,
        session: AsyncSession,
        user: User,
        *,
        name: str,
        endpoint: str,
        authorization: str | None,
    ) -> McpServer:
        label = name.strip()
        url = endpoint.strip()
        if not label or not url:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Name and endpoint are required")
        url, url_key = split_url_credential(url)
        if url_key:
            # A key pasted into the URL moves to the vault like any other credential.
            given = (authorization or "").strip()
            if given.lower().startswith("bearer "):
                given = given[7:].strip()
            if given and given != url_key:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "Put the API key in the authorization field, not the URL")
            authorization = url_key
        url = require_mcp_endpoint(url)
        existing = await session.scalar(
            select(McpServer).where(
                McpServer.organization_id == user.organization_id,
                McpServer.name == label,
            )
        )
        endpoint_changed = existing is not None and existing.endpoint.strip() != url
        token = ""
        if authorization is not None:
            token = authorization.strip()
        elif existing is not None and not endpoint_changed:
            try:
                token = (await read_grant(session, existing))["access_token"]
            except SecretNeedsReconnect as exc:
                raise HTTPException(status.HTTP_409_CONFLICT, "This connection needs to be signed in again") from exc
        try:
            discovered = await list_remote_tools(url, token)
        except McpUnauthorized as exc:
            if authorization and authorization.strip():
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "Access token was rejected") from exc
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "This MCP server requires sign-in") from exc
        if existing is None:
            server = McpServer(
                id=new_id("mcp"),
                organization_id=user.organization_id,
                name=label,
                endpoint=url,
                status="active",
            )
            session.add(server)
            await session.flush()
        else:
            server = existing
            server.endpoint = url
            server.status = "active"
        if authorization is not None:
            if token:
                await write_grant(
                    session,
                    server,
                    {"access_token": token, "refresh_token": "", "client_secret": ""},
                )
            else:
                await write_grant(session, server, {})
        elif endpoint_changed:
            await write_grant(session, server, {})
        await self._store_tools(session, server, discovered)
        result = await session.execute(
            select(McpServer).options(selectinload(McpServer.tools)).where(McpServer.id == server.id)
        )
        return result.scalar_one()

    async def refresh(self, session: AsyncSession, user: User, server_id: str) -> McpServer:
        server = await session.get(McpServer, server_id)
        if server is None or server.organization_id != user.organization_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "MCP server not found")
        if not server.endpoint:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "MCP server has no endpoint")
        url = require_mcp_endpoint(server.endpoint)
        from app.features.mcp.oauth.services.mcp_oauth import mcp_oauth

        secret = await mcp_oauth.authorization_for(session, server)
        try:
            discovered = await list_remote_tools(url, secret)
        except McpUnauthorized:
            secret = await mcp_oauth.refresh_after_reject(session, server, secret)
            if not secret:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "Access token was rejected") from None
            try:
                discovered = await list_remote_tools(url, secret)
            except McpUnauthorized as exc:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "Access token was rejected") from exc
        await self._store_tools(session, server, discovered)
        result = await session.execute(
            select(McpServer).options(selectinload(McpServer.tools)).where(McpServer.id == server.id)
        )
        return result.scalar_one()

    async def _store_tools(self, session: AsyncSession, server: McpServer, discovered: list[dict]) -> None:
        current = list(
            (
                await session.execute(select(Tool).where(Tool.mcp_server_id == server.id))
            ).scalars().all()
        )
        org_tools = list(
            (
                await session.execute(select(Tool).where(Tool.organization_id == server.organization_id))
            ).scalars().all()
        )
        by_upstream = {tool.upstream_name or tool.name: tool for tool in current}
        taken = {tool.name for tool in org_tools if tool.mcp_server_id != server.id}
        taken.update(tool.name for tool in current)
        seen: set[str] = set()
        for item in discovered:
            upstream = str(item["name"])
            seen.add(upstream)
            tool = by_upstream.get(upstream)
            if tool is None:
                exposed = _exposed(server.name, upstream, taken)
                taken.add(exposed)
                tool = Tool(
                    id=new_id("tool"),
                    organization_id=server.organization_id,
                    name=exposed,
                    description=str(item.get("description") or ""),
                    type=ToolType.MCP.value,
                    mcp_endpoint=server.endpoint,
                    permissions=list(item.get("permissions") or ["write"]),
                    input_schema=item.get("inputSchema") or {"type": "object", "properties": {}},
                    upstream_name=upstream,
                    mcp_server_id=server.id,
                    status=ToolStatus.ACTIVE.value,
                )
                session.add(tool)
            else:
                tool.description = str(item.get("description") or tool.description)
                tool.input_schema = item.get("inputSchema") or tool.input_schema or {}
                tool.permissions = list(item.get("permissions") or ["write"])
                tool.upstream_name = upstream
                tool.mcp_endpoint = server.endpoint
                tool.mcp_server_id = server.id
                tool.status = ToolStatus.ACTIVE.value
                taken.add(tool.name)
        for tool in current:
            if (tool.upstream_name or tool.name) not in seen:
                tool.status = ToolStatus.DISABLED.value
        await session.flush()
        from app.features.policy.policies.services.default_policy import extend_default_policy

        await extend_default_policy(session, server.organization_id)


mcp_connect_service = McpConnectService()
