from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field

from app.core.config import get_settings

logger = logging.getLogger(__name__)

LIST_CHANGED = {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}
CHANNEL = "saturn:mcp:events"
SESSION_TTL = 86_400
# What one process keeps in memory. A record is small, but nothing else ever removed one.
MAX_LOCAL_SESSIONS = 10_000
# Sessions one client may hold before it has an agent: an initialize that names no agent of
# its own opens one each time, and those have no agent to be replaced by.
MAX_UNBOUND_PER_CLIENT = 4
# With Redis, a local record is only a cache of the Redis one and can be rebuilt from it.
LOCAL_CACHE_IDLE = 900
# Every notice says the same thing ("the tool list changed"), so a few waiting are plenty.
MAX_QUEUED_NOTICES = 16


@dataclass
class McpSession:
    session_id: str
    user_id: str
    agent_id: str
    client_id: str
    queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=MAX_QUEUED_NOTICES))
    touched: float = field(default_factory=time.monotonic)


class McpSessionHub:
    """Session records live in Redis so any instance can serve the stream.

    The queue stays on the instance that holds the SSE connection. Tests and a
    single local process keep the record in memory.
    """

    def __init__(self) -> None:
        self._items: dict[str, McpSession] = {}
        self._redis = None
        self._listener: asyncio.Task | None = None

    async def start(self) -> None:
        if get_settings().in_process_runtime or self._redis is not None:
            return
        from redis.asyncio import Redis

        client = Redis.from_url(get_settings().redis_url, decode_responses=True)
        try:
            await client.ping()
        except Exception:
            await client.aclose()
            if os.environ.get("K_SERVICE", "").strip():
                raise
            logger.warning("MCP sessions staying in this process because Redis is unavailable")
            return
        self._redis = client
        self._listener = asyncio.create_task(self._listen())

    async def stop(self) -> None:
        if self._listener is not None:
            self._listener.cancel()
            with_cancel = self._listener
            self._listener = None
            try:
                await with_cancel
            except asyncio.CancelledError:
                pass
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None

    async def open(self, session_id: str, user_id: str, agent_id: str, client_id: str) -> McpSession | None:
        """Record a session id the server just issued. An id that already exists is never taken over."""
        if not session_id:
            return None
        if self._redis is None:
            if session_id in self._items:
                return self._local_get(session_id, user_id, client_id)
            self._evict_local(session_id, agent_id, client_id)
            return self._attach(session_id, user_id, agent_id, client_id)
        payload = self._record(session_id, user_id, agent_id, client_id)
        created = await self._redis.set(f"saturn:mcp:session:{session_id}", payload, ex=SESSION_TTL, nx=True)
        if not created:
            return await self.get(session_id, user_id, client_id)
        await self._claim_owner(session_id, agent_id, client_id)
        return self._attach(session_id, user_id, agent_id, client_id)

    async def bind(self, session_id: str, user_id: str, agent_id: str, client_id: str) -> McpSession | None:
        """Point an existing session at the agent it now serves. Unknown or foreign ids are ignored."""
        record = await self.get(session_id, user_id, client_id)
        if record is None:
            return None
        if record.agent_id == agent_id:
            return record
        record.agent_id = agent_id
        if self._redis is None:
            self._evict_local(session_id, agent_id, client_id)
            return record
        await self._redis.set(
            f"saturn:mcp:session:{session_id}",
            self._record(session_id, user_id, agent_id, client_id),
            ex=SESSION_TTL,
            xx=True,
        )
        await self._claim_owner(session_id, agent_id, client_id)
        return record

    @staticmethod
    def _record(session_id: str, user_id: str, agent_id: str, client_id: str) -> str:
        return json.dumps(
            {
                "session_id": session_id,
                "user_id": user_id,
                "agent_id": agent_id,
                "client_id": client_id,
            }
        )

    async def _claim_owner(self, session_id: str, agent_id: str, client_id: str) -> None:
        assert self._redis is not None
        if not agent_id:
            return
        owner_key = f"saturn:mcp:owner:{agent_id}:{client_id}"
        previous = await self._redis.get(owner_key)
        if previous and previous != session_id:
            await self._redis.delete(f"saturn:mcp:session:{previous}")
            self._close_local(previous)
            await self._redis.publish(CHANNEL, json.dumps({"kind": "close", "session_id": previous}))
        await self._redis.set(owner_key, session_id, ex=SESSION_TTL)

    async def get(self, session_id: str, user_id: str, client_id: str) -> McpSession | None:
        local = self._local_get(session_id, user_id, client_id)
        if local is not None or self._redis is None:
            return local
        raw = await self._redis.get(f"saturn:mcp:session:{session_id}")
        if not raw:
            return None
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if data.get("user_id") != user_id or data.get("client_id") != client_id:
            return None
        return self._attach(
            session_id,
            user_id,
            str(data.get("agent_id") or ""),
            client_id,
        )

    async def notify(self, agent_ids: list[str]) -> None:
        if self._redis is None:
            self._notify_local(agent_ids)
            return
        await self._redis.publish(CHANNEL, json.dumps({"kind": "notify", "agent_ids": agent_ids}))

    async def close(self, session_id: str) -> None:
        self._close_local(session_id)
        if self._redis is None:
            return
        await self._redis.delete(f"saturn:mcp:session:{session_id}")
        await self._redis.publish(CHANNEL, json.dumps({"kind": "close", "session_id": session_id}))

    async def detach(self, session_id: str) -> None:
        """The event stream ended; the session itself goes on.

        A proxy or the platform ends a long stream sooner or later. The client then opens the
        stream again with the same session id, which must still be known. With Redis the record
        there is the session, so only this instance's copy and its queue are dropped. Without
        Redis this record is the only one and stays until it is idle too long.
        """
        if self._redis is not None:
            self._items.pop(session_id, None)

    def reset(self) -> None:
        for session_id in list(self._items):
            self._close_local(session_id)

    def _evict_local(self, session_id: str, agent_id: str, client_id: str) -> None:
        if not agent_id:
            return
        for sid, item in list(self._items.items()):
            if sid != session_id and item.agent_id == agent_id and item.client_id == client_id:
                self._close_local(sid)

    def _attach(self, session_id: str, user_id: str, agent_id: str, client_id: str) -> McpSession | None:
        existing = self._items.get(session_id)
        if existing is not None:
            # Another caller's record keeps its owner.
            if existing.user_id != user_id or existing.client_id != client_id:
                return None
            existing.agent_id = agent_id
            return existing
        record = McpSession(
            session_id=session_id,
            user_id=user_id,
            agent_id=agent_id,
            client_id=client_id,
        )
        self._items[session_id] = record
        self._trim(record)
        return record

    def _trim(self, newest: McpSession) -> None:
        """Keep the in-memory records bounded. The newest one is never the one removed."""
        now = time.monotonic()
        idle_limit = LOCAL_CACHE_IDLE if self._redis is not None else SESSION_TTL
        unbound: list[str] = []
        for sid, item in list(self._items.items()):
            if item is newest:
                continue
            if now - item.touched > idle_limit:
                self._close_local(sid)
            elif not item.agent_id and item.user_id == newest.user_id and item.client_id == newest.client_id:
                unbound.append(sid)
        if not newest.agent_id:
            # Oldest first: dicts keep insertion order.
            for sid in unbound[: max(0, len(unbound) + 1 - MAX_UNBOUND_PER_CLIENT)]:
                self._close_local(sid)
        while len(self._items) > MAX_LOCAL_SESSIONS:
            oldest = next(iter(self._items))
            if self._items[oldest] is newest:
                break
            self._close_local(oldest)

    def _local_get(self, session_id: str, user_id: str, client_id: str) -> McpSession | None:
        record = self._items.get(session_id)
        if record is None or record.user_id != user_id or record.client_id != client_id:
            return None
        record.touched = time.monotonic()
        return record

    def _notify_local(self, agent_ids: list[str]) -> None:
        wanted = {agent_id for agent_id in agent_ids if agent_id}
        if not wanted:
            return
        for record in self._items.values():
            if record.agent_id in wanted:
                try:
                    record.queue.put_nowait(dict(LIST_CHANGED))
                except asyncio.QueueFull:
                    # Nobody is reading this stream. The notices already waiting say the same thing.
                    pass

    def _close_local(self, session_id: str) -> None:
        record = self._items.pop(session_id, None)
        if record is None:
            return
        # The end marker must get through even when the queue is full of unread notices.
        while True:
            try:
                record.queue.put_nowait(None)
                return
            except asyncio.QueueFull:
                try:
                    record.queue.get_nowait()
                except asyncio.QueueEmpty:
                    return

    async def _listen(self) -> None:
        assert self._redis is not None
        while True:
            pubsub = self._redis.pubsub()
            try:
                await pubsub.subscribe(CHANNEL)
                async for message in pubsub.listen():
                    if message.get("type") != "message":
                        continue
                    raw = message.get("data")
                    try:
                        body = json.loads(raw) if isinstance(raw, str) else {}
                    except json.JSONDecodeError:
                        continue
                    kind = body.get("kind")
                    if kind == "notify":
                        self._notify_local(list(body.get("agent_ids") or []))
                    elif kind == "close":
                        self._close_local(str(body.get("session_id") or ""))
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("MCP session listener stopped")
                await asyncio.sleep(1)
            finally:
                try:
                    await pubsub.aclose()
                except Exception:
                    logger.debug("MCP session listener cleanup failed", exc_info=True)


mcp_sessions = McpSessionHub()
