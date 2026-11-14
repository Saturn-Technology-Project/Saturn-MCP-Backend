from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import threading

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.ids import utcnow
from app.features.credentials.vault.models.secret_vault import SecretVault
from app.features.credentials.vault.services.pq_crypto import SecretNeedsReconnect, open_secret_async, seal_async

logger = logging.getLogger(__name__)

_SECRET_ID = re.compile(r"[^A-Za-z0-9_-]+")


def _project() -> str:
    return (get_settings().saturn_secret_project or "").strip()


def _legacy_gcp_name(secret_id: str) -> str:
    """The old name. Different ids collapse onto it, and it does not say which tenant owns it."""
    cleaned = _SECRET_ID.sub("-", secret_id).strip("-")
    return f"sat-{cleaned}"[:255]


def _gcp_name(secret_id: str, organization_id: str) -> str:
    """Unique per (organization, exact secret id): both are hashed, so nothing collapses."""
    if not organization_id:
        raise ValueError("organization id is required for a Secret Manager name")
    org_tag = hashlib.sha256(f"saturn-secret-org\n{organization_id}".encode()).hexdigest()[:24]
    id_tag = hashlib.sha256(f"saturn-secret-id\n{secret_id}".encode()).hexdigest()[:24]
    readable = _SECRET_ID.sub("-", secret_id).strip("-")[:80]
    return f"sat2-{org_tag}-{id_tag}-{readable}".rstrip("-")[:255]


def vault_context(secret_id: str) -> str:
    """What a vault value is bound to. Moving it onto another entry makes it refuse to open."""
    return f"vault:{secret_id}"


def _owns(blob: str, organization_id: str, user_id: str = "") -> bool:
    """A legacy entry belongs to this tenant only when this tenant's key opens it."""
    if not blob or not organization_id:
        return False
    from app.features.credentials.vault.services.pq_crypto import open_secret

    try:
        open_secret(blob, organization_id, user_id)
    except SecretNeedsReconnect:
        return False
    return True


async def put_secret(
    session: AsyncSession,
    secret_id: str,
    plaintext: str,
    organization_id: str,
    user_id: str = "",
) -> None:
    if not secret_id:
        return
    if not plaintext:
        await delete_secret(session, secret_id, organization_id, user_id)
        return
    blob = await seal_async(plaintext, organization_id, user_id, vault_context(secret_id))
    project = _project()
    if project:
        await asyncio.to_thread(_gcp_put, project, _gcp_name(secret_id, organization_id), blob)
        await asyncio.to_thread(_gcp_drop_legacy, project, secret_id, organization_id, user_id)
        await _db_delete(session, secret_id)
        return
    row = await session.get(SecretVault, secret_id)
    if row is None:
        session.add(SecretVault(id=secret_id, ciphertext=blob, updated_at=utcnow()))
    else:
        row.ciphertext = blob
        row.updated_at = utcnow()
    await session.flush()


def _gcp_read(project: str, secret_id: str, organization_id: str) -> str:
    blob = _gcp_get(project, _gcp_name(secret_id, organization_id))
    if blob:
        return blob
    # Entries written before names were per organization. Another tenant's entry under the
    # same legacy name does not open with this tenant's key, so the read still fails safely.
    return _gcp_get(project, _legacy_gcp_name(secret_id))


def _gcp_drop_legacy(project: str, secret_id: str, organization_id: str, user_id: str = "") -> None:
    legacy = _legacy_gcp_name(secret_id)
    if legacy == _gcp_name(secret_id, organization_id):
        return
    if _owns(_gcp_get(project, legacy), organization_id, user_id):
        _gcp_delete(project, legacy)


async def _ciphertext(session: AsyncSession, secret_id: str, organization_id: str, *, fresh: bool = False) -> str:
    project = _project()
    if project:
        if not organization_id:
            return ""
        return await asyncio.to_thread(_gcp_read, project, secret_id, organization_id)
    row = await session.get(SecretVault, secret_id, populate_existing=fresh)
    return row.ciphertext if row is not None else ""


async def get_secret(
    session: AsyncSession, secret_id: str, organization_id: str, user_id: str = "", *, fresh: bool = False
) -> str:
    """With fresh, read the entry again even if this session already holds a copy another writer may have replaced."""
    if not secret_id or not organization_id:
        return ""
    return await open_secret_async(
        await _ciphertext(session, secret_id, organization_id, fresh=fresh),
        organization_id,
        user_id,
        vault_context(secret_id),
    )


async def reconnect_status(session: AsyncSession, secret_id: str, organization_id: str, user_id: str = "") -> str:
    if not secret_id:
        return "none"
    blob = await _ciphertext(session, secret_id, organization_id)
    if not blob.startswith(("pq2.", "pq3.")):
        return "needs_reconnect"
    try:
        await open_secret_async(blob, organization_id, user_id, vault_context(secret_id))
    except SecretNeedsReconnect:
        return "needs_reconnect"
    return "ok"


async def delete_secret(session: AsyncSession, secret_id: str, organization_id: str = "", user_id: str = "") -> None:
    if not secret_id:
        return
    project = _project()
    if project:
        if organization_id:
            await asyncio.to_thread(_gcp_delete, project, _gcp_name(secret_id, organization_id))
            await asyncio.to_thread(_gcp_drop_legacy, project, secret_id, organization_id, user_id)
        else:
            # Without the tenant the name is unknown, and deleting the legacy name could
            # remove another tenant's entry. Leave it; it only holds that tenant's ciphertext.
            logger.warning("secret %s not deleted from Secret Manager: no organization given", secret_id)
    await _db_delete(session, secret_id)


async def stored_ids(session: AsyncSession, secret_ids: list[str], organization_id: str = "") -> set[str]:
    if not secret_ids:
        return set()
    project = _project()
    if project:
        found: set[str] = set()
        if not organization_id:
            return found
        for secret_id in secret_ids:
            if await asyncio.to_thread(_gcp_read, project, secret_id, organization_id):
                found.add(secret_id)
        return found
    result = await session.scalars(select(SecretVault.id).where(SecretVault.id.in_(secret_ids)))
    return set(result.all())


async def _db_delete(session: AsyncSession, secret_id: str) -> None:
    row = await session.get(SecretVault, secret_id)
    if row is not None:
        await session.delete(row)
        await session.flush()


_shared_client = None
_client_lock = threading.Lock()


def _client():
    """One client for the process. Building one opens a gRPC channel and fetches credentials,
    which used to happen again on every read and write."""
    global _shared_client
    with _client_lock:
        if _shared_client is None:
            from google.cloud import secretmanager

            _shared_client = secretmanager.SecretManagerServiceClient()
        return _shared_client


def _gcp_put(project: str, gcp_name: str, blob: str) -> None:
    from google.api_core.exceptions import NotFound

    client = _client()
    parent = f"projects/{project}"
    name = f"{parent}/secrets/{gcp_name}"
    try:
        client.get_secret(name=name)
    except NotFound:
        client.create_secret(
            parent=parent,
            secret_id=gcp_name,
            secret={"replication": {"automatic": {}}},
        )
    client.add_secret_version(parent=name, payload={"data": blob.encode()})


def _gcp_get(project: str, gcp_name: str) -> str:
    from google.api_core.exceptions import NotFound

    client = _client()
    name = f"projects/{project}/secrets/{gcp_name}/versions/latest"
    try:
        response = client.access_secret_version(name=name)
    except NotFound:
        return ""
    return response.payload.data.decode()


def _gcp_delete(project: str, gcp_name: str) -> None:
    from google.api_core.exceptions import NotFound

    client = _client()
    name = f"projects/{project}/secrets/{gcp_name}"
    try:
        client.delete_secret(name=name)
    except NotFound:
        return
