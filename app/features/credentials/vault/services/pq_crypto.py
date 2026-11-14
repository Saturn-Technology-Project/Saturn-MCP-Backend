"""Per-tenant credential keys.

The root HMAC key stays in Cloud KMS and is never loaded into this process.
Each organization, and each user when a secret belongs to one person, gets its
own ML-KEM seed from a KMS MAC of a labeled string. A tenant key does not open
another tenant's ciphertext, and a copy of this process does not contain the root.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import threading
import time

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM1024PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)

_PREFIX = "pq2."
_LEGACY_PREFIX = "pq1."
# pq3.<context>.<blob>: like pq2, with the context (what the value is for, such as the vault entry
# it belongs to) authenticated as AES-GCM associated data. A value moved to another entry no longer
# opens there.
_BOUND_PREFIX = "pq3."
_AAD_LABEL = b"saturn-pq3\n"


class SecretNeedsReconnect(Exception):
    """The stored secret is pq1 or cannot be opened. The caller must reconnect it."""

    def __init__(self) -> None:
        super().__init__("This secret needs to be connected again")


class KeyUnavailable(Exception):
    """The tenant key could not be derived just now (KMS did not answer, or is not configured).

    Nothing is wrong with the stored value, so this is never reported as SecretNeedsReconnect:
    a caller that treated it that way would tell people to reconnect, or give up on a delivery,
    over an outage that ends by itself.
    """

    def __init__(self) -> None:
        super().__init__("The key service is unavailable")


_INFO_AES = b"saturn-credential-aes-256-gcm-v1"
# Full cryptoKeyVersion resource name, for example .../cryptoKeys/kem-root/cryptoKeyVersions/N.
# Rotation creates a new version and points SATURN_KMS_KEY at it. Existing ciphertext stays
# readable only by the version that produced it, so a rotation also rewraps each secret:
# open with the old version, then seal again after the setting changes.
_KMS_ENV = "SATURN_KMS_KEY"
_CONTENT_TTL_SECONDS = 300.0
# warm_content_key renews a key this long before it expires, so one request never outlives it.
_WARM_MARGIN_SECONDS = 60.0
_root: bytes | None = None
_keys: dict[tuple[str, str, str], MLKEM1024PrivateKey] = {}
_MAX_CACHED_KEYS = 256
_content_keys: dict[str, tuple[float, bytes]] = {}
# seal and open run on worker threads (asyncio.to_thread), several at a time. The lock covers
# only the two caches; a KMS call is never made while holding it.
_cache_lock = threading.Lock()
_kms_client = None


def _hkdf(material: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA384(), length=length, salt=None, info=info).derive(material)


def install_root(root: bytes) -> None:
    """Test hook. Production derives keys through KMS and never calls this."""
    global _root
    if len(root) < 32:
        raise RuntimeError("local root must be at least 32 bytes")
    _root = root
    with _cache_lock:
        _keys.clear()
        _content_keys.clear()


def _mac(data: bytes) -> bytes:
    if _root is not None:
        digest = hmac.HMAC(_root, hashes.SHA256())
        digest.update(data)
        return digest.finalize()
    name = os.environ.get(_KMS_ENV, "").strip()
    if not name:
        raise RuntimeError(f"{_KMS_ENV} is required")
    response = _kms().mac_sign(request={"name": name, "data": data})
    mac = bytes(response.mac)
    if len(mac) != 32:
        raise RuntimeError("KMS MAC was not 32 bytes")
    return mac


def require_root() -> None:
    if _root is not None:
        return
    _mac(b"saturn-kms-probe")


def mlkem_seed(organization_id: str, user_id: str = "") -> bytes:
    if not organization_id:
        raise RuntimeError("organization id is required")
    label = f"saturn-mlkem-v1\n{organization_id}\n{user_id}\n".encode()
    return _mac(label + b"0") + _mac(label + b"1")


def _kms():
    global _kms_client
    if _kms_client is None:
        from google.cloud import kms

        _kms_client = kms.KeyManagementServiceClient()
    return _kms_client


def content_key(organization_id: str) -> bytes:
    if not organization_id:
        raise RuntimeError("organization id is required")
    now = time.monotonic()
    with _cache_lock:
        cached = _content_keys.get(organization_id)
    if cached is not None and cached[0] > now:
        return cached[1]
    return _derive_content_key(organization_id)


def _derive_content_key(organization_id: str) -> bytes:
    value = _mac(f"saturn-org-content-v2\n{organization_id}".encode())
    with _cache_lock:
        _content_keys[organization_id] = (time.monotonic() + _CONTENT_TTL_SECONDS, value)
    return value


async def content_key_async(organization_id: str) -> bytes:
    return await asyncio.to_thread(content_key, organization_id)


async def warm_content_key(organization_id: str) -> None:
    """Have the organization's content key cached before a request starts sealing with it.

    Sealing, opening and digests read the key synchronously, in many places. A KMS call made
    there would hold the event loop, and every other request, for as long as KMS takes. Calling
    this once where the request learns its organization moves that wait onto a worker thread;
    the synchronous readers then find the key in the cache. A failure is left for the code that
    needs the key to report.
    """
    if not organization_id:
        return
    with _cache_lock:
        cached = _content_keys.get(organization_id)
    if cached is not None and cached[0] > time.monotonic() + _WARM_MARGIN_SECONDS:
        return
    try:
        await asyncio.to_thread(_derive_content_key, organization_id)
    except Exception as exc:
        logger.warning("content key not warmed: %s", type(exc).__name__)


async def open_secret_async(token: str, organization_id: str, user_id: str = "", context: str | None = None) -> str:
    return await asyncio.to_thread(open_secret, token, organization_id, user_id, context)


async def seal_async(plain: str, organization_id: str, user_id: str = "", context: str = "") -> str:
    return await asyncio.to_thread(seal, plain, organization_id, user_id, context)


def bound_aad(context: str) -> bytes:
    return _AAD_LABEL + context.encode()


def split_bound(token: str) -> tuple[str, str] | None:
    """(context, base64 blob) of a pq3 value, or None if it is not one."""
    if not token.startswith(_BOUND_PREFIX):
        return None
    head, _, blob = token[len(_BOUND_PREFIX) :].partition(".")
    if not head or not blob:
        return None
    try:
        context = base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)).decode()
    except Exception:
        return None
    return context, blob


def join_bound(context: str, blob: str) -> str:
    head = base64.urlsafe_b64encode(context.encode()).decode().rstrip("=")
    return f"{_BOUND_PREFIX}{head}.{blob}"


def unbound_secrets_allowed() -> bool:
    """pq2 values carry no context. Accepted until SATURN_REQUIRE_BOUND_SECRETS is set after a reseal."""
    return os.environ.get("SATURN_REQUIRE_BOUND_SECRETS", "").strip().lower() not in {"1", "true", "yes"}


def _private(organization_id: str, user_id: str) -> MLKEM1024PrivateKey:
    cache_key = ("mlkem", organization_id, user_id)
    with _cache_lock:
        found = _keys.get(cache_key)
    if found is not None:
        return found
    # Two threads may both derive the same key; the result is identical, so the second one wins harmlessly.
    found = MLKEM1024PrivateKey.from_seed_bytes(mlkem_seed(organization_id, user_id))
    with _cache_lock:
        # Bounded, oldest first out, so a process never holds every tenant's key it has ever used.
        while len(_keys) >= _MAX_CACHED_KEYS and cache_key not in _keys:
            _keys.pop(next(iter(_keys)))
        _keys[cache_key] = found
    return found


def seal(plain: str, organization_id: str, user_id: str = "", context: str = "") -> str:
    """Seal for this tenant. With a context, the value only opens where that context is expected."""
    if not plain:
        return ""
    public = _private(organization_id, user_id).public_key()
    shared, kem_ciphertext = public.encapsulate()
    key = _hkdf(shared, _INFO_AES, 32)
    nonce = os.urandom(12)
    encrypted = AESGCM(key).encrypt(nonce, plain.encode(), bound_aad(context) if context else None)
    blob = base64.b64encode(kem_ciphertext + nonce + encrypted).decode()
    return join_bound(context, blob) if context else _PREFIX + blob


def open_secret(token: str, organization_id: str, user_id: str = "", context: str | None = None) -> str:
    """Open a sealed value. Pass the context the caller expects; a value sealed for another refuses.

    SecretNeedsReconnect means the stored value is no good. KeyUnavailable means try again later.
    """
    if not token or not organization_id:
        return ""
    bound = split_bound(token)
    if bound is not None:
        sealed_for, blob = bound
        if context is not None and sealed_for != context:
            logger.warning("sealed value opened in the wrong place")
            raise SecretNeedsReconnect()
        aad: bytes | None = bound_aad(sealed_for)
    elif token.startswith(_LEGACY_PREFIX) or not token.startswith(_PREFIX):
        raise SecretNeedsReconnect()
    else:
        if context and not unbound_secrets_allowed():
            raise SecretNeedsReconnect()
        blob, aad = token[len(_PREFIX) :], None
    try:
        private = _private(organization_id, user_id)
    except Exception as exc:
        logger.warning("tenant key unavailable: %s", type(exc).__name__)
        raise KeyUnavailable() from exc
    try:
        raw = base64.b64decode(blob)
        kem_ciphertext, rest = raw[:1568], raw[1568:]
        nonce, encrypted = rest[:12], rest[12:]
        shared = private.decapsulate(kem_ciphertext)
        key = _hkdf(shared, _INFO_AES, 32)
        return AESGCM(key).decrypt(nonce, encrypted, aad).decode()
    except SecretNeedsReconnect:
        raise
    except Exception as exc:
        logger.warning("credential open failed: %s", type(exc).__name__)
        raise SecretNeedsReconnect() from exc
