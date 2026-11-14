import hashlib
import hmac
import ipaddress
import os
import time
from collections import defaultdict

from fastapi import Request

from app.core.config import get_settings

WINDOW_SECONDS = 600
MAX_HITS = 20
_PRUNE_EVERY = 1024

_hits: dict[str, list[float]] = defaultdict(list)
_calls = 0
_redis = None

# Give one hit back, never below zero and never creating the key.
_DECR_FLOOR = """
local count = tonumber(redis.call('GET', KEYS[1]) or '0')
if count > 0 then
  return redis.call('DECR', KEYS[1])
end
return 0
"""

# INCR and EXPIRE in one step, so a key can never be left without a TTL.
_INCR_WITH_TTL = """
local count = redis.call('INCR', KEYS[1])
if redis.call('TTL', KEYS[1]) < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
"""


def behind_cloudflare() -> bool:
    """CF-Connecting-IP is only meaningful when every request must carry the Cloudflare origin secret."""
    return bool(os.environ.get("ORIGIN_AUTH_SECRET", "").strip())


CONSOLE_AUTH_HEADER = "x-saturn-console-auth"
CONSOLE_CLIENT_IP_HEADER = "x-saturn-client-ip"


def _console_secret_ok(presented: str) -> bool:
    accepted = [
        os.environ.get("CONSOLE_PROXY_SECRET", "").strip(),
        os.environ.get("CONSOLE_PROXY_SECRET_PREVIOUS", "").strip(),
    ]
    digest = hashlib.sha256(presented.encode()).digest()
    return any(hmac.compare_digest(digest, hashlib.sha256(value.encode()).digest()) for value in accepted if value)


def console_client_ip(request: Request) -> str:
    """The browser's address as the console proxy reported it, or "" when it cannot be trusted.

    Every console request reaches the API from the console's own address, so Cloudflare's
    CF-Connecting-IP names the console, not the browser. The console sends the browser's address
    with a secret only it holds; without that secret the header is ignored.
    """
    presented = request.headers.get(CONSOLE_AUTH_HEADER, "")
    if not presented or not _console_secret_ok(presented):
        return ""
    value = request.headers.get(CONSOLE_CLIENT_IP_HEADER, "").strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""


def client_ip(request: Request) -> str:
    """The address used for rate limits and throttles.

    The console proxy's report wins when its secret matches. Cloudflare overwrites CF-Connecting-IP, so it
    is trusted only when origin auth proves the request came through Cloudflare. Otherwise the rightmost
    X-Forwarded-For entry is the one the nearest proxy appended. Any value a client chose itself is never used.
    """
    console = console_client_ip(request)
    if console:
        return console
    if behind_cloudflare():
        cf_ip = request.headers.get("cf-connecting-ip", "").strip()
        if cf_ip:
            return cf_ip
    forwarded = request.headers.get("x-forwarded-for", "")
    parts = [part.strip() for part in forwarded.split(",") if part.strip()]
    if parts:
        return parts[-1]
    if request.client is not None and request.client.host:
        return request.client.host
    return "unknown"


def limit_address(request: Request) -> str:
    """The address a limit is counted against.

    One IPv6 customer is normally given a whole /64, and can pick any of its 2^64 addresses per
    request. Counting each address separately would give them unlimited buckets, so IPv6 is
    counted per /64. An IPv4 address written as IPv6 is counted as that IPv4 address.
    """
    value = client_ip(request)
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    if address.version == 4:
        return str(address)
    if address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return f"{ipaddress.ip_network(f'{address}/64', strict=False).network_address}/64"


def _use_redis() -> bool:
    settings = get_settings()
    return bool(settings.redis_url) and not settings.in_process_runtime


def _redis_client():
    global _redis
    if _redis is None:
        import redis.asyncio as redis_async

        # Asynchronous, so a slow Redis delays only the request that is waiting for it. The
        # synchronous client this replaced stopped the whole event loop for up to its timeout.
        # The timeouts stay short: a limiter that cannot answer refuses, and should do so quickly.
        _redis = redis_async.Redis.from_url(
            get_settings().redis_url,
            socket_timeout=0.5,
            socket_connect_timeout=0.5,
        )
    return _redis


def _prune(now: float, window: int) -> None:
    for key in list(_hits):
        kept = [stamp for stamp in _hits[key] if now - stamp < max(window, WINDOW_SECONDS)]
        if kept:
            _hits[key] = kept
        else:
            del _hits[key]


def _memory_allow(key: str, *, limit: int, window: int) -> bool:
    global _calls
    now = time.monotonic()
    _calls += 1
    if _calls % _PRUNE_EVERY == 0:
        _prune(now, window)
    bucket = [stamp for stamp in _hits[key] if now - stamp < window]
    if len(bucket) >= limit:
        _hits[key] = bucket
        return False
    bucket.append(now)
    _hits[key] = bucket
    return True


async def _redis_allow(key: str, *, limit: int, window: int) -> bool:
    client = _redis_client()
    count = int(await client.eval(_INCR_WITH_TTL, 1, f"saturn:rate:{key}", int(window)))
    return count <= limit


def _memory_count(key: str, window: int) -> int:
    now = time.monotonic()
    return sum(1 for stamp in _hits.get(key, []) if now - stamp < window)


async def under_limit(key: str, *, limit: int, window: int = WINDOW_SECONDS) -> bool:
    """Whether key has fewer than limit hits in the window, without adding one."""
    if _use_redis():
        try:
            raw = await _redis_client().get(f"saturn:rate:{key}")
            return int(raw or 0) < limit
        except Exception:
            return False
    if not get_settings().in_process_runtime:
        return False
    return _memory_count(key, window) < limit


async def allow(key: str, *, limit: int = MAX_HITS, window: int = WINDOW_SECONDS) -> bool:
    if _use_redis():
        try:
            return await _redis_allow(key, limit=limit, window=window)
        except Exception:
            return False
    if not get_settings().in_process_runtime:
        return False
    return _memory_allow(key, limit=limit, window=window)


async def release(key: str) -> None:
    """Hand back one hit that allow() counted. Used when the attempt turned out not to be a failure."""
    if _use_redis():
        try:
            await _redis_client().eval(_DECR_FLOOR, 1, f"saturn:rate:{key}")
        except Exception:  # noqa: S110
            # The hit stays counted and expires with its window: the safe direction.
            pass
        return
    bucket = _hits.get(key)
    if bucket:
        bucket.pop()


async def registration_allowed(request: Request) -> bool:
    return await allow(f"oauth-register:{limit_address(request)}")


async def signup_allowed(request: Request) -> bool:
    """Account sign-up. Its own budget, so agent client registrations cannot use it up."""
    return await allow(f"signup:{limit_address(request)}")


LOGIN_ACCOUNT_FAILURES = 10


async def login_allowed(request: Request, email: str | None = None) -> bool:
    """Whether this sign-in attempt may go ahead. With an email, it also takes one of the account's slots.

    Per account, so rotating addresses does not give unlimited guesses against one user. The slot
    is taken here, before the password is checked: counting a failure only afterwards let every
    request that was already in flight through, so a burst of guesses passed a limit of ten.
    A correct password gives its slot back (login_succeeded), so an owner who signs in often is
    never locked out.
    """
    if not await allow(f"login:{limit_address(request)}"):
        return False
    if not (email or "").strip():
        return True
    return await allow(_login_account_key(email), limit=LOGIN_ACCOUNT_FAILURES)


def _login_account_key(email: str) -> str:
    return f"login-account:{email.strip().lower()}"


async def login_succeeded(email: str | None) -> None:
    """The password was right, or the attempt failed for a reason that was not a wrong password."""
    if email:
        await release(_login_account_key(email))


async def migration_allowed(request: Request, email: str | None = None) -> bool:
    if not await allow(f"login-migration:{limit_address(request)}", limit=24):
        return False
    if email is None:
        return True
    # It answers whether a legacy password is right, so it gets the same per-account cap as sign-in.
    return await allow(f"login-migration-account:{email.strip().lower()}", limit=10)


async def code_check_allowed(request: Request, subject: str | None = None) -> bool:
    """Checking an emailed, reset or authenticator code. Per address, and per account when known.

    Each code is also capped at a few guesses; this stops one address from spreading guesses
    over many codes and accounts.
    """
    if not await allow(f"code-check:{limit_address(request)}", limit=30):
        return False
    if not subject:
        return True
    return await allow(f"code-check-account:{subject.strip().lower()}", limit=15)


# Wrong emailed sign-in codes one account may collect in a day, across every challenge and
# address. Each code already allows only a few guesses, but a new code can be requested once
# those are spent, and whoever is guessing already has the password.
LOGIN_CODE_DAILY_FAILURES = 30
_DAY_SECONDS = 86_400


async def login_code_open(user_id: str) -> bool:
    return await under_limit(f"login-code-fail:{user_id}", limit=LOGIN_CODE_DAILY_FAILURES, window=_DAY_SECONDS)


async def login_code_failed(user_id: str) -> None:
    await allow(f"login-code-fail:{user_id}", limit=LOGIN_CODE_DAILY_FAILURES * 10, window=_DAY_SECONDS)


async def reauth_allowed(user_id: str) -> bool:
    return await allow(f"reauth:{user_id}", limit=8, window=900)


async def accept_invite_allowed(request: Request) -> bool:
    return await allow(f"accept-invite:{limit_address(request)}", limit=20)


def reset() -> None:
    global _redis, _calls
    _hits.clear()
    _calls = 0
    _redis = None
