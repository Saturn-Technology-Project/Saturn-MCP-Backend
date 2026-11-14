from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import HTTPException, status

# Marketplace MCP hosts. A connection must use HTTPS and one of these names.
ALLOWED_MCP_HOSTS = frozenset(
    {
        "gmailmcp.googleapis.com",
        "calendarmcp.googleapis.com",
        "mcp.mercury.com",
        "mcp.ether.fi",
        "agents.coinbase.com",
        "api.ibkr.com",
        "mcp.dukascopy.com",
        "mcp.app.carta.com",
        "mcp.twelvedata.com",
        "mcp.factset.com",
        "mcp.financialdatasets.ai",
        "api.sec-api.io",
        "finance.foundation",
        "mcp.ramp.com",
        "api.brex.com",
        "mcp.xero.com",
        "seekingalpha.com",
        "api.githubcopilot.com",
        "mcp.notion.com",
        "mcp.linear.app",
        "mcp.stripe.com",
        "mcp.atlassian.com",
        "mcp.sentry.dev",
        "mcp.context7.com",
        "mcp.deepwiki.com",
        "huggingface.co",
        "mcp.neon.tech",
        "mcp.supabase.com",
    }
)

_METADATA_HOSTS = frozenset({"metadata.google.internal", "metadata.google.com"})
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_BLOCKED_V4 = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("240.0.0.0/4"),
    # Azure's wire server: a public-looking address that answers only from inside a VM, like the
    # link-local metadata address.
    ipaddress.ip_network("168.63.129.16/32"),
)


def addresses_for(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MCP endpoint could not be resolved") from exc
    return [item[4][0] for item in infos]


def address_blocked(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.version == 6:
        # IPv6 forms that carry an IPv4 address: a NAT64 gateway or a 6to4/Teredo relay would
        # turn them back into that IPv4 address, internal ones included.
        embedded = None
        if address in _NAT64:
            embedded = ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
        elif address.sixtofour is not None:
            embedded = address.sixtofour
        elif address.teredo is not None:
            embedded = address.teredo[1]
        if embedded is not None:
            return True
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        # fec0::/10, the retired site-local range. Not in is_private, still routed inside some networks.
        or (address.version == 6 and address.is_site_local)
    ):
        return True
    return address.version == 4 and any(address in network for network in _BLOCKED_V4)


def require_mcp_endpoint(url: str) -> str:
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower().rstrip(".")
    if parts.scheme != "https" or not host or parts.username or parts.password:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MCP endpoint must be HTTPS")
    try:
        ipaddress.ip_address(host)
        literal_ip = True
    except ValueError:
        literal_ip = False
    if literal_ip or host in _METADATA_HOSTS or host not in ALLOWED_MCP_HOSTS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MCP endpoint host is not approved")
    try:
        port = parts.port or 443
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MCP endpoint must be HTTPS") from exc
    if port != 443:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MCP endpoint must use port 443")
    found = addresses_for(host, port)
    if not found or any(address_blocked(item) for item in found):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MCP endpoint address is not allowed")
    return url.strip()


# Query parameter names that carry a credential, compared without case, "-" or "_".
_CREDENTIAL_PARAMS = frozenset(
    {
        "apikey",
        "key",
        "token",
        "accesstoken",
        "apitoken",
        "authtoken",
        "auth",
        "authorization",
        "secret",
        "clientsecret",
        "password",
        "accesskey",
        "signature",
        "sig",
    }
)


# A name that ends in one of these carries a credential too: x-api-key, subscription-key, id_token.
_CREDENTIAL_SUFFIXES = (
    "key",
    "token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "signature",
    "auth",
    "authorization",
    "credential",
    "credentials",
    "jwt",
    "bearer",
)


def _param_name(name: str) -> str:
    return re.sub(r"[-_.]", "", name).lower()


def credential_param(name: str) -> bool:
    """Whether a query parameter with this name holds a credential."""
    cleaned = _param_name(name)
    return cleaned in _CREDENTIAL_PARAMS or cleaned.endswith(_CREDENTIAL_SUFFIXES)


def split_url_credential(url: str) -> tuple[str, str]:
    """The URL without credential query parameters, and the credential it carried ("" if none).

    An endpoint is stored and shown to every member who can see connections, so a key never stays
    in it. A URL that carries more than one distinct credential is refused.
    """
    parts = urlsplit(url.strip())
    if not parts.query:
        return url.strip(), ""
    kept: list[tuple[str, str]] = []
    found: set[str] = set()
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        if credential_param(name):
            if value:
                found.add(value)
            continue
        kept.append((name, value))
    if len(found) > 1:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Put the API key in the authorization field, not the URL")
    clean = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(kept), parts.fragment))
    return clean, next(iter(found), "")


def pin_mcp_url(url: str) -> tuple[str, str]:
    """Resolve the endpoint once, check every address, and return (url on that IP, host name).

    The request then connects to the address that was checked, with Host and SNI set to the name.
    Resolving again at connect time would let a DNS answer change in between and reach an
    internal address.
    """
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().rstrip(".")
    found = addresses_for(host, parts.port or 443)
    if not found or any(address_blocked(item) for item in found):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MCP endpoint address is not allowed")
    address = found[0]
    netloc = f"[{address}]" if ":" in address else address
    if parts.port and parts.port != 443:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, "")), host
