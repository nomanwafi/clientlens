"""Target parsing and normalisation.

Only what ClientLens is authorised to scan is ever scanned. The parser is
strict on purpose: a mangled target must fail loudly rather than silently
scan the wrong host.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

import tldextract

from .exceptions import InvalidTarget
from .models import ScanTarget

# Hostnames: letters/digits/hyphen labels, optional trailing dot, optional port.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)

# Loose private/loopback/link-local checks we refuse to scan without override.
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def normalize_target(raw: str, *, allow_private: bool = False) -> ScanTarget:
    """Turn user input into a :class:`ScanTarget`.

    Accepts ``example.com``, ``www.example.com``, ``https://example.com/path``,
    ``example.com:8443``. Rejects anything that is not a hostname or public IP.
    """
    if not raw or not raw.strip():
        raise InvalidTarget("empty target")

    candidate = raw.strip()

    # Reject scheme-less strings that contain whitespace or shell metacharacters.
    if re.search(r"[\s\\;|&$`<>\"']", candidate):
        raise InvalidTarget(f"target contains illegal characters: {raw!r}")

    has_scheme = "://" in candidate
    if not has_scheme:
        candidate = "https://" + candidate

    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise InvalidTarget(f"unsupported scheme {parsed.scheme!r} (use http or https)")

    host = parsed.hostname
    if not host:
        raise InvalidTarget(f"could not extract hostname from {raw!r}")

    host = host.rstrip(".").lower()

    # Literal IP target?
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is not None:
        if not allow_private and any(ip in net for net in _PRIVATE_NETWORKS):
            raise InvalidTarget(
                f"{host} is a private/loopback address; pass --allow-private to scan it"
            )
        return ScanTarget(
            raw=raw,
            domain=host,
            apex=host,
            scheme=parsed.scheme,
            base_url=f"{parsed.scheme}://{host}",
            resolved_ips=[host],
        )

    if not _HOSTNAME_RE.match(host):
        raise InvalidTarget(f"not a valid hostname: {host!r}")

    ext = tldextract.extract(host)
    if not ext.suffix:
        raise InvalidTarget(
            f"{host!r} has no public suffix — is it a local/internal name? "
            "Use --allow-private if you really mean it."
        )
    if not ext.domain:
        raise InvalidTarget(f"could not determine registrable domain for {host!r}")

    apex = f"{ext.domain}.{ext.suffix}"
    return ScanTarget(
        raw=raw,
        domain=host,
        apex=apex,
        scheme=parsed.scheme,
        base_url=f"{parsed.scheme}://{host}",
    )


def is_private_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in net for net in _PRIVATE_NETWORKS)
