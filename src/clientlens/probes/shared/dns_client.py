"""DNS resolution helpers.

DNS answers here are treated as ground truth: whatever the resolver returns is
what we report, with the raw record as evidence. We never infer beyond it.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import UTC

import dns.asyncresolver
import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver

log = logging.getLogger("clientlens.dns")

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA", "SRV")

# Public resolvers used as a fallback chain. All free, no key.
RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


@dataclass
class DnsAnswer:
    name: str
    rtype: str
    values: list[str] = field(default_factory=list)
    ttl: int | None = None
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error

    @property
    def present(self) -> bool:
        return bool(self.values) and not self.error


@dataclass
class DnsSnapshot:
    answers: dict[str, DnsAnswer] = field(default_factory=dict)

    def get(self, rtype: str) -> DnsAnswer | None:
        return self.answers.get(rtype)

    def values(self, rtype: str) -> list[str]:
        a = self.answers.get(rtype)
        return list(a.values) if a else []

    def txt_joined(self, rtype: str = "TXT") -> list[str]:
        return ["".join(v.split()) if isinstance(v, str) else v for v in self.values(rtype)]


def _resolver() -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver()
    r.lifetime = 8.0
    r.timeout = 4.0
    return r


async def resolve_record(name: str, rtype: str) -> DnsAnswer:
    """Resolve one record type. Never raises — errors land in ``error``."""
    answer = DnsAnswer(name=name, rtype=rtype)
    resolvers = [_resolver()]
    for ip in RESOLVERS:
        r = _resolver()
        r.nameservers = [ip]
        resolvers.append(r)

    last_err = ""
    for resolver in resolvers:
        try:
            found = await resolver.resolve(name, rtype, raise_on_no_answer=False, search=False)
            if found is None or found.rrset is None:
                answer.values = []
                answer.error = ""
                return answer
            values = []
            for rr in found.rrset:
                text = rr.to_text().strip()
                if text.startswith('"') and text.endswith('"'):
                    text = text[1:-1]
                values.append(text)
            answer.values = values
            answer.ttl = found.rrset.ttl
            answer.error = ""
            return answer
        except dns.resolver.NXDOMAIN:
            answer.values = []
            answer.error = "NXDOMAIN"
            return answer
        except dns.resolver.NoAnswer:
            answer.values = []
            answer.error = ""
            return answer
        except dns.resolver.NoNameservers as exc:
            last_err = f"NoNameservers: {exc}"
        except dns.exception.Timeout:
            last_err = "Timeout"
        except Exception as exc:  # noqa: BLE001
            last_err = f"{type(exc).__name__}: {exc}"

    answer.error = last_err or "resolution failed"
    return answer


async def resolve_all(name: str, record_types: tuple[str, ...] = RECORD_TYPES) -> DnsSnapshot:
    """Resolve all requested record types concurrently."""
    snapshot = DnsSnapshot()
    results = await asyncio.gather(
        *(resolve_record(name, rt) for rt in record_types),
        return_exceptions=False,
    )
    for res in results:
        snapshot.answers[res.rtype] = res
    return snapshot


async def resolve_a(name: str) -> list[str]:
    """Convenience: A + AAAA addresses."""
    snap = await resolve_all(name, ("A", "AAAA"))
    return snap.values("A") + snap.values("AAAA")


async def resolve_txt_at(name: str) -> list[str]:
    """Resolve TXT records and normalise multi-string TXT chunks."""
    ans = await resolve_record(name, "TXT")
    return [_normalize_txt(v) for v in ans.values]


def _normalize_txt(value: str) -> str:
    # dnspython may return quoted chunks joined by spaces for long TXT.
    return value.replace('" "', "").strip()


async def resolve_mx(name: str) -> list[tuple[int, str]]:
    ans = await resolve_record(name, "MX")
    out: list[tuple[int, str]] = []
    for v in ans.values:
        parts = v.split()
        if len(parts) >= 2:
            try:
                pref = int(parts[0])
            except ValueError:
                pref = 0
            out.append((pref, parts[1].rstrip(".")))
    return sorted(out)


def lookup_certificate_names(hostname: str, port: int = 443) -> dict:
    """Synchronous TLS handshake capture.

    Kept synchronous (and wrapped in a thread by the engine) because the stdlib
    ``ssl`` module is blocking. Returns the certificate fields we care about
    plus the negotiated protocol — both are directly observed facts.
    """
    import socket
    import ssl
    from datetime import datetime

    result: dict = {
        "hostname": hostname,
        "port": port,
        "protocol": "",
        "cipher": "",
        "certificate": {},
        "chain_length": 0,
        "error": "",
    }

    ctx = ssl.create_default_context()
    try:
        with (
            socket.create_connection((hostname, port), timeout=8.0) as sock,
            ctx.wrap_socket(sock, server_hostname=hostname) as tls,
        ):
            result["protocol"] = tls.version() or ""
            cipher = tls.cipher()
            result["cipher"] = cipher[0] if cipher else ""
            cert = tls.getpeercert()
            der = tls.getpeercert(binary_form=True)
            result["certificate"] = _parse_cert(cert)
            result["certificate_der_sha256"] = _sha256(der) if der else ""
            try:
                result["chain_length"] = 1 + len(tls.getpeercert_chain() or [])
            except Exception:  # noqa: BLE001
                result["chain_length"] = 1
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    cert = result["certificate"]
    not_after = cert.get("notAfter")
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
            result["days_until_expiry"] = (exp - datetime.now(UTC)).days
        except Exception:  # noqa: BLE001
            result["days_until_expiry"] = None
    return result


def _parse_cert(cert: dict) -> dict:
    """Flatten the stdlib cert dict into plain serialisable fields."""

    def _names(entries) -> list[str]:
        out: list[str] = []
        for entry in entries or []:
            for kind, value in entry:
                if kind == "commonName":
                    out.append(value)
        return out

    subject = _names(cert.get("subject"))
    issuer = _names(cert.get("issuer"))
    sans: list[str] = []
    for kind, value in cert.get("subjectAltName", ()) or ():
        if kind == "DNS":
            sans.append(value)

    return {
        "subject_cn": subject[0] if subject else "",
        "issuer_cn": issuer[0] if issuer else "",
        "not_before": cert.get("notBefore", ""),
        "not_after": cert.get("notAfter", ""),
        "serial_number": cert.get("serialNumber", ""),
        "subject_alt_names": sans,
        "version": cert.get("version"),
    }


def _sha256(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()
