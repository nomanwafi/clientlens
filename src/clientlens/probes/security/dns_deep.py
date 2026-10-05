"""DNSSEC and www-canonicalisation checks.

DNSSEC state is read from the DNSKEY/DS records — directly observed. The
www/non-www behaviour is observed from the redirect chain.
"""

from __future__ import annotations

from ...core.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    FindingKind,
    Severity,
)
from ...core.registry import ProbeContext, ProbeMode, ProbePhase, register_probe
from ..shared.dns_client import resolve_record


@register_probe(
    id="security.dns.dnssec",
    category=Category.SECURITY,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    title="DNSSEC signing",
    description="Whether the domain publishes DNSSEC keys and the parent has a DS record.",
    tags=("dns", "dnssec", "integrity"),
)
async def check_dnssec(ctx: ProbeContext) -> list[Finding]:
    """Check DNSKEY (zone signing) and DS (parent chain of trust)."""
    findings: list[Finding] = []
    apex = ctx.target.apex

    dnskey = await resolve_record(apex, "DNSKEY")
    ds = await resolve_record(apex, "DS")
    source = f"DNS {apex}"

    has_dnskey = dnskey.present
    has_ds = ds.present

    if has_dnskey and has_ds:
        findings.append(
            Finding(
                id="security.dnssec.signed",
                title="Zone is DNSSEC-signed (DNSKEY + DS present)",
                category=Category.SECURITY,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(
                    f"DNSKEY: {len(dnskey.values)} key(s)\nDS: {len(ds.values)} record(s)",
                    source=source,
                ),
                reasoning=(
                    "The zone publishes signing keys and the parent zone holds a DS "
                    "record, so resolvers can validate that DNS answers were not "
                    "tampered with in transit. DNS spoofing of this domain becomes "
                    "materially harder."
                ),
                scope=f"DNSKEY/DS records for {apex}",
                tags=["dns", "dnssec", "strength"],
            )
        )
    elif has_dnskey and not has_ds:
        findings.append(
            Finding(
                id="security.dnssec.unsigned_at_parent",
                title="Zone is signed but the parent has no DS record",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(
                    f"DNSKEY: present ({len(dnskey.values)})\nDS: (absent)",
                    source=source,
                ),
                reasoning=(
                    "The zone publishes DNSKEY but the parent zone has no DS record, "
                    "so the chain of trust is broken at the delegation point. "
                    "Validating resolvers treat the zone as unsigned — the signing "
                    "work is done but delivers no protection."
                ),
                scope=f"DNSKEY/DS records for {apex}",
                remediation="Submit the DS record to the registrar so the parent signs the delegation.",
                tags=["dns", "dnssec"],
            )
        )
    else:
        findings.append(
            Finding(
                id="security.dnssec.unsigned",
                title="Zone is not DNSSEC-signed",
                category=Category.SECURITY,
                kind=FindingKind.OBSERVATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(
                    f"DNSKEY: {'present' if has_dnskey else 'absent'}\nDS: {'present' if has_ds else 'absent'}",
                    source=source,
                ),
                reasoning=(
                    "Without DNSSEC, a resolver has no cryptographic way to know a "
                    "DNS answer is authentic. A cache-poisoning or on-path attack "
                    "can silently redirect mail and web traffic. Most modern "
                    "registrars offer one-click signing."
                ),
                scope=f"DNSKEY/DS records for {apex}",
                remediation="Enable DNSSEC at the DNS provider and registrar.",
                tags=["dns", "dnssec"],
            )
        )

    return findings


@register_probe(
    id="security.dns.www_redirect",
    category=Category.SECURITY,
    mode=ProbeMode.ACTIVE,
    phase=ProbePhase.ACTIVE,
    requires=("http_response",),
    title="www / non-www canonicalisation",
    description="Whether both host variants resolve and one redirects to the other.",
    tags=("dns", "canonical", "seo", "redirects"),
)
async def check_www_redirect(ctx: ProbeContext) -> list[Finding]:
    """Check how www.<domain> and the bare domain relate."""
    findings: list[Finding] = []
    target = ctx.target
    http = ctx.http_client

    if target.domain.startswith("www."):
        other = target.domain[4:]
        primary = target.domain
    else:
        other = f"www.{target.domain}"
        primary = target.domain

    # Resolve both.
    from ..shared.dns_client import resolve_a

    other_ips = await resolve_a(other)

    if not other_ips:
        findings.append(
            Finding(
                id="security.www.no_dns",
                title=f"{other} has no DNS record",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(f"{other}: no A/AAAA record", source=f"DNS {other}"),
                reasoning=(
                    f"Visitors who type {other} get a resolution failure instead of "
                    "the site. This is the most common 'the site is down' report "
                    "that is not actually an outage."
                ),
                scope=f"DNS {other}",
                remediation=f"Add a CNAME or A record for {other} pointing at {primary}.",
                tags=["dns", "canonical", "seo"],
            )
        )
        return findings

    # Fetch the other variant and see where it lands.
    other_url = f"https://{other}/"
    resp = await http.get(other_url, follow=True)

    if resp.error:
        findings.append(
            Finding(
                id="security.www.unreachable",
                title=f"{other} resolves but does not serve HTTPS",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(resp.error, source=other_url),
                reasoning=(
                    f"{other} resolves to {', '.join(other_ips[:4])} but no TLS "
                    "endpoint answers. Visitors to the alternate hostname see an "
                    "error."
                ),
                scope=f"GET {other_url}",
                remediation=f"Configure {other} to serve or redirect to {primary}.",
                tags=["dns", "canonical"],
            )
        )
        return findings

    final_host = resp.final_url.split("//", 1)[-1].split("/", 1)[0]
    canonical = final_host == primary

    if canonical:
        findings.append(
            Finding(
                id="security.www.canonicalised",
                title=f"{other} redirects to the canonical {primary}",
                category=Category.SECURITY,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(
                    f"{other} -> {resp.final_url} ({resp.status})",
                    source=f"GET {other_url}",
                ),
                reasoning=(
                    "One canonical hostname is in use and the other variant "
                    "redirects to it. Ranking signals consolidate on one host."
                ),
                scope=f"GET {other_url}",
                tags=["dns", "canonical", "seo", "strength"],
            )
        )
    else:
        findings.append(
            Finding(
                id="security.www.duplicate_content",
                title=f"Both {primary} and {other} serve content without redirecting",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(
                    f"{other} -> {resp.final_url} ({resp.status})",
                    source=f"GET {other_url}",
                ),
                reasoning=(
                    "Both hostnames serve the site. Search engines treat them as "
                    "duplicate content and split ranking signals between them. "
                    "Cookie scope and referrer behaviour also differ by host."
                ),
                scope=f"GET {other_url}",
                remediation=(
                    "Pick one canonical host and 301 the other to it. Also set a "
                    "canonical link on every page."
                ),
                tags=["dns", "canonical", "seo"],
            )
        )

    return findings
