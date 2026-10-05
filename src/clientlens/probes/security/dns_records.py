"""DNS posture checks.

DNS answers are reported verbatim. We flag configuration gaps that are
verifiable from public data (missing CAA, missing MX where mail is expected)
and never speculate about what a record "probably" means.
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


@register_probe(
    id="security.dns",
    category=Category.SECURITY,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("dns",),
    title="DNS records & delegation",
    description="Record inventory and verifiable configuration gaps (CAA, MX, NS).",
    tags=("dns", "infrastructure"),
)
async def check_dns(ctx: ProbeContext) -> list[Finding]:
    """Review the DNS snapshot captured for the target."""
    snap = ctx.require("dns")
    findings: list[Finding] = []
    target = ctx.target
    source = f"DNS {target.domain}"

    # ---- inventory ---------------------------------------------------------
    inventory_lines = []
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA"):
        ans = snap.get(rtype)
        if ans is None:
            continue
        values = ans.values or (["(none)"] if not ans.error else [f"(error: {ans.error})"])
        inventory_lines.append(f"{rtype}: " + ", ".join(values[:10]))
    inventory = Evidence.text("\n".join(inventory_lines), summary="DNS inventory", source=source)

    findings.append(
        Finding(
            id="security.dns.inventory",
            title=f"DNS record inventory for {target.apex}",
            category=Category.SECURITY,
            kind=FindingKind.OBSERVATION,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            evidence=inventory,
            reasoning=(
                "Public DNS data for the apex domain. This is the delegation "
                "footprint any external party can see."
            ),
            scope=f"Public DNS for {target.apex}",
            tags=["dns", "inventory"],
        )
    )

    # ---- CAA ---------------------------------------------------------------
    caa = snap.get("CAA")
    if caa is None or caa.error == "NXDOMAIN":
        pass  # domain doesn't exist; nothing to say about CAA
    elif not caa.present:
        findings.append(
            Finding(
                id="security.dns.caa_missing",
                title="No CAA records published",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.dns_record(target.apex, "CAA", []),
                reasoning=(
                    "Without CAA, any certificate authority in the browser trust "
                    "store is permitted to issue a certificate for this domain. CAA "
                    "does not stop a determined attacker but it constrains "
                    "mis-issuance and is required by the CA/Browser Forum baseline."
                ),
                scope=f"CAA records for {target.apex}",
                remediation=(
                    f"Publish CAA records restricting issuance to your actual CA, e.g.\n"
                    f'  {target.apex}.  IN  CAA  0 issue "letsencrypt.org"'
                ),
                tags=["dns", "caa", "pki"],
            )
        )
    else:
        findings.append(
            Finding(
                id="security.dns.caa_present",
                title="CAA records published",
                category=Category.SECURITY,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.dns_record(target.apex, "CAA", caa.values),
                reasoning="Certificate issuance is restricted to the listed CAs.",
                scope=f"CAA records for {target.apex}",
                tags=["dns", "caa", "strength"],
            )
        )

    # ---- MX ----------------------------------------------------------------
    mx = snap.get("MX")
    has_txt_spf = any("v=spf1" in v for v in snap.txt_joined("TXT"))
    if mx and not mx.present and has_txt_spf:
        findings.append(
            Finding(
                id="security.dns.mx_missing_but_spf_present",
                title="SPF record exists but no MX record",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.dns_record(target.apex, "MX", []),
                reasoning=(
                    "An SPF policy is published but there is no MX record. Either "
                    "mail is received via another mechanism (inbound gateway, "
                    "third-party) or the mail setup is incomplete — both warrant "
                    "confirmation because inbound mail may be silently dropped."
                ),
                scope=f"MX records for {target.apex}",
                remediation="Confirm the intended mail flow and publish MX records if the domain receives mail.",
                tags=["dns", "mail"],
            )
        )

    # ---- NS delegation -----------------------------------------------------
    ns = snap.get("NS")
    if ns.present and len(ns.values) == 1:
        findings.append(
            Finding(
                id="security.dns.single_ns",
                title="Domain has only one nameserver",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.dns_record(target.apex, "NS", ns.values),
                reasoning=(
                    "A single nameserver is a single point of failure. RFC 2182 "
                    "requires at least two; with one, a failure or an attack on that "
                    "host takes the whole domain's resolution down."
                ),
                scope=f"NS records for {target.apex}",
                remediation="Delegate to at least two nameservers in different networks.",
                tags=["dns", "resilience"],
            )
        )

    return findings
