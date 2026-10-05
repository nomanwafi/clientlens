"""Subdomain discovery via Certificate Transparency (crt.sh).

crt.sh is free and requires no API key. What it returns is what we report:
names that appear in issued certificates. Absence from CT logs is explicitly
labelled as "not detected", not "does not exist".
"""

from __future__ import annotations

import json
import logging

import httpx

from ...core.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    FindingKind,
    Severity,
)
from ...core.registry import ProbeContext, ProbeMode, ProbePhase, register_probe

log = logging.getLogger("clientlens.subdomains")

CRTSH_URL = "https://crt.sh/"
CRTSH_PARAMS = {"q": None, "output": "json"}
CRTSH_TIMEOUT = 25.0


@register_probe(
    id="security.subdomains",
    category=Category.SECURITY,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    title="Subdomain discovery (Certificate Transparency)",
    description="Names observed in issued certificates for the apex domain via crt.sh.",
    tags=("recon", "subdomains", "attack-surface"),
)
async def check_subdomains(ctx: ProbeContext) -> list[Finding]:
    """Query crt.sh for names in certificates issued for the apex domain."""
    findings: list[Finding] = []
    target = ctx.target
    apex = target.apex

    if not ctx.config.use_crtsh:
        return findings

    names, error = await _query_crtsh(apex)

    if error:
        findings.append(
            Finding(
                id="security.subdomains.ct_unavailable",
                title="Certificate Transparency lookup unavailable",
                category=Category.SECURITY,
                kind=FindingKind.GAP,
                severity=Severity.INFO,
                confidence=Confidence.NEEDS_REVIEW,
                evidence=Evidence.text(error, source=f"crt.sh q={apex}"),
                reasoning=(
                    "The crt.sh query failed, so no subdomain data is available. "
                    "This is a coverage gap, not a clean result."
                ),
                scope=f"crt.sh query for {apex}",
                tags=["recon", "coverage-gap", "needs-review"],
            )
        )
        return findings

    if not names:
        findings.append(
            Finding(
                id="security.subdomains.none_found",
                title="No additional hostnames found in CT logs",
                category=Category.SECURITY,
                kind=FindingKind.GAP,
                severity=Severity.INFO,
                confidence=Confidence.NEEDS_REVIEW,
                evidence=Evidence.text(
                    f"crt.sh returned no names for {apex}.",
                    source=f"crt.sh q={apex}",
                ),
                reasoning=(
                    "Certificate Transparency only shows names that appear in "
                    "issued certificates. Names resolved internally, or covered by "
                    "a wildcard that was never logged individually, will not appear. "
                    "Do not read this as 'there are no subdomains'."
                ),
                scope=f"crt.sh query for {apex}",
                tags=["recon", "negative-result", "needs-review"],
            )
        )
        return findings

    # Partition into the scanned host, apex, and everything else.
    scanned = target.domain
    others = sorted({n for n in names if n != apex and n != scanned and not n.startswith("*.")})
    wildcards = sorted({n for n in names if n.startswith("*.")})

    findings.append(
        Finding(
            id="security.subdomains.ct_inventory",
            title=f"{len(others)} additional hostname(s) found in CT logs",
            category=Category.SECURITY,
            kind=FindingKind.OBSERVATION,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            evidence=Evidence.urls(
                others[:60], summary=f"{len(others)} names", source=f"crt.sh q={apex}"
            ),
            reasoning=(
                "Every name here appeared in an issued certificate for the apex "
                "domain. Each one is an additional public entry point that needs "
                "its own exposure review — legacy or staging hosts on a domain are "
                "the most common source of a breach."
            ),
            scope=f"crt.sh query for {apex}",
            remediation=(
                "Review each hostname: decommission hosts that no longer serve a "
                "purpose, and confirm the rest are in scope for patching and "
                "monitoring."
            ),
            tags=["recon", "subdomains", "attack-surface"],
        )
    )

    # Highlight hosts that look like staging/dev/admin surfaces.
    risky_tokens = (
        "staging",
        "stage",
        "dev",
        "test",
        "qa",
        "uat",
        "admin",
        "internal",
        "vpn",
        "remote",
        "mail",
        "webmail",
        "cpanel",
        "direct",
        "portal",
        "jenkins",
        "gitlab",
        "grafana",
        "kibana",
        "elastic",
        "phpmyadmin",
    )
    risky = [n for n in others if any(tok in n.lower() for tok in risky_tokens)]

    if risky:
        findings.append(
            Finding(
                id="security.subdomains.high_risk_hosts",
                title=f"{len(risky)} hostname(s) look like staging/admin/remote surfaces",
                category=Category.SECURITY,
                kind=FindingKind.EXPOSURE,
                severity=Severity.MEDIUM,
                confidence=Confidence.LIKELY,
                evidence=Evidence.urls(risky[:40], source=f"crt.sh q={apex}"),
                reasoning=(
                    "Names containing staging/dev/admin/vpn-type tokens are "
                    "frequently lower-hardened than production and are a standard "
                    "first target. The name alone does not prove anything is wrong — "
                    "it is a prioritisation signal."
                ),
                scope=f"crt.sh query for {apex}",
                remediation=(
                    "Confirm each of these is intentionally public. Staging and "
                    "admin surfaces should sit behind VPN or IP allowlists."
                ),
                tags=["recon", "subdomains", "prioritisation"],
            )
        )

    if wildcards:
        findings.append(
            Finding(
                id="security.subdomains.wildcard_certificates",
                title=f"{len(wildcards)} wildcard certificate(s) issued for this domain",
                category=Category.SECURITY,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.urls(wildcards[:20], source=f"crt.sh q={apex}"),
                reasoning=(
                    "A wildcard certificate covers every label under its suffix. It "
                    "is convenient but means any single compromised host can serve "
                    "valid TLS for the entire domain."
                ),
                scope=f"crt.sh query for {apex}",
                tags=["recon", "pki"],
            )
        )

    return findings


async def _query_crtsh(apex: str) -> tuple[set[str], str]:
    """Fetch CT names for the apex. Returns (names, error)."""
    params = {"q": f"%.{apex}", "output": "json"}
    try:
        async with httpx.AsyncClient(timeout=CRTSH_TIMEOUT) as client:
            resp = await client.get(
                CRTSH_URL, params=params, headers={"User-Agent": "ClientLens/0.1"}
            )
            if resp.status_code != 200:
                return set(), f"crt.sh returned HTTP {resp.status_code}"
            if not resp.text.strip():
                return set(), ""
            try:
                rows = json.loads(resp.text)
            except json.JSONDecodeError:
                return set(), "crt.sh returned non-JSON payload"
    except httpx.HTTPError as exc:
        return set(), f"crt.sh request failed: {type(exc).__name__}: {exc}"

    names: set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        value = row.get("name_value", "") or ""
        for part in value.splitlines():
            part = part.strip().lower().rstrip(".")
            if (part and "*" not in part or part.startswith("*.")) and (
                part.endswith(apex) or part == apex
            ):
                names.add(part)
    return names, ""
