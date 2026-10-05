"""TLS certificate and transport analysis.

Every value here comes from the TLS handshake itself — issuer, subject,
validity window, SAN list and negotiated protocol. No inference.
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

WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
DEPRECATED_TLS13_REMOVED = WEAK_PROTOCOLS  # explicit for readability

# Certificates issued by these are short-lived automated CAs; a short validity
# window is expected and not a finding by itself.
AUTOMATED_CAS = ("let's encrypt", "letsencrypt", "google trust services", "amazon", "zeroSSL")


@register_probe(
    id="security.tls",
    category=Category.SECURITY,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("tls",),
    title="TLS certificate & transport",
    description="Certificate issuer, validity window, SAN coverage and negotiated protocol.",
    tags=("tls", "transport", "pci-req4"),
)
async def check_tls(ctx: ProbeContext) -> list[Finding]:
    """Analyse the TLS handshake capture."""
    tls: dict = ctx.require("tls")
    findings: list[Finding] = []
    target = ctx.target
    source = f"TLS handshake {target.domain}:443"

    if tls.get("error"):
        findings.append(
            Finding(
                id="security.tls.handshake_failed",
                title="TLS handshake did not complete",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(str(tls["error"]), source=source),
                reasoning=(
                    "A TLS handshake could not be completed against port 443. Either "
                    "HTTPS is not served on this host, or the certificate chain is "
                    "unusable by a default-trust client. Browsers will show an "
                    "interstitial to every visitor."
                ),
                scope=f"TCP/443 on {target.domain}",
                remediation="Verify the certificate chain and that HTTPS is served on this host.",
                tags=["tls", "availability"],
            )
        )
        return findings

    cert = tls.get("certificate", {}) or {}
    evidence = Evidence.tls_certificate(_render_cert(tls), summary=tls.get("protocol", ""))

    # ---- protocol version --------------------------------------------------
    protocol = tls.get("protocol", "")
    if protocol in WEAK_PROTOCOLS:
        findings.append(
            Finding(
                id="security.tls.weak_protocol",
                title=f"Negotiated deprecated protocol {protocol}",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                reasoning=(
                    f"{protocol} has known, practical weaknesses and is deprecated by "
                    "NIST and the major browser vendors. A network attacker can "
                    "downgrade or decrypt traffic protected only by it."
                ),
                scope=f"TLS handshake {target.domain}:443",
                remediation="Disable TLS 1.0/1.1 and SSL; serve TLS 1.2 minimum, 1.3 preferred.",
                tags=["tls", "protocol"],
            )
        )
    elif protocol:
        findings.append(
            Finding(
                id="security.tls.protocol_ok",
                title=f"Negotiated modern protocol {protocol}",
                category=Category.SECURITY,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                reasoning="The handshake negotiated a currently supported TLS version.",
                scope=f"TLS handshake {target.domain}:443",
                tags=["tls", "strength"],
            )
        )

    # ---- certificate validity ---------------------------------------------
    days = tls.get("days_until_expiry")
    if isinstance(days, int):
        if days < 0:
            findings.append(
                Finding(
                    id="security.tls.cert_expired",
                    title=f"Certificate expired {abs(days)} days ago",
                    category=Category.SECURITY,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    evidence=evidence,
                    reasoning=(
                        "An expired certificate means browsers show a security "
                        "warning to every visitor and treat the connection as "
                        "untrusted. Traffic is effectively unprotected from the "
                        "user's perspective."
                    ),
                    scope=f"Certificate for {target.domain}",
                    remediation="Renew the certificate immediately and enable auto-renewal.",
                    tags=["tls", "certificate", "expiry"],
                )
            )
        elif days <= 14:
            findings.append(
                Finding(
                    id="security.tls.cert_expiring_soon",
                    title=f"Certificate expires in {days} days",
                    category=Category.SECURITY,
                    kind=FindingKind.OBSERVATION,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    evidence=evidence,
                    reasoning=(
                        "The certificate is inside the two-week window where a failed "
                        "renewal becomes an outage. Confirm auto-renewal is working."
                    ),
                    scope=f"Certificate for {target.domain}",
                    remediation="Confirm the ACME/auto-renewal job is healthy before expiry.",
                    tags=["tls", "certificate", "expiry"],
                )
            )
        else:
            findings.append(
                Finding(
                    id="security.tls.cert_validity_window",
                    title=f"Certificate valid for {days} more days",
                    category=Category.SECURITY,
                    kind=FindingKind.OBSERVATION,
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    evidence=evidence,
                    reasoning="Certificate is inside its validity window.",
                    scope=f"Certificate for {target.domain}",
                    tags=["tls", "certificate"],
                )
            )

    # ---- SAN coverage ------------------------------------------------------
    sans = cert.get("subject_alt_names") or []
    subject_cn = cert.get("subject_cn", "")
    if sans and target.domain not in sans and not _covered_by_wildcard(target.domain, sans):
        findings.append(
            Finding(
                id="security.tls.san_mismatch",
                title="Certificate SAN list does not cover the scanned hostname",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                reasoning=(
                    f"The certificate was served for {target.domain} but its Subject "
                    f"Alternative Names are {', '.join(sans[:8])}. A validating client "
                    "will reject the certificate."
                ),
                scope=f"Certificate for {target.domain}",
                remediation="Issue a certificate whose SAN list includes this hostname.",
                tags=["tls", "certificate", "san"],
            )
        )
    elif sans:
        findings.append(
            Finding(
                id="security.tls.san_coverage",
                title=f"Certificate covers {len(sans)} name(s) including this host",
                category=Category.SECURITY,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                reasoning="Hostname validation will succeed for the scanned host.",
                scope=f"Certificate for {target.domain}",
                tags=["tls", "certificate", "strength"],
            )
        )

    if subject_cn:
        findings.append(
            Finding(
                id="security.tls.issuer",
                title=f"Certificate issued by {cert.get('issuer_cn', 'unknown')}",
                category=Category.SECURITY,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                reasoning=(
                    "Certificate authority of record. Self-signed or private CAs "
                    "warrant a closer look; public automated CAs are normal."
                ),
                scope=f"Certificate for {target.domain}",
                tags=["tls", "certificate"],
            )
        )

    return findings


def _covered_by_wildcard(host: str, sans: list[str]) -> bool:
    for san in sans:
        if san.startswith("*."):
            suffix = san[2:]
            if (host == suffix or host.endswith("." + suffix)) and (
                host[: -len(suffix) - 1].count(".") == 0 or host == suffix
            ):
                return True
    return False


def _render_cert(tls: dict) -> str:
    cert = tls.get("certificate", {}) or {}
    lines = [
        f"hostname:        {tls.get('hostname')}",
        f"protocol:        {tls.get('protocol')}",
        f"cipher:          {tls.get('cipher')}",
        f"chain_length:    {tls.get('chain_length')}",
        f"subject_cn:      {cert.get('subject_cn')}",
        f"issuer_cn:       {cert.get('issuer_cn')}",
        f"not_before:      {cert.get('not_before')}",
        f"not_after:       {cert.get('not_after')}",
        f"serial:          {cert.get('serial_number')}",
        f"days_remaining:  {tls.get('days_until_expiry')}",
        f"san:             {', '.join(cert.get('subject_alt_names') or [])}",
    ]
    return "\n".join(lines)
