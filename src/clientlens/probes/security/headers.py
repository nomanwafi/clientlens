"""Security header checks.

Everything here is ``CONFIRMED``: we read the response headers and report
exactly what is and is not present. Absence is reported as absence, never as
proof of exploitability.
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

# (header, severity_if_missing, why it matters, remediation)
HEADER_POLICY: list[tuple[str, Severity, str, str]] = [
    (
        "strict-transport-security",
        Severity.MEDIUM,
        "Without HSTS a first visit over http:// can be SSL-stripped by an "
        "on-path attacker before the redirect to https happens.",
        "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` "
        "once HTTPS is confirmed working on all subdomains.",
    ),
    (
        "content-security-policy",
        Severity.MEDIUM,
        "CSP is the primary browser-side mitigation for XSS and malicious "
        "third-party script injection. Without it, an injected script runs.",
        "Start with `Content-Security-Policy-Report-Only` and tighten from "
        "real violation reports before enforcing.",
    ),
    (
        "x-content-type-options",
        Severity.LOW,
        "Without `nosniff` a browser may MIME-sniff a response and execute it "
        "as a script, turning a data leak into code execution.",
        "Add `X-Content-Type-Options: nosniff`.",
    ),
    (
        "x-frame-options",
        Severity.LOW,
        "Without framing control the page can be embedded in a hostile frame "
        "for clickjacking. CSP `frame-ancestors` covers this too.",
        "Add `X-Frame-Options: DENY` (or `SAMEORIGIN`), or CSP frame-ancestors.",
    ),
    (
        "referrer-policy",
        Severity.LOW,
        "The default referrer behaviour leaks full URLs — including campaign "
        "and session parameters — to third-party origins.",
        "Add `Referrer-Policy: strict-origin-when-cross-origin`.",
    ),
    (
        "permissions-policy",
        Severity.INFO,
        "Without a permissions policy the page grants every embedded third "
        "party access to powerful browser features (camera, mic, geolocation).",
        "Add `Permissions-Policy` denying features the page does not need.",
    ),
    (
        "cross-origin-opener-policy",
        Severity.INFO,
        "COOP isolates the browsing context from cross-origin popups and is "
        "part of a modern cross-origin isolation posture.",
        "Add `Cross-Origin-Opener-Policy: same-origin-allow-popups`.",
    ),
]

# Values that are technically present but ineffective.
INEFFECTIVE_VALUES = {
    "content-security-policy": {
        "default-src *": "wildcard source allows any origin",
        "unsafe-inline": "'unsafe-inline' largely defeats script-src protection",
        "unsafe-eval": "'unsafe-eval' allows dynamic code generation",
    },
    "x-frame-options": {
        "allowall": "ALLOWALL disables framing protection entirely",
        "allow-from": "ALLOW-FROM is unsupported by modern browsers",
    },
    "strict-transport-security": {
        "max-age=0": "max-age=0 disables HSTS immediately",
    },
}


@register_probe(
    id="security.headers",
    category=Category.SECURITY,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("http_response",),
    title="HTTP security headers",
    description="Presence, correctness and effectiveness of browser security headers.",
    tags=("headers", "owasp-a05"),
)
async def check_security_headers(ctx: ProbeContext) -> list[Finding]:
    """Evaluate HTTP security headers on the homepage response."""
    resp = ctx.require("http_response")
    findings: list[Finding] = []

    if not resp.ok:
        return findings

    headers = resp.headers
    source = f"GET {resp.final_url}"

    for header, severity, why, fix in HEADER_POLICY:
        value = headers.get(header)

        if not value:
            findings.append(
                Finding(
                    id=f"security.headers.{header.replace('-', '_')}_missing",
                    title=f"{header} header not present",
                    category=Category.SECURITY,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=severity,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.http_headers(headers, source=source),
                    reasoning=why,
                    scope=f"Response headers of {resp.final_url}",
                    remediation=fix,
                    tags=["headers", "missing-header"],
                )
            )
            continue

        # Present but possibly ineffective.
        lowered = value.lower()
        problems = [
            problem
            for token, problem in INEFFECTIVE_VALUES.get(header, {}).items()
            if token in lowered
        ]
        if problems:
            findings.append(
                Finding(
                    id=f"security.headers.{header.replace('-', '_')}_ineffective",
                    title=f"{header} is present but ineffective",
                    category=Category.SECURITY,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.http_headers({header: value}, source=source),
                    reasoning="; ".join(problems),
                    scope=f"Response headers of {resp.final_url}",
                    remediation=fix,
                    tags=["headers", "weak-value"],
                )
            )
        else:
            findings.append(
                Finding(
                    id=f"security.headers.{header.replace('-', '_')}_present",
                    title=f"{header} correctly configured",
                    category=Category.SECURITY,
                    kind=FindingKind.STRENGTH,
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.http_headers({header: value}, source=source),
                    reasoning="Header is present with a protective value.",
                    scope=f"Response headers of {resp.final_url}",
                    tags=["headers", "strength"],
                )
            )

    # ---- server banner disclosure -----------------------------------------
    for banner_header in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        val = headers.get(banner_header)
        if val:
            findings.append(
                Finding(
                    id=f"security.headers.{banner_header.replace('-', '_')}_disclosed",
                    title=f"Technology disclosed via `{banner_header}` header",
                    category=Category.SECURITY,
                    kind=FindingKind.EXPOSURE,
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.http_headers({banner_header: val}, source=source),
                    reasoning=(
                        "The server advertises its implementation. This is not a "
                        "vulnerability, but it shortens an attacker's fingerprinting "
                        "work and should be suppressed unless a specific version is "
                        "genuinely required."
                    ),
                    scope=f"Response headers of {resp.final_url}",
                    remediation=f"Remove or genericise the `{banner_header}` response header.",
                    tags=["disclosure", "fingerprint"],
                )
            )

    return findings
