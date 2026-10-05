"""Deep Content-Security-Policy analysis.

Goes beyond presence: parses the directive set and flags the specific
weaknesses that turn a deployed CSP into a decorative one. Every claim is
backed by the actual header value.
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
    id="security.headers.csp_deep",
    category=Category.SECURITY,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("http_response",),
    title="CSP directive analysis",
    description="Parses the CSP and flags the directives that actually weaken it.",
    tags=("headers", "csp", "owasp-a05"),
)
async def check_csp_deep(ctx: ProbeContext) -> list[Finding]:
    """Parse and evaluate the Content-Security-Policy header."""
    findings: list[Finding] = []
    resp = ctx.require("http_response")
    if not resp.ok:
        return findings

    source = f"GET {resp.final_url}"
    csp = resp.headers.get("content-security-policy", "")
    csp_report_only = resp.headers.get("content-security-policy-report-only", "")

    if not csp and not csp_report_only:
        # Already covered by security.headers (missing header). Don't duplicate.
        return findings

    if csp_report_only and not csp:
        findings.append(
            Finding(
                id="security.csp.report_only_mode",
                title="CSP is deployed in Report-Only mode (not enforced)",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.http_headers(
                    {"content-security-policy-report-only": csp_report_only[:300]}, source=source
                ),
                reasoning=(
                    "A Report-Only CSP collects violation reports but blocks "
                    "nothing. It is the correct first step of a CSP rollout, but if "
                    "it has been in place for a long time the enforcement work has "
                    "stalled — the policy is watching, not protecting."
                ),
                scope=f"Response headers of {resp.final_url}",
                remediation=(
                    "Review the accumulated violation reports, fix legitimate "
                    "sources into the allowlist, then move the same directives to "
                    "`Content-Security-Policy` (enforcing)."
                ),
                tags=["headers", "csp"],
            )
        )

    if not csp:
        return findings

    directives = _parse_csp(csp)
    evidence = Evidence.http_headers({"content-security-policy": csp[:600]}, source=source)

    # ---- unsafe directives ------------------------------------------------
    unsafe_flags = []
    for directive in ("script-src", "style-src"):
        values = directives.get(directive, set()) | directives.get("default-src", set())
        if "'unsafe-inline'" in values:
            unsafe_flags.append(f"'unsafe-inline' in {directive}")
        if "'unsafe-eval'" in values:
            unsafe_flags.append(f"'unsafe-eval' in {directive}")

    if unsafe_flags:
        findings.append(
            Finding(
                id="security.csp.unsafe_directives",
                title="CSP contains 'unsafe-inline' / 'unsafe-eval'",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                reasoning=(
                    "The CSP permits: " + "; ".join(unsafe_flags) + ". "
                    "'unsafe-inline' allows any inline <script>/<style> to run, "
                    "which is exactly what XSS injects. 'unsafe-eval' allows string "
                    "code execution. With either present the CSP no longer prevents "
                    "the class of attack it exists to prevent."
                ),
                scope=f"Response headers of {resp.final_url}",
                remediation=(
                    "Move inline code to external files and use nonces or hashes "
                    "for the few that must stay inline. Remove 'unsafe-eval' unless "
                    "a specific library requires it."
                ),
                tags=["headers", "csp", "xss"],
            )
        )

    # ---- wildcard sources --------------------------------------------------
    wildcard_directives = []
    for directive in ("default-src", "script-src", "connect-src", "img-src", "frame-src"):
        values = directives.get(directive, set())
        if "*" in values:
            wildcard_directives.append(directive)

    if wildcard_directives:
        findings.append(
            Finding(
                id="security.csp.wildcard_sources",
                title=f"CSP uses wildcard sources in {len(wildcard_directives)} directive(s)",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                reasoning=(
                    "`*` in " + ", ".join(wildcard_directives) + " allows any origin. "
                    "The policy then constrains nothing — any attacker-controlled "
                    "host is an allowed source for those resource types."
                ),
                scope=f"Response headers of {resp.final_url}",
                remediation="Replace `*` with an explicit allowlist of the origins actually used.",
                tags=["headers", "csp"],
            )
        )

    # ---- missing directives ------------------------------------------------
    missing = []
    for directive, why in (
        ("object-src", "object-src 'none' blocks plugin-based script execution (Flash, etc.)"),
        ("base-uri", "base-uri 'self' prevents <base> tag hijacking of relative URLs"),
        ("frame-ancestors", "frame-ancestors replaces X-Frame-Options for clickjacking"),
        ("form-action", "form-action constrains where forms can submit to"),
    ):
        if directive not in directives:
            missing.append((directive, why))

    if missing:
        findings.append(
            Finding(
                id="security.csp.missing_directives",
                title=f"CSP is missing {len(missing)} hardening directive(s)",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                reasoning=("Not present: " + "; ".join(f"{d} ({why})" for d, why in missing) + "."),
                scope=f"Response headers of {resp.final_url}",
                remediation="Add: object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'.",
                tags=["headers", "csp"],
            )
        )

    # ---- well-formed check -------------------------------------------------
    if not unsafe_flags and not wildcard_directives and not missing:
        findings.append(
            Finding(
                id="security.csp.well_configured",
                title="CSP is enforced with a restrictive directive set",
                category=Category.SECURITY,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                reasoning=(
                    "The enforcing CSP contains no 'unsafe-inline', no 'unsafe-eval', "
                    "no wildcards, and includes the hardening directives. This is a "
                    "genuinely protective policy."
                ),
                scope=f"Response headers of {resp.final_url}",
                tags=["headers", "csp", "strength"],
            )
        )

    return findings


def _parse_csp(csp: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            out[tokens[0].lower()] = set(tokens[1:])
    return out
