"""CORS misconfiguration vector detection.

Reports the *observed* Access-Control-Allow-* values against a set of probe
origins. A permissive value is reported as a vector needing manual review, not
as a proven vulnerability, because real exploitability depends on whether the
endpoint serves sensitive data and whether credentials are allowed.
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

PROBE_ORIGINS = (
    "https://evil.example",
    "https://subdomain.attacker.test",
    "null",
)


@register_probe(
    id="security.cors",
    category=Category.SECURITY,
    mode=ProbeMode.ACTIVE,
    phase=ProbePhase.ACTIVE,
    requires=("http_response",),
    title="CORS origin reflection vector",
    description="Sends probe Origin headers and records how the server responds.",
    tags=("cors", "owasp-a05", "needs-review"),
)
async def check_cors(ctx: ProbeContext) -> list[Finding]:
    """Send a few Origin probes and report reflected ACAO values."""
    findings: list[Finding] = []
    http = ctx.http_client
    base = ctx.target.base_url

    # Reuse the shared client but with an explicit Origin header.
    client = http._client  # noqa: SLF001 - intentional, shared budget still applies
    if client is None:
        return findings

    observed: list[str] = []
    reflected_any = False

    for origin in PROBE_ORIGINS:
        await http.limiter.acquire()
        try:
            resp = await client.get(f"{base}/", headers={"Origin": origin})
        except Exception as exc:  # noqa: BLE001
            observed.append(f"Origin: {origin} -> error {type(exc).__name__}")
            continue

        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")
        observed.append(
            f"Origin: {origin}\n  ACAO: {acao or '(absent)'}\n  ACAC: {acac or '(absent)'}"
        )

        if not acao:
            continue

        is_reflected = acao == origin or acao == "*"
        if is_reflected:
            reflected_any = True
            creds = acac.lower() == "true"
            findings.append(
                Finding(
                    id=f"security.cors.reflects_{_slug(origin)}",
                    title=f"CORS reflects Origin `{origin}`"
                    + (" with credentials" if creds else ""),
                    category=Category.SECURITY,
                    kind=FindingKind.VULNERABILITY_VECTOR,
                    severity=Severity.HIGH if creds else Severity.MEDIUM,
                    confidence=Confidence.LIKELY,
                    evidence=Evidence.text(
                        f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac or '(absent)'}",
                        source=f"GET {base}/ with Origin header",
                    ),
                    reasoning=(
                        "The server echoes back the caller-supplied Origin as an "
                        "allowed origin" + (" AND allows credentials" if creds else "") + ". "
                        "If this endpoint returns non-public data, a page on another "
                        "origin can read it in a victim's browser.\n\n"
                        "This is an attack-surface observation. Confirm manually "
                        "whether the endpoint serves user-specific data before "
                        "treating it as a vulnerability."
                    ),
                    scope=f"GET {base}/ with Origin: {origin}",
                    remediation=(
                        "Allowlist permitted origins explicitly. Never echo an "
                        "arbitrary Origin, and never combine `*` with credentials."
                    ),
                    references=["https://portswigger.net/web-security/cors"],
                    tags=["cors", "needs-review"],
                )
            )

    if not reflected_any:
        findings.append(
            Finding(
                id="security.cors.no_reflection",
                title="CORS did not reflect any probe Origin",
                category=Category.SECURITY,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text("\n".join(observed), source=f"GET {base}/"),
                reasoning=(
                    "None of the probe origins were echoed back in "
                    "Access-Control-Allow-Origin. This is a positive result for the "
                    "endpoints tested."
                ),
                scope=f"GET {base}/ with {len(PROBE_ORIGINS)} Origin headers",
                tags=["cors", "strength"],
            )
        )

    return findings


def _slug(value: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in value).strip("_").lower()[:40]
