"""API surface discovery — documentation and well-known endpoints.

API docs left open on a production host are both a security exposure (they map
the attack surface for free) and a common staging artefact. Each path is
fetched once and the response is shape-validated before it is reported, so an
SPA's catch-all 200 is not mistaken for a live swagger UI.
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

# Bounded wordlist — 12 high-signal paths, not brute force.
API_PATHS = (
    ("/swagger.json", "OpenAPI 2.0 (swagger) document"),
    ("/openapi.json", "OpenAPI 3.x document"),
    ("/api-docs", "API documentation index"),
    ("/swagger-ui.html", "Swagger UI"),
    ("/graphql", "GraphQL endpoint"),
    ("/graphiql", "GraphiQL explorer"),
    ("/api/v1", "API v1 root"),
    ("/api/", "API root"),
    ("/.well-known/openid-configuration", "OpenID Connect discovery"),
    ("/.well-known/security.txt", "RFC 9116 security contact"),
    ("/v1/", "Versioned API root"),
    ("/altair", "Altair GraphQL client"),
)

DOC_MARKERS = ("swagger", "openapi", "paths", "graphiql", "graphql", "altair")


@register_probe(
    id="security.exposure.api",
    category=Category.SECURITY,
    mode=ProbeMode.ACTIVE,
    phase=ProbePhase.ACTIVE,
    requires=("http_response",),
    title="API documentation & endpoint exposure",
    description="Bounded check for swagger, OpenAPI, GraphQL and well-known endpoints.",
    tags=("exposure", "api", "owasp-a01", "attack-surface"),
)
async def check_api_exposure(ctx: ProbeContext) -> list[Finding]:
    """Fetch a small set of API discovery paths and report what answers."""
    findings: list[Finding] = []
    http = ctx.http_client
    if http is None:
        return findings

    base = ctx.target.base_url
    open_endpoints: list[str] = []

    for path, label in API_PATHS:
        await http.limiter.acquire()
        resp = await http.get(f"{base}{path}", follow=True)

        if resp.error or not resp.ok:
            continue

        body = resp.body[:4000].lower()
        looks_like_doc = any(marker in body for marker in DOC_MARKERS)
        # A soft-404 SPA returns 200 + HTML shell for every path — exclude those.
        is_html_shell = resp.is_html and not looks_like_doc

        if looks_like_doc and not is_html_shell:
            open_endpoints.append(f"{path}  ({label}, HTTP {resp.status})")

    if open_endpoints:
        findings.append(
            Finding(
                id="security.exposure.api.docs_open",
                title=f"{len(open_endpoints)} API documentation endpoint(s) publicly reachable",
                category=Category.SECURITY,
                kind=FindingKind.EXPOSURE,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text("\n".join(open_endpoints), source=f"GET {base}/*"),
                reasoning=(
                    "API documentation on a production host hands an attacker a "
                    "complete map of the attack surface — every route, parameter "
                    "and data shape — before they send a single guess. If the "
                    "spec is public on purpose (an open API), the rate limits and "
                    "auth requirements become the only defence."
                ),
                scope=f"API discovery paths under {base}",
                remediation=(
                    "Restrict docs to authenticated or internal users (IP allowlist, "
                    "VPN or reverse-proxy auth). Keep the spec available only in "
                    "staging, and verify rate limiting and auth on every documented route."
                ),
                tags=["exposure", "api", "attack-surface"],
            )
        )
    else:
        findings.append(
            Finding(
                id="security.exposure.api.none",
                title="No API documentation endpoints publicly reachable",
                category=Category.SECURITY,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(
                    f"None of the {len(API_PATHS)} discovery paths returned API documentation.",
                    source=f"GET {base}/*",
                ),
                reasoning=(
                    "The common API discovery paths either do not exist or do not "
                    "serve a spec. That removes the free reconnaissance an attacker "
                    "would otherwise get."
                ),
                scope=f"API discovery paths under {base}",
                tags=["exposure", "api", "strength"],
            )
        )

    return findings
