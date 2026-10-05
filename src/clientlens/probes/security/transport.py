"""HTTP transport deep checks.

OPTIONS method enumeration, HTTP version support and HTTPS enforcement. All
observed from the wire — a method in ``Allow`` is a directly observed fact.
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

# Methods that let a caller modify server state or leak information when the
# endpoint does not expect them.
DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH", "TRACK"}
SAFE_METHODS = {"GET", "HEAD", "POST", "OPTIONS"}


@register_probe(
    id="security.transport.methods",
    category=Category.SECURITY,
    mode=ProbeMode.ACTIVE,
    phase=ProbePhase.ACTIVE,
    requires=("http_response",),
    title="HTTP method enumeration",
    description="OPTIONS request to see which methods the server accepts.",
    tags=("transport", "methods", "owasp-a05"),
)
async def check_http_methods(ctx: ProbeContext) -> list[Finding]:
    """Send OPTIONS and report the advertised methods."""
    findings: list[Finding] = []
    http = ctx.http_client
    base = ctx.target.base_url

    client = http._client  # noqa: SLF001 - shared budget still applies
    if client is None:
        return findings

    await http.limiter.acquire()
    import httpx

    try:
        resp = await client.options(f"{base}/")
    except httpx.HTTPError as exc:
        findings.append(
            Finding(
                id="security.transport.methods.options_failed",
                title="OPTIONS request did not complete",
                category=Category.SECURITY,
                kind=FindingKind.GAP,
                severity=Severity.INFO,
                confidence=Confidence.NEEDS_REVIEW,
                evidence=Evidence.text(f"{type(exc).__name__}: {exc}", source=f"OPTIONS {base}/"),
                reasoning="The OPTIONS request failed, so method enumeration is unavailable.",
                scope=f"OPTIONS {base}/",
                tags=["transport", "needs-review"],
            )
        )
        return findings

    allow_header = resp.headers.get("allow", "")
    public_header = resp.headers.get("public", "")
    raw_allow = allow_header or public_header
    methods = {m.strip().upper() for m in raw_allow.split(",") if m.strip()} if raw_allow else set()

    if not methods:
        findings.append(
            Finding(
                id="security.transport.methods.not_advertised",
                title="Server does not advertise allowed methods via OPTIONS",
                category=Category.SECURITY,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.http_response(
                    resp.status_code, dict(resp.headers), source=f"OPTIONS {base}/"
                ),
                reasoning=(
                    "The OPTIONS response carries no Allow/Public header, so the "
                    "server is not disclosing its method surface. This is normal and "
                    "not a defect."
                ),
                scope=f"OPTIONS {base}/ (status {resp.status_code})",
                tags=["transport", "methods"],
            )
        )
        return findings

    dangerous = methods & DANGEROUS_METHODS
    source = f"OPTIONS {base}/ (status {resp.status_code})"

    if dangerous:
        findings.append(
            Finding(
                id="security.transport.methods.dangerous",
                title=f"Server advertises state-changing methods: {', '.join(sorted(dangerous))}",
                category=Category.SECURITY,
                kind=FindingKind.VULNERABILITY_VECTOR,
                severity=Severity.MEDIUM,
                confidence=Confidence.LIKELY,
                evidence=Evidence.text(
                    f"Allow: {raw_allow}",
                    summary=f"{len(methods)} methods",
                    source=source,
                ),
                reasoning=(
                    f"The server advertises {', '.join(sorted(dangerous))} in its "
                    "Allow header. Methods like PUT, DELETE and TRACE let a caller "
                    "write or delete resources (or leak credentials via TRACE) when "
                    "the endpoint does not guard them. Advertising them is not "
                    "proof they work — many frameworks accept OPTIONS on all routes "
                    "while rejecting the methods on data routes.\n\n"
                    "Verify manually whether these methods actually change state "
                    "before treating this as a vulnerability."
                ),
                scope=source,
                remediation=(
                    "Return 405 for methods the endpoint does not need, and omit "
                    "them from the Allow header."
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"
                ],
                tags=["transport", "methods", "needs-review"],
            )
        )
    else:
        findings.append(
            Finding(
                id="security.transport.methods.safe",
                title=f"Advertised methods are read-only: {', '.join(sorted(methods))}",
                category=Category.SECURITY,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(f"Allow: {raw_allow}", source=source),
                reasoning="No state-changing methods are advertised.",
                scope=source,
                tags=["transport", "methods", "strength"],
            )
        )

    return findings


@register_probe(
    id="security.transport.https_enforcement",
    category=Category.SECURITY,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("http_response",),
    title="HTTPS enforcement",
    description="Whether the http:// version redirects to https:// or serves content.",
    tags=("transport", "https", "hsts"),
)
async def check_https_enforcement(ctx: ProbeContext) -> list[Finding]:
    """Check whether plain http:// redirects to https://."""
    findings: list[Finding] = []
    target = ctx.target
    http = ctx.http_client

    http_url = f"http://{target.domain}/"
    resp = await http.get(http_url, follow=False)

    if resp.error:
        findings.append(
            Finding(
                id="security.transport.http_unreachable",
                title="Plain http:// is not reachable",
                category=Category.SECURITY,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(resp.error, source=http_url),
                reasoning=(
                    "The http:// port did not answer. That is a valid posture — no "
                    "plaintext listener exists to be downgraded through. Note that "
                    "HSTS preload is the stricter control; this result only covers "
                    "the redirect behaviour."
                ),
                scope=f"GET {http_url}",
                tags=["transport", "https"],
            )
        )
        return findings

    location = resp.headers.get("location", "")
    redirects_to_https = location.startswith("https://")

    if resp.status in (301, 302, 303, 307, 308) and redirects_to_https:
        findings.append(
            Finding(
                id="security.transport.http_redirects_https",
                title="http:// redirects to https://",
                category=Category.SECURITY,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.http_response(resp.status, resp.headers, source=http_url),
                reasoning=(
                    f"Plain HTTP redirects to HTTPS ({location}). First visits over "
                    "http are upgraded by the server. Combine with HSTS for full "
                    "protection."
                ),
                scope=f"GET {http_url} -> {location}",
                tags=["transport", "https", "strength"],
            )
        )
    elif resp.status == 200:
        findings.append(
            Finding(
                id="security.transport.http_serves_content",
                title="http:// serves content instead of redirecting to https://",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.http_response(resp.status, resp.headers, source=http_url),
                reasoning=(
                    "The plaintext endpoint returns a 200 with content instead of "
                    "redirecting. A visitor on an untrusted network can receive the "
                    "entire page — including forms — over an unencrypted connection "
                    "and never reach the TLS version."
                ),
                scope=f"GET {http_url} returned {resp.status}",
                remediation=(
                    "Return a 301 to the https:// equivalent and serve no content "
                    "over plain HTTP. Enable HSTS once HTTPS is confirmed working."
                ),
                tags=["transport", "https", "hsts"],
            )
        )
    elif resp.status in (301, 302, 303, 307, 308) and not redirects_to_https:
        findings.append(
            Finding(
                id="security.transport.http_redirects_http",
                title="http:// redirects to another http:// URL",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.http_response(resp.status, resp.headers, source=http_url),
                reasoning=(
                    f"The plaintext endpoint redirects to {location}, which is still "
                    "plain HTTP. The whole redirect happens in the clear."
                ),
                scope=f"GET {http_url} -> {location}",
                remediation="Redirect directly to the https:// equivalent.",
                tags=["transport", "https"],
            )
        )

    return findings


@register_probe(
    id="security.transport.http_versions",
    category=Category.SECURITY,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("http_response",),
    title="HTTP version support",
    description="Whether the server negotiates HTTP/2 (or falls back to 1.1).",
    tags=("transport", "http2", "performance"),
)
async def check_http_versions(ctx: ProbeContext) -> list[Finding]:
    """Report the negotiated HTTP version on the homepage response."""
    findings: list[Finding] = []
    resp = ctx.require("http_response")
    if not resp.ok:
        return findings

    # httpx exposes the negotiated version on the underlying response, but our
    # FetchedResponse does not capture it. We infer from the presence of
    # HTTP/2-only pseudo-headers in the redirect chain note, so instead we do
    # one explicit probe request and read the version from the extension info.
    http = ctx.http_client
    client = http._client  # noqa: SLF001
    if client is None:
        return findings

    base = ctx.target.base_url
    await http.limiter.acquire()
    try:
        probe = await client.get(f"{base}/")
        version = probe.extensions.get("http_version", b"").decode(errors="ignore") or "unknown"
        altsvc = probe.headers.get("alt-svc", "")
    except Exception:  # noqa: BLE001
        return findings

    source = f"GET {base}/"
    evidence = Evidence.text(
        f"negotiated: {version}\nalt-svc: {altsvc or '(none)'}",
        source=source,
    )

    if version in {"HTTP/2", "h2", "HTTP/3"}:
        findings.append(
            Finding(
                id="security.transport.http2_negotiated",
                title=f"Connection negotiated {version}",
                category=Category.SECURITY,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                reasoning=(
                    f"The homepage was served over {version}. Multiplexing improves "
                    "page-load latency and header compression (HPACK/QPACK) reduces "
                    "on-the-wire exposure of repeated headers."
                ),
                scope=source,
                tags=["transport", "http2", "performance", "strength"],
            )
        )
    elif version in {"HTTP/1.1", "HTTP/1.0", "h1"}:
        findings.append(
            Finding(
                id="security.transport.http1_only",
                title=f"Connection negotiated {version} (no HTTP/2)",
                category=Category.SECURITY,
                kind=FindingKind.OBSERVATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                reasoning=(
                    "The server negotiated HTTP/1.1, not HTTP/2. This is not a "
                    "security defect but it costs real page-load latency on "
                    "asset-heavy pages, which indirectly affects Core Web Vitals."
                ),
                scope=source,
                remediation="Enable HTTP/2 (and ideally HTTP/3/QUIC) at the server or CDN.",
                tags=["transport", "http2", "performance"],
            )
        )

    if altsvc and ("h3" in altsvc.lower() or "quic" in altsvc.lower()):
        findings.append(
            Finding(
                id="security.transport.http3_available",
                title="HTTP/3 (QUIC) available via alt-svc",
                category=Category.SECURITY,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                reasoning="The server advertises HTTP/3 via Alt-Svc, offering the lowest-latency transport.",
                scope=source,
                tags=["transport", "http3", "performance", "strength"],
            )
        )

    return findings
