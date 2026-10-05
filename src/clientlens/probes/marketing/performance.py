"""Performance signals observable from a single fetch.

These are *lab* measurements of one request: TTFB, payload size, resource
count, compression. Real-user Core Web Vitals require field data (CrUX) which
is not collected in this build — that gap is stated explicitly.
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

TTFB_GOOD_MS = 800
TTFB_POOR_MS = 1800
HTML_SIZE_WARN_BYTES = 300_000
RESOURCE_WARN_COUNT = 80


@register_probe(
    id="marketing.performance",
    category=Category.MARKETING,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("html", "http_response"),
    title="Performance signals (lab)",
    description="TTFB, HTML payload size, resource count and compression on the homepage.",
    tags=("performance", "core-web-vitals", "seo"),
)
async def check_performance(ctx: ProbeContext) -> list[Finding]:
    """Measure what a single request reveals about page weight and speed."""
    html = ctx.require("html")
    resp = ctx.require("http_response")
    findings: list[Finding] = []
    source = html.final_url

    if not resp.ok:
        return findings

    # ---- TTFB --------------------------------------------------------------
    ttfb = resp.elapsed_ms
    evidence_ttfb = Evidence.text(
        f"TTFB / total time: {ttfb}ms\nstatus: {resp.status}\nfinal URL: {resp.final_url}",
        source=f"GET {resp.url}",
    )

    if ttfb > TTFB_POOR_MS:
        severity = Severity.MEDIUM
        finding_kind = FindingKind.MISCONFIGURATION
        title = f"TTFB is {ttfb}ms — well above the {TTFB_GOOD_MS}ms target"
        reasoning = (
            f"Time to first byte measured {ttfb}ms. Google treats TTFB over "
            f"{TTFB_POOR_MS}ms as poor, and it is the floor for every other "
            "loading metric — nothing can start painting before the first byte "
            "arrives. Server-side caching is the usual fix."
        )
    elif ttfb > TTFB_GOOD_MS:
        severity = Severity.LOW
        finding_kind = FindingKind.MISCONFIGURATION
        title = f"TTFB is {ttfb}ms — above the {TTFB_GOOD_MS}ms target"
        reasoning = (
            f"Time to first byte measured {ttfb}ms, which is above the "
            f"{TTFB_GOOD_MS}ms guideline. Not critical, but it consumes the "
            "loading budget before any rendering work begins."
        )
    else:
        severity = Severity.INFO
        finding_kind = FindingKind.STRENGTH
        title = f"TTFB is {ttfb}ms — within target"
        reasoning = (
            f"Time to first byte measured {ttfb}ms, inside the {TTFB_GOOD_MS}ms "
            "guideline. Server is responding quickly."
        )

    findings.append(
        Finding(
            id="marketing.performance.ttfb",
            title=title,
            category=Category.MARKETING,
            kind=finding_kind,
            severity=severity,
            confidence=Confidence.CONFIRMED,
            evidence=evidence_ttfb,
            reasoning=reasoning,
            scope=f"GET {resp.url}",
            remediation=(
                "Enable full-page caching at the edge, reduce origin work before "
                "the first byte, and use a CDN."
            )
            if severity is not Severity.INFO
            else "",
            tags=["performance", "ttb", "core-web-vitals"],
        )
    )

    # ---- HTML payload ------------------------------------------------------
    html_size = len(html.raw.encode("utf-8", errors="ignore"))
    if html_size > HTML_SIZE_WARN_BYTES:
        findings.append(
            Finding(
                id="marketing.performance.html_heavy",
                title=f"HTML payload is {html_size / 1024:.0f} KB",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(f"HTML size: {html_size} bytes", source=source),
                reasoning=(
                    f"The initial HTML is over {HTML_SIZE_WARN_BYTES // 1000} KB "
                    "uncompressed. Everything else in the critical path waits on "
                    "this document, so a heavy HTML delays first paint directly. "
                    "Large inline CSS/JS and server-rendered lists are the usual "
                    "causes."
                ),
                scope=f"GET {resp.url}",
                remediation="Move inline assets to external files, paginate server-rendered lists, enable gzip/brotli.",
                tags=["performance", "payload"],
            )
        )
    else:
        findings.append(
            Finding(
                id="marketing.performance.html_size",
                title=f"HTML payload is {html_size / 1024:.1f} KB",
                category=Category.MARKETING,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(f"HTML size: {html_size} bytes", source=source),
                reasoning="Initial document size is reasonable.",
                scope=f"GET {resp.url}",
                tags=["performance", "payload"],
            )
        )

    # ---- resource count ----------------------------------------------------
    scripts = html.scripts()
    styles = html.stylesheets()
    images = html.images()
    total = len(scripts) + len(styles) + len(images)

    resource_lines = (
        f"scripts:      {len(scripts)}\n"
        f"stylesheets:  {len(styles)}\n"
        f"images:       {len(images)}\n"
        f"total tags:   {total}"
    )

    if total > RESOURCE_WARN_COUNT:
        findings.append(
            Finding(
                id="marketing.performance.many_resources",
                title=f"{total} subresource tags on the page",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(resource_lines, source=source),
                reasoning=(
                    f"{total} tags referencing external resources. Each one is a "
                    "network request, a DNS lookup and a render-blocking candidate. "
                    "Third-party tags in particular multiply latency because they "
                    "queue behind their own connection setup."
                ),
                scope=f"HTML source of {source}",
                remediation="Audit third-party tags, defer non-critical scripts, and lazy-load images.",
                tags=["performance", "third-party"],
            )
        )
    else:
        findings.append(
            Finding(
                id="marketing.performance.resource_count",
                title=f"{total} subresource tags on the page",
                category=Category.MARKETING,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(resource_lines, source=source),
                reasoning="Subresource count is within a normal range for a marketing site.",
                scope=f"HTML source of {source}",
                tags=["performance"],
            )
        )

    # ---- compression -------------------------------------------------------
    encoding = resp.headers.get("content-encoding", "")
    if encoding:
        findings.append(
            Finding(
                id="marketing.performance.compression",
                title=f"Response compressed with {encoding}",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.http_headers(
                    {
                        "content-encoding": encoding,
                        "content-length": resp.headers.get("content-length", ""),
                    },
                    source=f"GET {resp.url}",
                ),
                reasoning="Compression reduces transfer size, which improves Largest Contentful Paint.",
                scope=f"GET {resp.url}",
                tags=["performance", "compression", "strength"],
            )
        )
    else:
        findings.append(
            Finding(
                id="marketing.performance.no_compression",
                title="Response is not compressed",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.http_headers(resp.headers, source=f"GET {resp.url}"),
                reasoning=(
                    "No Content-Encoding header was returned. Uncompressed HTML is "
                    "typically 3-5x larger on the wire than the same content with "
                    "brotli or gzip."
                ),
                scope=f"GET {resp.url}",
                remediation="Enable brotli or gzip at the server/CDN for text responses.",
                tags=["performance", "compression"],
            )
        )

    # ---- cache headers -----------------------------------------------------
    cache_control = resp.headers.get("cache-control", "")
    if not cache_control:
        findings.append(
            Finding(
                id="marketing.performance.no_cache_headers",
                title="No Cache-Control header on the HTML response",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.http_headers(resp.headers, source=f"GET {resp.url}"),
                reasoning=(
                    "Without Cache-Control, intermediaries and browsers guess how "
                    "long to keep the document. On repeat visits that usually means "
                    "a full re-download and a slower return visit."
                ),
                scope=f"GET {resp.url}",
                remediation="Set an explicit Cache-Control policy; use stale-while-revalidate for HTML.",
                tags=["performance", "caching"],
            )
        )

    # ---- field data gap (explicit) ----------------------------------------
    findings.append(
        Finding(
            id="marketing.performance.field_data_gap",
            title="Real-user Core Web Vitals not collected",
            category=Category.MARKETING,
            kind=FindingKind.GAP,
            severity=Severity.INFO,
            confidence=Confidence.NEEDS_REVIEW,
            evidence=Evidence.none(
                "CrUX / PageSpeed Insights field data not enabled in this build"
            ),
            reasoning=(
                "The measurements above are lab observations of a single request "
                "from one location. LCP, CLS and INP as experienced by real users "
                "require Chrome UX Report field data, which is not gathered in this "
                "build. Do not read the lab TTFB as a Core Web Vitals score."
            ),
            scope="Field data collection",
            tags=["performance", "coverage-gap", "core-web-vitals", "needs-review"],
        )
    )

    return findings
