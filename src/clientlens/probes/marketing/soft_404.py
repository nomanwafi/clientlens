"""Soft-404 detection — does a missing page admit it is missing?

A site that returns HTTP 200 with a "page not found" message for a URL that
does not exist is serving a *soft 404*. Search engines then index the error
page as real content, waste crawl budget on it, and split ranking signals
across infinite URLs. One request to a certainly-nonexistent path answers this.
"""

from __future__ import annotations

import uuid

from ...core.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    FindingKind,
    Severity,
)
from ...core.registry import ProbeContext, ProbeMode, ProbePhase, register_probe

NOT_FOUND_MARKERS = (
    "404",
    "not found",
    "no longer available",
    "page doesn't exist",
    "page does not exist",
    "cannot be found",
    "couldn't find",
    "does not exist",
    "nothing here",
    "has been removed",
)


@register_probe(
    id="marketing.soft_404",
    category=Category.MARKETING,
    mode=ProbeMode.ACTIVE,
    phase=ProbePhase.ACTIVE,
    requires=("http_response",),
    title="Soft-404 handling",
    description="One request to a nonexistent path to verify real 404s return 404.",
    tags=("seo", "crawl", "404", "indexing"),
)
async def check_soft_404(ctx: ProbeContext) -> list[Finding]:
    """Fetch a random nonexistent path and check the response shape."""
    findings: list[Finding] = []
    http = ctx.http_client
    if http is None:
        return findings

    base = ctx.target.base_url
    token = uuid.uuid4().hex[:16]
    probe_path = f"/clientlens-404-probe-{token}"
    url = f"{base}{probe_path}"

    await http.limiter.acquire()
    resp = await http.get(url, follow=True)

    if resp.error:
        findings.append(
            Finding(
                id="marketing.soft_404.untested",
                title="Soft-404 check could not complete",
                category=Category.MARKETING,
                kind=FindingKind.GAP,
                severity=Severity.INFO,
                confidence=Confidence.NEEDS_REVIEW,
                evidence=Evidence.text(resp.error, source=f"GET {url}"),
                reasoning=(
                    "The probe request failed, so the site's 404 behaviour is "
                    "unknown. This is a coverage gap, not a clean result."
                ),
                scope=f"GET {url}",
                tags=["seo", "404", "gap"],
            )
        )
        return findings

    body_lower = (resp.body or "")[:5000].lower()
    says_not_found = any(marker in body_lower for marker in NOT_FOUND_MARKERS)

    if resp.status == 404:
        findings.append(
            Finding(
                id="marketing.soft_404.correct",
                title="Nonexistent URL returns a real HTTP 404",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(
                    f"GET {probe_path} -> HTTP {resp.status}",
                    source=f"GET {url}",
                ),
                reasoning=(
                    "The server returns 404 for a URL that does not exist. Search "
                    "engines will drop it from the index instead of storing the "
                    "error page as content, and crawl budget is not wasted."
                ),
                scope=f"GET {url}",
                tags=["seo", "404", "strength"],
            )
        )
    elif resp.status in {301, 302, 307, 308}:
        findings.append(
            Finding(
                id="marketing.soft_404.redirects",
                title=f"Nonexistent URL redirects (HTTP {resp.status})",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(
                    f"GET {probe_path} -> HTTP {resp.status} -> {resp.final_url}",
                    source=f"GET {url}",
                ),
                reasoning=(
                    "A URL that should not exist redirects instead of returning "
                    "404. If it redirects to the homepage, search engines treat "
                    "every mistyped or deleted URL as a homepage duplicate — the "
                    "classic soft-404 shape that inflates the index with copies."
                ),
                scope=f"GET {url}",
                remediation=(
                    "Return 404 (or 410 Gone) for URLs that do not exist. If the "
                    "redirect is deliberate, make the destination a real 404 page "
                    "rather than the homepage."
                ),
                tags=["seo", "404"],
            )
        )
    elif 200 <= resp.status < 300:
        severity = Severity.MEDIUM if says_not_found else Severity.LOW
        findings.append(
            Finding(
                id="marketing.soft_404.serving_200",
                title=f"Nonexistent URL returns HTTP {resp.status} (soft 404)",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=severity,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(
                    f"GET {probe_path} -> HTTP {resp.status}\n"
                    f"body looks like an error page: {says_not_found}",
                    source=f"GET {url}",
                ),
                reasoning=(
                    "A URL that does not exist returns a success status"
                    + (" and the body itself says the page is missing" if says_not_found else "")
                    + ". Search engines cannot tell the error page from real "
                    "content, so they index it. Combined with links or sitemaps "
                    "that generate many such URLs, this wastes crawl budget and "
                    "fills the index with useless pages."
                ),
                scope=f"GET {url}",
                remediation=(
                    "Configure the web server / framework to return HTTP 404 for "
                    "unknown paths. If the router catches all paths for an SPA, "
                    "add a real 404 route and return 404 status for it."
                ),
                tags=["seo", "404", "indexing"],
            )
        )
    else:
        findings.append(
            Finding(
                id="marketing.soft_404.server_error",
                title=f"Nonexistent URL returns HTTP {resp.status}",
                category=Category.MARKETING,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(
                    f"GET {probe_path} -> HTTP {resp.status}", source=f"GET {url}"
                ),
                reasoning=(
                    f"A missing URL returns HTTP {resp.status}. That is at least "
                    "not a soft 404, but a 4xx other than 404/410 is unusual for "
                    "a plain missing page."
                ),
                scope=f"GET {url}",
                tags=["seo", "404"],
            )
        )

    return findings
