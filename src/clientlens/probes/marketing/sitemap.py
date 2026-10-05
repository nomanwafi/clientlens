"""robots.txt and sitemap.xml health.

These files are fetched and parsed as-is. Their contents are reported verbatim
because they are the site's own declarations.
"""

from __future__ import annotations

import re

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
    id="marketing.sitemap",
    category=Category.MARKETING,
    mode=ProbeMode.ACTIVE,
    phase=ProbePhase.ACTIVE,
    requires=("http_response",),
    title="robots.txt & sitemap.xml health",
    description="Presence, parseability and discoverability of the crawl-control files.",
    tags=("seo", "crawl", "indexing", "sitemap"),
)
async def check_sitemap(ctx: ProbeContext) -> list[Finding]:
    """Fetch and parse robots.txt and sitemap.xml."""
    findings: list[Finding] = []
    base = ctx.target.base_url
    http = ctx.http_client

    # ---- robots.txt --------------------------------------------------------
    robots = await http.get(f"{base}/robots.txt", follow=True)

    sitemap_declared: list[str] = []
    disallow_count = 0
    user_agents: list[str] = []

    if robots.status == 200 and robots.body.strip():
        for line in robots.body.splitlines():
            stripped = line.strip()
            low = stripped.lower()
            if low.startswith("sitemap:"):
                sitemap_declared.append(stripped.split(":", 1)[1].strip())
            elif low.startswith("disallow:"):
                if stripped.split(":", 1)[1].strip():
                    disallow_count += 1
            elif low.startswith("user-agent:"):
                user_agents.append(stripped.split(":", 1)[1].strip())

        findings.append(
            Finding(
                id="marketing.sitemap.robots_present",
                title=f"robots.txt present ({len(user_agents)} user-agent group(s))",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.http_response(
                    robots.status, robots.headers, robots.snippet(800), source=f"{base}/robots.txt"
                ),
                reasoning=(
                    f"robots.txt declares {disallow_count} non-empty Disallow rule(s) "
                    f"and {len(sitemap_declared)} Sitemap directive(s). This file "
                    "controls crawl access, not security."
                ),
                scope=f"GET {base}/robots.txt",
                tags=["seo", "crawl", "strength"],
            )
        )

        if not sitemap_declared:
            findings.append(
                Finding(
                    id="marketing.sitemap.robots_no_sitemap_directive",
                    title="robots.txt does not declare a Sitemap",
                    category=Category.MARKETING,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.http_response(
                        robots.status,
                        robots.headers,
                        robots.snippet(400),
                        source=f"{base}/robots.txt",
                    ),
                    reasoning=(
                        "The Sitemap directive is how a crawler reliably finds the "
                        "sitemap regardless of where it is hosted. Without it, "
                        "discovery depends on the sitemap being at the conventional "
                        "location or linked in the console."
                    ),
                    scope=f"GET {base}/robots.txt",
                    remediation=f"Add `Sitemap: {base}/sitemap.xml` to robots.txt.",
                    tags=["seo", "crawl", "sitemap"],
                )
            )

        # Disallow rules that also block CSS/JS — a common rendering problem.
        blocking_assets = [
            line.split(":", 1)[1].strip()
            for line in robots.body.splitlines()
            if line.strip().lower().startswith("disallow:")
            and re.search(r"(\.css|\.js|/wp-content|/assets|/static|/css|/js)", line, re.I)
        ]
        if blocking_assets:
            findings.append(
                Finding(
                    id="marketing.sitemap.robots_blocks_assets",
                    title="robots.txt Disallow rules cover CSS/JS asset paths",
                    category=Category.MARKETING,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.urls(blocking_assets[:20], source=f"{base}/robots.txt"),
                    reasoning=(
                        "Blocking stylesheets or scripts makes the page render as "
                        "unstyled text to Googlebot, which then evaluates a page "
                        "that users never see. This used to be the single most "
                        "common cause of mysterious ranking drops."
                    ),
                    scope=f"Disallow rules in {base}/robots.txt",
                    remediation="Remove Disallow rules covering CSS, JS and image assets.",
                    tags=["seo", "crawl", "rendering"],
                )
            )
    else:
        findings.append(
            Finding(
                id="marketing.sitemap.robots_missing",
                title="robots.txt not available",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.http_response(
                    robots.status, robots.headers, robots.snippet(200), source=f"{base}/robots.txt"
                ),
                reasoning=(
                    f"GET {base}/robots.txt returned {robots.status or 'no response'}. "
                    "Without it the site has no crawl guidance and no Sitemap "
                    "declaration. Crawlers will fetch everything they can find."
                ),
                scope=f"GET {base}/robots.txt",
                remediation=f"Publish a robots.txt with a Sitemap directive pointing at {base}/sitemap.xml.",
                tags=["seo", "crawl"],
            )
        )

    # ---- sitemap.xml -------------------------------------------------------
    sitemap_urls = sitemap_declared or [f"{base}/sitemap.xml"]
    checked_any = False

    for sitemap_url in sitemap_urls[:3]:
        sm = await http.get(sitemap_url, follow=True)
        if sm.status != 200 or not sm.body.strip():
            continue
        checked_any = True

        is_index = "<sitemapindex" in sm.body[:2000].lower()
        url_count = len(re.findall(r"<loc>", sm.body, re.I))
        has_lastmod = "<lastmod>" in sm.body.lower()

        findings.append(
            Finding(
                id="marketing.sitemap.present",
                title=f"{'Sitemap index' if is_index else 'Sitemap'} present at {sitemap_url}",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.http_response(
                    sm.status, sm.headers, sm.snippet(600), source=sitemap_url
                ),
                reasoning=(
                    f"Contains {url_count} <loc> entr{'ies' if url_count != 1 else 'y'}. "
                    + (
                        "It is a sitemap index referencing child sitemaps."
                        if is_index
                        else "It is a flat sitemap."
                    )
                    + (
                        " lastmod is present, which helps crawlers prioritise."
                        if has_lastmod
                        else " lastmod is absent, so crawlers get no freshness signal."
                    )
                ),
                scope=f"GET {sitemap_url}",
                tags=["seo", "sitemap", "strength"],
            )
        )

        if url_count == 0:
            findings.append(
                Finding(
                    id="marketing.sitemap.empty",
                    title="Sitemap contains no <loc> entries",
                    category=Category.MARKETING,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.http_response(
                        sm.status, sm.headers, sm.snippet(300), source=sitemap_url
                    ),
                    reasoning=(
                        "An empty sitemap tells crawlers there is nothing to index. "
                        "It is usually a generation error rather than a deliberate "
                        "choice."
                    ),
                    scope=f"GET {sitemap_url}",
                    remediation="Regenerate the sitemap from the CMS and verify it lists the real URLs.",
                    tags=["seo", "sitemap"],
                )
            )

        if not has_lastmod and not is_index:
            findings.append(
                Finding(
                    id="marketing.sitemap.no_lastmod",
                    title="Sitemap has no <lastmod> values",
                    category=Category.MARKETING,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.http_response(
                        sm.status, sm.headers, sm.snippet(300), source=sitemap_url
                    ),
                    reasoning=(
                        "Without lastmod, a crawler must refetch every URL to find "
                        "out what changed. On a large site that wastes crawl budget "
                        "on unchanged pages."
                    ),
                    scope=f"GET {sitemap_url}",
                    remediation="Include an accurate <lastmod> per URL.",
                    tags=["seo", "sitemap"],
                )
            )

    if not checked_any:
        findings.append(
            Finding(
                id="marketing.sitemap.missing",
                title="No reachable sitemap found",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.urls(
                    sitemap_urls,
                    summary="all returned non-200 or empty",
                    source=f"{base}/",
                ),
                reasoning=(
                    "None of the candidate sitemap URLs returned usable content. "
                    "Without a sitemap, discovery depends entirely on internal link "
                    "crawling, which is slower and misses orphan pages."
                ),
                scope=f"GET {', '.join(sitemap_urls)}",
                remediation=f"Publish a sitemap at {base}/sitemap.xml and declare it in robots.txt.",
                tags=["seo", "sitemap", "crawl"],
            )
        )

    return findings
