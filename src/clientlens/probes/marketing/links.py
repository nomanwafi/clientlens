"""Link profile and outbound-link hygiene.

Link counts are exact for the sampled document. Broken-link status is only
asserted for URLs we actually requested and got a non-2xx response from.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ...core.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    FindingKind,
    Severity,
)
from ...core.registry import ProbeContext, ProbeMode, ProbePhase, register_probe
from ..shared.html import build_link_inventory


@register_probe(
    id="marketing.links",
    category=Category.MARKETING,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("html",),
    title="Internal / external link inventory",
    description="Link counts, external-link ratio and nofollow usage on the homepage.",
    tags=("seo", "links", "internal-linking"),
)
async def check_links(ctx: ProbeContext) -> list[Finding]:
    """Analyse the homepage link graph."""
    html = ctx.require("html")
    findings: list[Finding] = []
    source = html.final_url

    inv = build_link_inventory(html, sample_limit=ctx.config.link_sample_size)

    findings.append(
        Finding(
            id="marketing.links.inventory",
            title=f"{inv.total} link(s): {len(inv.internal)} internal, {len(inv.external)} external",
            category=Category.MARKETING,
            kind=FindingKind.OBSERVATION,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            evidence=Evidence.text(
                f"internal: {len(inv.internal)}\nexternal: {len(inv.external)}\n"
                f"nofollow: {len(inv.nofollow)}\nexternal ratio: {inv.external_ratio:.0%}",
                source=source,
            ),
            reasoning=(
                "Link structure is the main way authority flows through a site "
                "and how crawlers discover pages. The counts here are exact for "
                "the homepage document."
            ),
            scope=f"HTML <a> elements of {source}",
            tags=["seo", "links"],
        )
    )

    # ---- external link ratio ----------------------------------------------
    if inv.total >= 10 and inv.external_ratio > 0.5:
        findings.append(
            Finding(
                id="marketing.links.heavy_external",
                title=f"{inv.external_ratio:.0%} of homepage links are external",
                category=Category.MARKETING,
                kind=FindingKind.OBSERVATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.urls(inv.external[:30], source=source),
                reasoning=(
                    "More than half of the outbound links leave the site. That is "
                    "common on directories and partner pages and unusual on a "
                    "product homepage — where it can send crawl budget and user "
                    "attention off-site before they've seen the offer."
                ),
                scope=f"HTML <a> elements of {source}",
                tags=["seo", "links"],
            )
        )

    # ---- nofollow usage ---------------------------------------------------
    if inv.nofollow:
        findings.append(
            Finding(
                id="marketing.links.nofollow",
                title=f"{len(inv.nofollow)} link(s) marked rel=nofollow",
                category=Category.MARKETING,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.urls(inv.nofollow[:30], source=source),
                reasoning=(
                    "These links are marked as not endorsing the destination. This "
                    "is the correct pattern for paid, sponsored or user-generated "
                    "links."
                ),
                scope=f"HTML <a rel=nofollow> of {source}",
                tags=["seo", "links", "nofollow"],
            )
        )

    # ---- sponsored / ugc --------------------------------------------------
    sponsored = _rel_counts(html)
    if sponsored.get("sponsored") or sponsored.get("ugc"):
        findings.append(
            Finding(
                id="marketing.links.rel_annotations",
                title=f"rel=sponsored: {sponsored.get('sponsored', 0)}, rel=ugc: {sponsored.get('ugc', 0)}",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(str(sponsored), source=source),
                reasoning=(
                    "Explicit sponsored/ugc annotations are what Google asks for "
                    "instead of nofollow on those link types. Their presence is a "
                    "positive signal of link hygiene."
                ),
                scope=f"HTML <a> elements of {source}",
                tags=["seo", "links", "strength"],
            )
        )

    # ---- suspicious outbound patterns -------------------------------------
    suspicious = [u for u in inv.external if _looks_suspicious(u)]
    if suspicious:
        findings.append(
            Finding(
                id="marketing.links.suspicious_outbound",
                title=f"{len(suspicious)} outbound link(s) with unusual characteristics",
                category=Category.MARKETING,
                kind=FindingKind.VULNERABILITY_VECTOR,
                severity=Severity.MEDIUM,
                confidence=Confidence.NEEDS_REVIEW,
                evidence=Evidence.urls(suspicious[:30], source=source),
                reasoning=(
                    "These outbound links use IP-literal hosts, non-standard ports "
                    "or URL shorteners. That pattern appears in SEO spam injections "
                    "and in compromised CMS installs, where injected links are added "
                    "to the template. It also appears in perfectly legitimate "
                    "affiliate and developer content — hence 'needs review' rather "
                    "than a claim of compromise."
                ),
                scope=f"HTML <a> elements of {source}",
                remediation="Confirm each destination was intentionally placed. Remove anything unexpected.",
                tags=["seo", "links", "spam", "needs-review", "security"],
            )
        )

    return findings


@register_probe(
    id="marketing.links.broken",
    category=Category.MARKETING,
    mode=ProbeMode.ACTIVE,
    phase=ProbePhase.ACTIVE,
    requires=("html",),
    title="Broken link spot-check",
    description="Requests a bounded sample of internal links and reports the ones that fail.",
    tags=("seo", "links", "crawl-health"),
)
async def check_broken_links(ctx: ProbeContext) -> list[Finding]:
    """Request a bounded sample of internal links and report failures."""
    html = ctx.require("html")
    http = ctx.http_client
    findings: list[Finding] = []
    source = html.final_url

    internal = html.links(same_host_only=True)
    sample = internal[: min(25, ctx.config.link_sample_size)]

    if not sample:
        findings.append(
            Finding(
                id="marketing.links.broken.no_sample",
                title="No internal links available to sample",
                category=Category.MARKETING,
                kind=FindingKind.GAP,
                severity=Severity.INFO,
                confidence=Confidence.NEEDS_REVIEW,
                evidence=Evidence.text("Homepage has no internal <a href> links.", source=source),
                reasoning=(
                    "A homepage with no internal links is unusual and is itself a "
                    "crawlability problem — crawlers and users have nowhere to go "
                    "next. Nothing could be sampled for broken-link checking."
                ),
                scope=f"HTML <a> elements of {source}",
                tags=["seo", "links", "needs-review"],
            )
        )
        return findings

    broken: list[tuple[str, int, str]] = []
    checked = 0

    for url in sample:
        resp = await http.get(url, follow=True)
        checked += 1
        if resp.status in (404, 410) or (resp.status >= 500):
            broken.append((url, resp.status, resp.final_url))

    if broken:
        findings.append(
            Finding(
                id="marketing.links.broken.found",
                title=f"{len(broken)} broken link(s) in a sample of {checked}",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.urls(
                    [f"{u} -> {s} ({final})" for u, s, final in broken[:30]], source=source
                ),
                reasoning=(
                    "Each of these links resolves to a 4xx or 5xx response. Broken "
                    "links waste crawl budget, send users to dead ends and are one "
                    "of the few technical SEO issues with a direct user-visible "
                    "consequence."
                ),
                scope=f"{checked} sampled internal links from {source}",
                remediation="Fix or remove each dead link, and add a redirect for retired URLs.",
                tags=["seo", "links", "broken", "crawl-health"],
            )
        )
    else:
        findings.append(
            Finding(
                id="marketing.links.broken.clean",
                title=f"No broken links in a sample of {checked}",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.urls(
                    sample[:checked], summary=f"{checked} checked", source=source
                ),
                reasoning=(
                    f"Every one of the {checked} sampled internal links returned a "
                    "2xx/3xx response. This is a sample, not a full crawl."
                ),
                scope=f"{checked} sampled internal links from {source}",
                tags=["seo", "links", "strength"],
            )
        )

    return findings


def _rel_counts(html) -> dict[str, int]:
    counts = {"nofollow": 0, "sponsored": 0, "ugc": 0}
    for a in html.soup.find_all("a", rel=True):
        rels = a.get("rel")
        if isinstance(rels, str):
            rels = [rels]
        for r in rels:
            key = r.lower()
            if key in counts:
                counts[key] += 1
    return counts


def _looks_suspicious(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except Exception:  # noqa: BLE001
        return True
    host = parsed.hostname or ""
    if not host:
        return True
    # IP-literal host
    if all(part.isdigit() for part in host.split(".")) and host.count(".") == 3:
        return True
    if parsed.port and parsed.port not in (80, 443, 8080, 8443):
        return True
    shorteners = {
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly",
        "shorturl.at",
        "rb.gy",
    }
    return host in shorteners
