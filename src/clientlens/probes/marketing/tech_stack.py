"""Technology stack fingerprinting.

Pattern matching against the bundled Wappalyzer-derived rule set. Mainstream
stacks are detected with high accuracy; custom or obfuscated builds may not
match, which is why the output is labelled as "detected", not "complete".
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
from ..shared import fingerprints


@register_probe(
    id="marketing.tech_stack",
    category=Category.MARKETING,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("html", "http_response"),
    title="Technology stack fingerprint",
    description="CMS, framework, CDN, hosting, e-commerce and marketing tooling in use.",
    tags=("recon", "tech-stack", "competitive-intel"),
)
async def check_tech_stack(ctx: ProbeContext) -> list[Finding]:
    """Fingerprint the technology stack from headers, HTML and cookies."""
    html = ctx.require("html")
    resp = ctx.require("http_response")
    findings: list[Finding] = []
    source = html.final_url

    meta_generator = html.meta(name="generator")
    cookie_names = _cookie_names(resp.headers)

    hits = fingerprints.match_tech(
        html_blob=html.raw,
        headers=resp.headers,
        meta_generator=meta_generator,
        cookie_names=cookie_names,
    )

    if not hits:
        findings.append(
            Finding(
                id="marketing.tech_stack.none_detected",
                title="No technologies matched the fingerprint database",
                category=Category.MARKETING,
                kind=FindingKind.GAP,
                severity=Severity.INFO,
                confidence=Confidence.NEEDS_REVIEW,
                evidence=Evidence.text(
                    f"Inspected {len(resp.headers)} response header(s), "
                    f"{len(html.raw)} bytes of HTML and {len(cookie_names)} cookie(s). "
                    "No bundled rule matched.",
                    source=source,
                ),
                reasoning=(
                    "This is a detection gap, not a blank stack. Custom-built sites, "
                    "aggressive server hardening and front-end bundling all reduce "
                    "what is visible to fingerprinting."
                ),
                scope=f"Headers, HTML and cookies of {source}",
                tags=["tech-stack", "negative-result", "needs-review"],
            )
        )
        return findings

    # ---- inventory ---------------------------------------------------------
    by_category: dict[str, list[fingerprints.TechRule]] = {}
    for rule in hits:
        by_category.setdefault(rule.category, []).append(rule)

    lines = []
    for category in sorted(by_category):
        label = fingerprints.category_label(category)
        names = ", ".join(sorted({r.name for r in by_category[category]}))
        lines.append(f"{label}: {names}")

    findings.append(
        Finding(
            id="marketing.tech_stack.inventory",
            title=f"{len({r.name for r in hits})} technology/technologies detected",
            category=Category.MARKETING,
            kind=FindingKind.OBSERVATION,
            severity=Severity.INFO,
            confidence=Confidence.LIKELY,
            evidence=Evidence.text("\n".join(lines), summary="tech stack", source=source),
            reasoning=(
                "Fingerprinted from response headers, HTML source, meta generator "
                "and cookies. Mainstream stacks match reliably; bespoke builds may "
                "not appear. This inventory is useful both for security scoping and "
                "for understanding how the site is put together."
            ),
            scope=f"Headers, HTML and cookies of {source}",
            tags=["tech-stack", "inventory"],
        )
    )

    # ---- CMS ---------------------------------------------------------------
    cms = by_category.get("cms", []) + by_category.get("builder", [])
    if cms:
        findings.append(
            Finding(
                id="marketing.tech_stack.cms",
                title=f"Site is built on {', '.join(sorted({r.name for r in cms}))}",
                category=Category.MARKETING,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.LIKELY,
                evidence=Evidence.text("; ".join(sorted({r.name for r in cms})), source=source),
                reasoning=(
                    "The CMS determines what the team can change without a "
                    "developer, which plugins/extensions are in the attack surface, "
                    "and how hard SEO fixes are to ship."
                ),
                scope=f"HTML and headers of {source}",
                tags=["tech-stack", "cms"],
            )
        )

    # ---- security product (positive signal) --------------------------------
    waf = by_category.get("waf", []) + by_category.get("security", [])
    if waf:
        findings.append(
            Finding(
                id="marketing.tech_stack.waf",
                title=f"Edge/WAF protection detected: {', '.join(sorted({r.name for r in waf}))}",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.LIKELY,
                evidence=Evidence.text("; ".join(sorted({r.name for r in waf})), source=source),
                reasoning=(
                    "An edge protection service is in front of the origin. This "
                    "provides DDoS mitigation and a baseline of common-attack "
                    "filtering. It does not replace application-level testing."
                ),
                scope=f"Response headers of {source}",
                tags=["tech-stack", "waf", "strength"],
            )
        )

    # ---- CDN ---------------------------------------------------------------
    cdn = by_category.get("cdn", [])
    if cdn:
        findings.append(
            Finding(
                id="marketing.tech_stack.cdn",
                title=f"CDN in use: {', '.join(sorted({r.name for r in cdn}))}",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.LIKELY,
                evidence=Evidence.text("; ".join(sorted({r.name for r in cdn})), source=source),
                reasoning=(
                    "A CDN serves static assets from edge locations, which improves "
                    "Core Web Vitals for geographically distributed audiences and "
                    "absorbs traffic spikes."
                ),
                scope=f"Response headers of {source}",
                tags=["tech-stack", "cdn", "performance", "strength"],
            )
        )

    # ---- hosting (attack surface note) ------------------------------------
    hosting = by_category.get("hosting", [])
    if hosting:
        findings.append(
            Finding(
                id="marketing.tech_stack.hosting",
                title=f"Hosting platform: {', '.join(sorted({r.name for r in hosting}))}",
                category=Category.MARKETING,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.LIKELY,
                evidence=Evidence.text("; ".join(sorted({r.name for r in hosting})), source=source),
                reasoning=(
                    "Identified from response headers. Knowing the platform is "
                    "useful for scoping patching responsibility and for "
                    "understanding the deployment model."
                ),
                scope=f"Response headers of {source}",
                tags=["tech-stack", "hosting"],
            )
        )

    # ---- generator meta (disclosure note) ---------------------------------
    if meta_generator:
        findings.append(
            Finding(
                id="marketing.tech_stack.generator_disclosed",
                title=f"Meta generator discloses the platform: {meta_generator[:80]}",
                category=Category.MARKETING,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node(
                    "meta[name=generator]",
                    f'<meta name="generator" content="{meta_generator}">',
                    source=source,
                ),
                reasoning=(
                    "The generator meta tag is a convenience for humans and a "
                    "free fingerprint for anyone enumerating targets. It often "
                    "carries a version number, which tells an attacker exactly "
                    "which CVEs to look up."
                ),
                scope=f"HTML <head> of {source}",
                remediation="Remove the generator meta tag on production.",
                tags=["tech-stack", "disclosure", "fingerprint"],
            )
        )

    return findings


def _cookie_names(headers: dict[str, str]) -> list[str]:
    out: list[str] = []
    for key, value in headers.items():
        if key.lower() != "set-cookie":
            continue
        first = value.split(";")[0]
        if "=" in first:
            out.append(first.split("=", 1)[0].strip())
    return out
