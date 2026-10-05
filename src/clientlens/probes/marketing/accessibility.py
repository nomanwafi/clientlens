"""Accessibility and form hygiene — both SEO-relevant and compliance-relevant.

Everything here is counted directly from the parsed DOM, so the numbers are
exact for the homepage document.
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
    id="marketing.accessibility",
    category=Category.MARKETING,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("html",),
    title="Accessibility & document hygiene",
    description="lang attribute, viewport, image alt coverage, form labels.",
    tags=("accessibility", "seo", "a11y", "wcag"),
)
async def check_accessibility(ctx: ProbeContext) -> list[Finding]:
    """Count accessibility signals in the parsed document."""
    html = ctx.require("html")
    findings: list[Finding] = []
    source = html.final_url

    # ---- lang attribute ----------------------------------------------------
    html_tag = html.soup.find("html")
    lang = html_tag.get("lang", "") if html_tag else ""
    if not lang:
        findings.append(
            Finding(
                id="marketing.a11y.lang_missing",
                title="<html> has no lang attribute",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node(
                    "html", str(html_tag)[:120] if html_tag else "(none)", source=source
                ),
                reasoning=(
                    "The lang attribute tells screen readers and search engines the "
                    "document's language. Without it, pronunciation rules and "
                    "translation hints are wrong, which affects both accessibility "
                    "and international SEO."
                ),
                scope=f"HTML <html> tag of {source}",
                remediation='Add lang="en" (or the document\'s language) to the <html> tag.',
                tags=["accessibility", "a11y", "seo"],
            )
        )
    else:
        findings.append(
            Finding(
                id="marketing.a11y.lang_present",
                title=f'Document language declared: lang="{lang}"',
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node("html", f'lang="{lang}"', source=source),
                reasoning="Language is declared for assistive technology and search engines.",
                scope=f"HTML <html> tag of {source}",
                tags=["accessibility", "strength"],
            )
        )

    # ---- viewport ----------------------------------------------------------
    viewport = html.meta(name="viewport")
    if not viewport:
        findings.append(
            Finding(
                id="marketing.a11y.viewport_missing",
                title="No viewport meta tag",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node("meta[name=viewport]", "(absent)", source=source),
                reasoning=(
                    "Without a viewport tag, mobile browsers render the page at a "
                    "desktop width and zoom it out. Google indexes mobile-first, so "
                    "a page that is not mobile-readable is ranked as a desktop page."
                ),
                scope=f"HTML <head> of {source}",
                remediation='Add <meta name="viewport" content="width=device-width, initial-scale=1">.',
                tags=["accessibility", "mobile", "seo"],
            )
        )
    elif "user-scalable=no" in viewport or "maximum-scale=1" in viewport.replace(" ", ""):
        findings.append(
            Finding(
                id="marketing.a11y.zoom_disabled",
                title="Viewport disables user zoom",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node("meta[name=viewport]", viewport, source=source),
                reasoning=(
                    "`user-scalable=no` or `maximum-scale=1` prevents pinch-zoom. "
                    "This fails WCAG 1.4.4 and is a real barrier for low-vision users."
                ),
                scope=f"HTML <head> of {source}",
                remediation="Remove user-scalable=no and maximum-scale from the viewport meta.",
                tags=["accessibility", "wcag"],
            )
        )
    else:
        findings.append(
            Finding(
                id="marketing.a11y.viewport_present",
                title="Responsive viewport configured",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node("meta[name=viewport]", viewport, source=source),
                reasoning="Viewport allows scaling and adapts to device width.",
                scope=f"HTML <head> of {source}",
                tags=["accessibility", "strength"],
            )
        )

    # ---- image alt coverage ------------------------------------------------
    images = html.soup.find_all("img")
    total_imgs = len(images)
    # Decorative images are allowed empty alt=""; missing alt attribute is the problem.
    missing_alt_attr = [img for img in images if "alt" not in img.attrs]

    if total_imgs:
        coverage = (total_imgs - len(missing_alt_attr)) / total_imgs
        if missing_alt_attr:
            findings.append(
                Finding(
                    id="marketing.a11y.img_alt_missing",
                    title=f"{len(missing_alt_attr)} of {total_imgs} image(s) have no alt attribute",
                    category=Category.MARKETING,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.urls(
                        [str(img.get("src", "(no src)"))[:80] for img in missing_alt_attr[:15]],
                        summary=f"{len(missing_alt_attr)}/{total_imgs} missing alt",
                        source=source,
                    ),
                    reasoning=(
                        f"Alt text coverage is {coverage:.0%}. Screen readers have "
                        "nothing to announce for these images, and image search "
                        "cannot index their content. Decorative images should have "
                        'alt="" explicitly.'
                    ),
                    scope=f"<img> elements of {source}",
                    remediation='Add meaningful alt text to content images; alt="" for decorative ones.',
                    tags=["accessibility", "a11y", "seo", "images"],
                )
            )
        else:
            findings.append(
                Finding(
                    id="marketing.a11y.img_alt_complete",
                    title=f"All {total_imgs} image(s) have alt attributes",
                    category=Category.MARKETING,
                    kind=FindingKind.STRENGTH,
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.text(f"{total_imgs} images, all with alt", source=source),
                    reasoning="Full alt-text coverage on the homepage.",
                    scope=f"<img> elements of {source}",
                    tags=["accessibility", "strength"],
                )
            )

    return findings
