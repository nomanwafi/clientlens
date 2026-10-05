"""Open Graph / Twitter Card / social preview checks.

These tags are what determine how a link looks when shared. Missing values are
reported as a specific, visible consequence (e.g. "no image when shared"), not
as an abstract SEO score.
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

OG_REQUIRED = [
    ("og:title", "headline shown when the link is shared"),
    ("og:description", "summary shown when the link is shared"),
    ("og:image", "preview image shown when the link is shared"),
    ("og:url", "canonical URL the share is attributed to"),
    ("og:type", "how the platform treats the object (website, article, product)"),
]

TWITTER_MAP = [
    ("twitter:card", "summary / summary_large_image"),
    ("twitter:site", "@handle of the site"),
    ("twitter:title", "headline for X/Twitter shares"),
    ("twitter:description", "summary for X/Twitter shares"),
    ("twitter:image", "preview image for X/Twitter shares"),
]


@register_probe(
    id="marketing.social",
    category=Category.MARKETING,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("html",),
    title="Social sharing metadata (Open Graph / Twitter Card)",
    description="Tags that control how the page renders when shared on social platforms.",
    tags=("social", "og", "twitter-card", "sharing"),
)
async def check_social_meta(ctx: ProbeContext) -> list[Finding]:
    """Review Open Graph and Twitter Card tags on the homepage."""
    html = ctx.require("html")
    findings: list[Finding] = []
    source = html.final_url

    present_og: dict[str, str] = {}
    for prop, _purpose in OG_REQUIRED:
        value = html.meta(prop=prop)
        present_og[prop] = value

    [p for p, _ in OG_REQUIRED if not present_og[p]]

    if not present_og.get("og:title") and not present_og.get("og:image"):
        findings.append(
            Finding(
                id="marketing.social.og_absent",
                title="No Open Graph tags found",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node("meta[property^='og:']", "(none)", source=source),
                reasoning=(
                    "When this link is shared on LinkedIn, Facebook, Slack, "
                    "WhatsApp, iMessage or a Discord channel, the platform has "
                    "nothing to render. It falls back to scraping body text and "
                    "the first image it can find, which usually looks broken."
                ),
                scope=f"HTML <head> of {source}",
                remediation=(
                    "Add at minimum: og:title, og:description, og:image (1200x630), "
                    "og:url, og:type."
                ),
                tags=["social", "og", "sharing"],
            )
        )
    else:
        # Report individual gaps as separate findings.
        for prop, purpose in OG_REQUIRED:
            if not present_og[prop]:
                findings.append(
                    Finding(
                        id=f"marketing.social.{prop.replace(':', '_')}_missing",
                        title=f"`{prop}` not set",
                        category=Category.MARKETING,
                        kind=FindingKind.MISCONFIGURATION,
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        evidence=Evidence.html_node(
                            f"meta[property={prop}]", "(absent)", source=source
                        ),
                        reasoning=f"`{prop}` controls {purpose}.",
                        scope=f"HTML <head> of {source}",
                        remediation=f'Add <meta property="{prop}" content="...">.',
                        tags=["social", "og"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        id=f"marketing.social.{prop.replace(':', '_')}_present",
                        title=f"`{prop}` set",
                        category=Category.MARKETING,
                        kind=FindingKind.STRENGTH,
                        severity=Severity.INFO,
                        confidence=Confidence.CONFIRMED,
                        evidence=Evidence.html_node(
                            f"meta[property={prop}]",
                            f'<meta property="{prop}" content="{present_og[prop][:120]}">',
                            source=source,
                        ),
                        reasoning=f"`{prop}` is present and will render in shares.",
                        scope=f"HTML <head> of {source}",
                        tags=["social", "og", "strength"],
                    )
                )

    # ---- og:image dimensions ----------------------------------------------
    og_image = present_og.get("og:image", "")
    if og_image.startswith("http://"):
        findings.append(
            Finding(
                id="marketing.social.og_image_insecure",
                title="og:image points at an http:// URL",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node("meta[property=og:image]", og_image, source=source),
                reasoning=(
                    "Several platforms refuse to fetch or render an insecure "
                    "og:image, so the share silently falls back to no image."
                ),
                scope=f"HTML <head> of {source}",
                remediation="Serve the share image over https://.",
                tags=["social", "og", "transport"],
            )
        )

    # ---- Twitter Card ------------------------------------------------------
    twitter_present = {}
    for key, _purpose in TWITTER_MAP:
        value = html.meta(name=key) or html.meta(prop=key)
        twitter_present[key] = value

    if not twitter_present.get("twitter:card") and not twitter_present.get("twitter:title"):
        findings.append(
            Finding(
                id="marketing.social.twitter_absent",
                title="No Twitter Card tags found",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node("meta[name^='twitter:']", "(none)", source=source),
                reasoning=(
                    "X/Twitter falls back to Open Graph when Twitter Cards are "
                    "absent, so this is not fatal — but `twitter:card=summary_large_image` "
                    "is what produces the large preview card that performs far "
                    "better than the small one."
                ),
                scope=f"HTML <head> of {source}",
                remediation=(
                    "Add twitter:card=summary_large_image plus twitter:title, "
                    "twitter:description and twitter:image."
                ),
                tags=["social", "twitter-card"],
            )
        )
    elif not twitter_present.get("twitter:card"):
        findings.append(
            Finding(
                id="marketing.social.twitter_card_missing",
                title="Twitter tags present but `twitter:card` is not set",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(
                    "; ".join(f"{k}={v}" for k, v in twitter_present.items() if v),
                    source=source,
                ),
                reasoning=(
                    "Without `twitter:card`, the other Twitter tags are ignored and "
                    "the platform falls back to Open Graph rendering."
                ),
                scope=f"HTML <head> of {source}",
                remediation='Add <meta name="twitter:card" content="summary_large_image">.',
                tags=["social", "twitter-card"],
            )
        )

    # ---- consistency between og and twitter --------------------------------
    og_title = present_og.get("og:title", "")
    tw_title = twitter_present.get("twitter:title", "")
    if og_title and tw_title and og_title.strip() != tw_title.strip():
        findings.append(
            Finding(
                id="marketing.social.title_mismatch",
                title="og:title and twitter:title differ",
                category=Category.MARKETING,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(
                    f"og:title:        {og_title}\ntwitter:title:   {tw_title}", source=source
                ),
                reasoning=(
                    "Different titles means the message changes depending on where "
                    "the link is shared. Sometimes intentional; worth confirming."
                ),
                scope=f"HTML <head> of {source}",
                tags=["social"],
            )
        )

    return findings
