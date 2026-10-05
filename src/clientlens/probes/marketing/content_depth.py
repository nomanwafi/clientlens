"""Content depth & heading structure.

Word count, heading hierarchy and text-to-HTML ratio — the structural signals
search engines and readers both use. Everything is counted from the parsed
document, so the numbers are exact for the homepage.
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

THIN_CONTENT_WORDS = 300
HEALTHY_CONTENT_WORDS = 600


@register_probe(
    id="marketing.content_depth",
    category=Category.MARKETING,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("html",),
    title="Content depth & heading structure",
    description="Word count, heading hierarchy, text-to-HTML ratio.",
    tags=("seo", "content", "readability"),
)
async def check_content_depth(ctx: ProbeContext) -> list[Finding]:
    """Measure the document's text substance and heading outline."""
    html = ctx.require("html")
    findings: list[Finding] = []
    source = html.final_url

    # ---- word count (visible text) ----------------------------------------
    text = html.soup.get_text(separator=" ", strip=True)
    words = re.findall(r"\b\w+\b", text)
    word_count = len(words)

    # ---- heading outline ---------------------------------------------------
    headings: dict[str, int] = {}
    outline: list[str] = []
    for level in range(1, 7):
        tags = html.soup.find_all(f"h{level}")
        headings[f"h{level}"] = len(tags)
        for t in tags[:3]:
            outline.append(f"h{level}: {t.get_text(strip=True)[:60]}")

    # ---- text-to-HTML ratio -----------------------------------------------
    raw_len = len(html.raw or "")
    text_len = len(text)
    ratio = (text_len / raw_len) if raw_len else 0.0

    evidence = Evidence.text(
        f"words: {word_count}\n"
        f"headings: " + ", ".join(f"{k}={v}" for k, v in headings.items() if v) + "\n"
        f"text/html ratio: {ratio:.1%}\n"
        "outline:\n  " + "\n  ".join(outline[:10]),
        source=source,
    )

    # ---- thin content ------------------------------------------------------
    if word_count < THIN_CONTENT_WORDS:
        findings.append(
            Finding(
                id="marketing.content.thin",
                title=f"Homepage is thin — about {word_count} words of visible text",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                reasoning=(
                    f"With {word_count} words the page gives search engines little "
                    "to understand what the business does or for whom. Thin home "
                    "pages rarely rank for competitive terms and convert poorly — "
                    "a visitor lands, sees little, and leaves. (A JS-rendered app "
                    "may show more to a real browser; this counts the served HTML.)"
                ),
                scope=f"Visible text of {source}",
                remediation=(
                    "Add clear, specific copy: what you do, who it is for, and the "
                    "next step. Aim for substance over keyword count — 600+ words "
                    "of genuinely useful text on the homepage is a healthy target."
                ),
                tags=["seo", "content", "thin-content"],
            )
        )
    elif word_count >= HEALTHY_CONTENT_WORDS:
        findings.append(
            Finding(
                id="marketing.content.healthy_depth",
                title=f"Content depth is healthy — about {word_count} words",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                reasoning=(
                    f"The homepage carries {word_count} words of visible text — "
                    "enough for search engines and visitors to understand the "
                    "offering without guessing."
                ),
                scope=f"Visible text of {source}",
                tags=["seo", "content", "strength"],
            )
        )

    # ---- heading hierarchy -------------------------------------------------
    if headings["h1"] == 0:
        pass  # Already reported by marketing.seo.meta — do not duplicate.
    elif headings["h1"] > 1:
        findings.append(
            Finding(
                id="marketing.content.multiple_h1",
                title=f"{headings['h1']} <h1> elements on one page",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                reasoning=(
                    "Multiple h1 elements split the page's main topic signal. It "
                    "is not a penalty, but it makes the document outline ambiguous "
                    "for both screen readers and crawlers."
                ),
                scope=f"Heading outline of {source}",
                remediation="Use exactly one descriptive <h1>; demote the others to <h2>.",
                tags=["seo", "content", "accessibility"],
            )
        )

    # Heading level skips (h1 -> h3) break the outline.
    levels_used = [int(k[1]) for k, v in headings.items() if v]
    if levels_used and len(levels_used) > 1:
        gaps = [
            (levels_used[i], levels_used[i + 1])
            for i in range(len(levels_used) - 1)
            if levels_used[i + 1] - levels_used[i] > 1
        ]
        if gaps:
            findings.append(
                Finding(
                    id="marketing.content.heading_skip",
                    title="Heading levels skip a rank (e.g. h1 → h3)",
                    category=Category.MARKETING,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    evidence=evidence,
                    reasoning=(
                        "Levels used: "
                        + " → ".join(f"h{n}" for n in levels_used)
                        + ". Skipping a rank breaks the document outline that "
                        "assistive technology navigates by."
                    ),
                    scope=f"Heading outline of {source}",
                    remediation="Keep heading levels contiguous — h1, h2, h3 in order.",
                    tags=["seo", "content", "accessibility"],
                )
            )

    # ---- text-to-HTML ratio ------------------------------------------------
    if raw_len > 10_000 and ratio < 0.02:
        findings.append(
            Finding(
                id="marketing.content.low_text_ratio",
                title=f"Text-to-HTML ratio is low ({ratio:.1%})",
                category=Category.MARKETING,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                reasoning=(
                    f"Only {ratio:.1%} of the {raw_len:,}-byte document is visible "
                    "text. A very low ratio often means the markup carries a lot of "
                    "inline script or styling. It is not a direct ranking factor, "
                    "but it usually travels with heavy pages."
                ),
                scope=f"HTML document of {source}",
                tags=["seo", "content", "performance"],
            )
        )

    return findings
