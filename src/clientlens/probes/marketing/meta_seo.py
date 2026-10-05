"""On-page SEO fundamentals.

Everything here is parsed directly from the document source: what the tag says
is what we report. Length and duplicate assessments are computed, not guessed.
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

TITLE_MIN, TITLE_MAX = 30, 60
DESC_MIN, DESC_MAX = 70, 160
H1_MIN, H1_MAX = 1, 1

STOPWORDS = {
    "the",
    "a",
    "an",
    "and",
    "or",
    "but",
    "in",
    "on",
    "at",
    "to",
    "for",
    "of",
    "with",
    "by",
    "is",
    "are",
    "was",
    "were",
    "be",
    "been",
    "this",
    "that",
    "these",
    "those",
    "it",
    "its",
    "as",
    "from",
    "into",
    "your",
    "you",
    "we",
    "our",
    "us",
    "they",
    "them",
}


@register_probe(
    id="marketing.seo.meta",
    category=Category.MARKETING,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("html",),
    title="On-page SEO metadata",
    description="Title, meta description, canonical, robots directives, heading structure.",
    tags=("seo", "on-page", "organic"),
)
async def check_meta_seo(ctx: ProbeContext) -> list[Finding]:
    """Evaluate the homepage's on-page SEO fundamentals."""
    html = ctx.require("html")
    findings: list[Finding] = []
    source = html.final_url

    # ---- title -------------------------------------------------------------
    title = html.title
    if not title:
        findings.append(
            Finding(
                id="marketing.seo.title_missing",
                title="Page has no <title> tag",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node("head > title", "(absent)", source=source),
                reasoning=(
                    "The title tag is the single strongest on-page relevance signal "
                    "and is what search results show as the blue link. Without it "
                    "the snippet is generated from body text and the page cannot "
                    "target a query deliberately."
                ),
                scope=f"HTML <head> of {source}",
                remediation="Add a unique, descriptive <title> of 30-60 characters.",
                tags=["seo", "title"],
            )
        )
    else:
        length = len(title)
        findings.append(
            Finding(
                id="marketing.seo.title_present",
                title=f'<title> present ({length} chars): "{title[:70]}"',
                category=Category.MARKETING,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node(
                    "head > title", f"<title>{title}</title>", source=source
                ),
                reasoning="Title tag present and parsed from the document.",
                scope=f"HTML <head> of {source}",
                tags=["seo", "title"],
            )
        )

        if length > TITLE_MAX:
            findings.append(
                Finding(
                    id="marketing.seo.title_too_long",
                    title=f"<title> is {length} characters — likely truncated in results",
                    category=Category.MARKETING,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.html_node("head > title", title, source=source),
                    reasoning=(
                        f"Google typically displays about {TITLE_MAX} characters of a "
                        "title. Anything beyond that is cut off, which usually means "
                        "the most distinctive words are lost."
                    ),
                    scope=f"HTML <head> of {source}",
                    remediation="Trim the title to the primary keyword + brand, under 60 characters.",
                    tags=["seo", "title"],
                )
            )
        elif length < TITLE_MIN:
            findings.append(
                Finding(
                    id="marketing.seo.title_too_short",
                    title=f"<title> is only {length} characters",
                    category=Category.MARKETING,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.html_node("head > title", title, source=source),
                    reasoning=(
                        "A very short title leaves relevance on the table — there is "
                        "room to describe what the page offers and to whom."
                    ),
                    scope=f"HTML <head> of {source}",
                    remediation="Expand the title to 30-60 characters with the primary topic and brand.",
                    tags=["seo", "title"],
                )
            )

    # ---- meta description --------------------------------------------------
    desc = html.meta(name="description")
    if not desc:
        findings.append(
            Finding(
                id="marketing.seo.description_missing",
                title="No meta description",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node(
                    "head > meta[name=description]", "(absent)", source=source
                ),
                reasoning=(
                    "Without a meta description Google generates a snippet from "
                    "whatever text it finds on the page. That snippet is the ad copy "
                    "for the search result — leaving it to chance usually lowers "
                    "click-through rate even when rankings are unchanged."
                ),
                scope=f"HTML <head> of {source}",
                remediation="Add a unique meta description of 70-160 characters that answers the query.",
                tags=["seo", "description"],
            )
        )
    else:
        length = len(desc)
        findings.append(
            Finding(
                id="marketing.seo.description_present",
                title=f"Meta description present ({length} chars)",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node(
                    "head > meta[name=description]", desc[:300], source=source
                ),
                reasoning="Meta description present and parsed from the document.",
                scope=f"HTML <head> of {source}",
                tags=["seo", "description", "strength"],
            )
        )
        if length > DESC_MAX:
            findings.append(
                Finding(
                    id="marketing.seo.description_too_long",
                    title=f"Meta description is {length} characters — likely truncated",
                    category=Category.MARKETING,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.html_node(
                        "head > meta[name=description]", desc, source=source
                    ),
                    reasoning="Descriptions over ~160 characters are cut mid-sentence in results.",
                    scope=f"HTML <head> of {source}",
                    remediation="Trim to under 160 characters.",
                    tags=["seo", "description"],
                )
            )

    # ---- canonical ---------------------------------------------------------
    canonical = _link_rel(html, "canonical")
    if not canonical:
        findings.append(
            Finding(
                id="marketing.seo.canonical_missing",
                title="No canonical link declared",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node(
                    "head > link[rel=canonical]", "(absent)", source=source
                ),
                reasoning=(
                    "Without a canonical, the URL variants (http/https, www/non-www, "
                    "trailing slash, query strings) compete as separate pages and "
                    "split ranking signals between them."
                ),
                scope=f"HTML <head> of {source}",
                remediation=f'Add <link rel="canonical" href="{source}">.',
                tags=["seo", "canonical"],
            )
        )
    else:
        findings.append(
            Finding(
                id="marketing.seo.canonical_present",
                title=f"Canonical declared: {canonical}",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node(
                    "head > link[rel=canonical]",
                    f'<link rel="canonical" href="{canonical}">',
                    source=source,
                ),
                reasoning="Canonical URL declared; URL-variant dilution is controlled.",
                scope=f"HTML <head> of {source}",
                tags=["seo", "canonical", "strength"],
            )
        )

    # ---- robots meta -------------------------------------------------------
    robots_meta = html.meta(name="robots")
    if robots_meta:
        lowered = robots_meta.lower()
        blocking = [t for t in ("noindex", "nofollow", "none", "noarchive") if t in lowered]
        if blocking:
            findings.append(
                Finding(
                    id="marketing.seo.robots_blocking",
                    title=f"Robots meta restricts indexing: {robots_meta}",
                    category=Category.MARKETING,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.html_node(
                        "head > meta[name=robots]",
                        f'<meta name="robots" content="{robots_meta}">',
                        source=source,
                    ),
                    reasoning=(
                        f"The page declares `{robots_meta}`, which explicitly tells "
                        "search engines not to index and/or not to follow its links. "
                        "If this page is meant to be found organically, this is the "
                        "reason it is not."
                    ),
                    scope=f"HTML <head> of {source}",
                    remediation="Change to `index, follow` unless this page is intentionally excluded.",
                    tags=["seo", "robots", "indexing"],
                )
            )

    # ---- hreflang ----------------------------------------------------------
    hreflangs = _hreflangs(html)
    if hreflangs:
        findings.append(
            Finding(
                id="marketing.seo.hreflang_present",
                title=f"{len(hreflangs)} hreflang annotation(s) declared",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.urls(
                    [f"{lang} -> {url}" for lang, url in hreflangs.items()],
                    source=source,
                ),
                reasoning=(
                    "Language/region annotations present. These let search engines "
                    "serve the correct language version instead of guessing."
                ),
                scope=f"HTML <head> of {source}",
                tags=["seo", "hreflang", "international", "strength"],
            )
        )

    # ---- heading structure -------------------------------------------------
    h1s = [h.get_text(strip=True) for h in html.soup.find_all("h1")]
    h1s = [h for h in h1s if h]

    if len(h1s) == 0:
        findings.append(
            Finding(
                id="marketing.seo.h1_missing",
                title="No <h1> heading on the page",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node("h1", "(none found)", source=source),
                reasoning=(
                    "The h1 is the page's primary topic declaration. Without one "
                    "search engines and screen readers infer the topic from body "
                    "copy, which is weaker and less consistent."
                ),
                scope=f"HTML headings of {source}",
                remediation="Add exactly one descriptive <h1> that states what the page is about.",
                tags=["seo", "headings", "accessibility"],
            )
        )
    elif len(h1s) > 1:
        findings.append(
            Finding(
                id="marketing.seo.h1_multiple",
                title=f"{len(h1s)} <h1> headings on the page",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node("h1", " | ".join(h1s[:8]), source=source),
                reasoning=(
                    "Multiple h1s dilute the topic signal and are a common symptom "
                    "of a page assembled from several templates. HTML5 permits it, "
                    "but a single clear h1 is the stronger pattern."
                ),
                scope=f"HTML headings of {source}",
                remediation="Keep one h1; demote the others to h2.",
                tags=["seo", "headings"],
            )
        )
    else:
        findings.append(
            Finding(
                id="marketing.seo.h1_present",
                title=f'Single <h1> present: "{h1s[0][:80]}"',
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node("h1", h1s[0][:300], source=source),
                reasoning="Exactly one h1, which is the expected pattern.",
                scope=f"HTML headings of {source}",
                tags=["seo", "headings", "strength"],
            )
        )

    # ---- title/h1 alignment ----------------------------------------------
    if title and h1s:
        overlap = _token_overlap(title, h1s[0])
        if overlap < 0.25:
            findings.append(
                Finding(
                    id="marketing.seo.title_h1_mismatch",
                    title="<title> and <h1> cover different topics",
                    category=Category.MARKETING,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=Severity.LOW,
                    confidence=Confidence.LIKELY,
                    evidence=Evidence.text(
                        f"<title>: {title}\n<h1>: {h1s[0][:200]}\ntoken overlap: {overlap:.0%}",
                        source=source,
                    ),
                    reasoning=(
                        "The search result title and the on-page heading describe "
                        "different things. That usually means either the title is "
                        "stuffed with unrelated keywords or the h1 is decorative. "
                        "Both weaken the relevance signal."
                    ),
                    scope=f"Title and h1 of {source}",
                    remediation="Make the h1 the plain-language version of the title.",
                    tags=["seo", "title", "headings"],
                )
            )

    return findings


# --------------------------------------------------------------------------- #
def _link_rel(html, rel: str) -> str:
    for tag in html.soup.find_all("link", rel=True):
        rels = tag.get("rel")
        if isinstance(rels, str):
            rels = [rels]
        if rel in [r.lower() for r in rels] and tag.get("href"):
            return str(tag["href"]).strip()
    return ""


def _hreflangs(html) -> dict[str, str]:
    out: dict[str, str] = {}
    for tag in html.soup.find_all("link", rel=True, hreflang=True):
        rels = tag.get("rel")
        if isinstance(rels, str):
            rels = [rels]
        if "alternate" in [r.lower() for r in rels]:
            out[str(tag["hreflang"])] = str(tag["href"])
    return out


def _token_overlap(a: str, b: str) -> float:
    def tokens(s: str) -> set[str]:
        return {t for t in re.findall(r"[a-z0-9]+", s.lower()) if t not in STOPWORDS and len(t) > 2}

    ta, tb = tokens(a), tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / min(len(ta), len(tb))
