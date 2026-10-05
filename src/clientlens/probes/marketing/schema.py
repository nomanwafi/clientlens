"""Structured data (JSON-LD) inventory and validity.

We parse the JSON-LD blocks and report the schema.org types actually declared.
We do not claim rich-result eligibility — that is a Google policy decision, not
a parseable fact.
"""

from __future__ import annotations

import json

from ...core.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    FindingKind,
    Severity,
)
from ...core.registry import ProbeContext, ProbeMode, ProbePhase, register_probe

# Types that commonly drive rich results.
HIGH_VALUE_TYPES = {
    "Organization": "Knowledge Panel and brand carousel eligibility",
    "LocalBusiness": "local pack / Maps eligibility",
    "Product": "product rich results (price, availability, rating)",
    "Review": "review stars in results",
    "AggregateRating": "star ratings in results",
    "FAQPage": "FAQ dropdown in results",
    "HowTo": "HowTo rich result",
    "Article": "article carousel / Top Stories",
    "BreadcrumbList": "breadcrumb trail in results",
    "WebSite": "sitelinks search box",
    "VideoObject": "video rich result",
    "Event": "event rich result",
    "JobPosting": "job listing rich result",
    "Course": "course listing rich result",
    "SoftwareApplication": "app rich result",
    "Recipe": "recipe rich result",
    "Service": "service knowledge",
}


@register_probe(
    id="marketing.schema",
    category=Category.MARKETING,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("html",),
    title="Structured data (JSON-LD / schema.org)",
    description="Inventory and parse-validity of JSON-LD blocks on the page.",
    tags=("seo", "schema", "structured-data", "rich-results"),
)
async def check_schema(ctx: ProbeContext) -> list[Finding]:
    """Parse every JSON-LD block and report the declared schema.org types."""
    html = ctx.require("html")
    findings: list[Finding] = []
    source = html.final_url

    blocks = html.json_ld_blocks()

    if not blocks:
        # Also check microdata / RDFa as a coverage signal.
        microdata = html.soup.find_all(attrs={"itemscope": True})
        rdfa = html.soup.find_all(attrs={"typeof": True})

        if microdata or rdfa:
            findings.append(
                Finding(
                    id="marketing.schema.microdata_only",
                    title="Structured data present as microdata/RDFa but no JSON-LD",
                    category=Category.MARKETING,
                    kind=FindingKind.OBSERVATION,
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.html_node(
                        "[itemscope], [typeof]",
                        f"{len(microdata)} itemscope node(s), {len(rdfa)} typeof node(s)",
                        source=source,
                    ),
                    reasoning=(
                        "Google can read microdata and RDFa, but JSON-LD is the "
                        "recommended format and is far easier to maintain and "
                        "validate. This is not a defect."
                    ),
                    scope=f"HTML source of {source}",
                    remediation="Consider migrating to JSON-LD when the markup is next revised.",
                    tags=["seo", "schema", "structured-data"],
                )
            )
        else:
            findings.append(
                Finding(
                    id="marketing.schema.absent",
                    title="No structured data found on the page",
                    category=Category.MARKETING,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.html_node(
                        "script[type='application/ld+json']", "(none)", source=source
                    ),
                    reasoning=(
                        "Without structured data the page cannot qualify for rich "
                        "results (stars, breadcrumbs, FAQ dropdowns, product info) "
                        "and search engines must infer the entity from text alone. "
                        "This is the most reliable single lever for improving how a "
                        "result looks."
                    ),
                    scope=f"HTML <head>/<body> of {source}",
                    remediation=(
                        "Add JSON-LD for at least Organization (or LocalBusiness) "
                        "and WebSite. Add Product/FAQ/Article types where the page "
                        "content warrants it."
                    ),
                    tags=["seo", "schema", "structured-data"],
                )
            )
        return findings

    # ---- parse each block --------------------------------------------------
    all_types: list[str] = []
    invalid_blocks = 0
    type_inventory: dict[str, int] = {}

    for idx, raw in enumerate(blocks):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            invalid_blocks += 1
            findings.append(
                Finding(
                    id=f"marketing.schema.block_{idx}_invalid_json",
                    title=f"JSON-LD block {idx + 1} is not valid JSON",
                    category=Category.MARKETING,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.text(f"Parse error: {exc}\n\n{raw[:400]}", source=source),
                    reasoning=(
                        "An unparseable JSON-LD block is ignored entirely by search "
                        "engines. The structured data in it is effectively not there."
                    ),
                    scope=f"JSON-LD block {idx + 1} of {source}",
                    remediation="Fix the JSON syntax error, or remove the block.",
                    tags=["seo", "schema", "invalid"],
                )
            )
            continue

        for t in _extract_types(data):
            all_types.append(t)
            type_inventory[t] = type_inventory.get(t, 0) + 1

    if all_types:
        summary = "\n".join(f"{t}: {n}" for t, n in sorted(type_inventory.items()))
        findings.append(
            Finding(
                id="marketing.schema.inventory",
                title=f"{len(blocks)} JSON-LD block(s) declaring {len(type_inventory)} schema type(s)",
                category=Category.MARKETING,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(summary, summary="schema.org types", source=source),
                reasoning=(
                    "These are the structured-data types actually declared on the "
                    "page. They are what a search engine can use to understand the "
                    "entity and to consider the page for rich results."
                ),
                scope=f"JSON-LD blocks of {source}",
                tags=["seo", "schema", "structured-data"],
            )
        )

    # ---- high-value type coverage -----------------------------------------
    found_high_value = {t: HIGH_VALUE_TYPES[t] for t in type_inventory if t in HIGH_VALUE_TYPES}
    if found_high_value:
        findings.append(
            Finding(
                id="marketing.schema.high_value_types",
                title=f"{len(found_high_value)} rich-result-relevant type(s) present",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(
                    "\n".join(f"{t} — {why}" for t, why in found_high_value.items()),
                    source=source,
                ),
                reasoning=(
                    "These types are associated with enhanced search presentations. "
                    "Presence of the type is necessary but not sufficient — Google "
                    "also requires content quality and policy compliance before "
                    "showing a rich result."
                ),
                scope=f"JSON-LD blocks of {source}",
                tags=["seo", "schema", "rich-results", "strength"],
            )
        )

    # ---- organisation identity ---------------------------------------------
    has_org = any(
        t in {"Organization", "Corporation", "LocalBusiness", "OnlineStore"} for t in all_types
    )
    if not has_org:
        findings.append(
            Finding(
                id="marketing.schema.organization_missing",
                title="No Organization/LocalBusiness schema declared",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(
                    f"Types found: {', '.join(sorted(type_inventory)) or '(none)'}", source=source
                ),
                reasoning=(
                    "Organization schema is what feeds the brand Knowledge Panel "
                    "and how search engines connect the site to the entity behind "
                    "it. Without it the brand entity is inferred from links alone."
                ),
                scope=f"JSON-LD blocks of {source}",
                remediation=(
                    "Add an Organization node with name, url, logo, sameAs "
                    "(social profiles) and contactPoint."
                ),
                tags=["seo", "schema", "entity"],
            )
        )

    if invalid_blocks:
        findings.append(
            Finding(
                id="marketing.schema.invalid_count",
                title=f"{invalid_blocks} of {len(blocks)} JSON-LD block(s) failed to parse",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(
                    f"{invalid_blocks}/{len(blocks)} blocks invalid", source=source
                ),
                reasoning="Invalid blocks are discarded wholesale by search engines.",
                scope=f"JSON-LD blocks of {source}",
                remediation="Validate every block with Google's Rich Results Test before publishing.",
                tags=["seo", "schema", "invalid"],
            )
        )

    return findings


def _extract_types(node, out: set[str] | None = None) -> set[str]:
    if out is None:
        out = set()
    if isinstance(node, dict):
        t = node.get("@type")
        if isinstance(t, str):
            out.add(t)
        elif isinstance(t, list):
            out.update(x for x in t if isinstance(x, str))
        for value in node.values():
            _extract_types(value, out)
    elif isinstance(node, list):
        for item in node:
            _extract_types(item, out)
    return out
