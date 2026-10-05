"""Tracking stack inventory.

Deterministic pattern matching against the bundled fingerprint database. What
is found is reported as found; what is not found is reported as "not detected",
never as "not installed".
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
    id="marketing.tracking",
    category=Category.MARKETING,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("html", "http_response"),
    title="Analytics & advertising tracking inventory",
    description="Which analytics, advertising and session-replay tools are loaded on the page.",
    tags=("analytics", "tracking", "privacy", "measurement"),
)
async def check_tracking(ctx: ProbeContext) -> list[Finding]:
    """Identify tracking scripts present in the homepage."""
    html = ctx.require("html")
    resp = ctx.require("http_response")
    findings: list[Finding] = []
    source = html.final_url

    script_srcs = html.scripts()
    inline_scripts = html.inline_scripts()
    cookie_names = _cookie_names(resp.headers)

    hits = fingerprints.match_trackers(
        script_srcs=script_srcs,
        inline_scripts=inline_scripts,
        cookie_names=cookie_names,
        html_blob=html.raw,
    )

    if not hits:
        findings.append(
            Finding(
                id="marketing.tracking.none_detected",
                title="No known tracking scripts detected",
                category=Category.MARKETING,
                kind=FindingKind.GAP,
                severity=Severity.INFO,
                confidence=Confidence.NEEDS_REVIEW,
                evidence=Evidence.text(
                    f"Inspected {len(script_srcs)} script src(s), {len(inline_scripts)} "
                    f"inline script(s) and {len(cookie_names)} cookie name(s). "
                    "No bundled fingerprint matched.",
                    source=source,
                ),
                reasoning=(
                    "No tracker in the bundled signature database matched the "
                    "homepage. That could mean the site genuinely runs no analytics, "
                    "that tracking is loaded later or on other pages, or that it "
                    "uses a tool not in our database. Treat this as 'not detected', "
                    "not as 'there is none'."
                ),
                scope=f"Homepage scripts and cookies of {source}",
                tags=["analytics", "negative-result", "needs-review"],
            )
        )
        return findings

    by_category: dict[str, list] = {}
    for rule in hits:
        by_category.setdefault(rule.category, []).append(rule)

    inventory_lines = [f"{r.name} ({r.vendor}) — {r.category}" for r in hits]
    findings.append(
        Finding(
            id="marketing.tracking.inventory",
            title=f"{len(hits)} tracking/analytics vendor(s) detected",
            category=Category.MARKETING,
            kind=FindingKind.OBSERVATION,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            evidence=Evidence.text(
                "\n".join(inventory_lines), summary=f"{len(hits)} vendors", source=source
            ),
            reasoning=(
                "These vendors receive data about every visitor to this page. Each "
                "one is part of the site's data-processing surface and needs to be "
                "named in the privacy notice and covered by a lawful basis."
            ),
            scope=f"Homepage scripts and cookies of {source}",
            tags=["analytics", "tracking", "inventory", "privacy"],
        )
    )

    # ---- advertising / pixel density --------------------------------------
    ad_trackers = [r for r in hits if r.category == "advertising"]
    if ad_trackers:
        findings.append(
            Finding(
                id="marketing.tracking.advertising_stack",
                title=f"{len(ad_trackers)} advertising pixel(s) active on the page",
                category=Category.MARKETING,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(
                    "\n".join(f"{r.name} ({r.vendor})" for r in ad_trackers), source=source
                ),
                reasoning=(
                    "Advertising pixels build audience profiles and attribute "
                    "conversions. They fire before consent on many sites, which is "
                    "the most common source of regulatory action in the EU/UK and "
                    "under GDPR-style regimes."
                ),
                scope=f"Homepage scripts of {source}",
                remediation="Gate advertising pixels behind explicit consent before they load.",
                tags=["tracking", "advertising", "privacy", "consent"],
            )
        )

    # ---- session replay ----------------------------------------------------
    replay = [r for r in hits if r.category == "session-replay"]
    if replay:
        findings.append(
            Finding(
                id="marketing.tracking.session_replay",
                title=f"Session replay tool(s) active: {', '.join(r.name for r in replay)}",
                category=Category.MARKETING,
                kind=FindingKind.OBSERVATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(
                    "\n".join(f"{r.name} ({r.vendor})" for r in replay), source=source
                ),
                reasoning=(
                    "Session replay records real user interactions including "
                    "clicks, scrolls and form input. It is extremely useful for "
                    "conversion work and is also the highest-privacy-impact "
                    "category of analytics — it must be disclosed and must mask "
                    "sensitive fields."
                ),
                scope=f"Homepage scripts of {source}",
                remediation=(
                    "Confirm form inputs and payment fields are masked, and that "
                    "replay is consent-gated."
                ),
                tags=["tracking", "session-replay", "privacy", "cro"],
            )
        )

    # ---- deprecated tools --------------------------------------------------
    deprecated = [r for r in hits if r.deprecated]
    if deprecated:
        findings.append(
            Finding(
                id="marketing.tracking.deprecated",
                title=f"Deprecated tracking tool(s) still loaded: {', '.join(r.name for r in deprecated)}",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(
                    "\n".join(f"{r.name} ({r.vendor})" for r in deprecated), source=source
                ),
                reasoning=(
                    "These tools have been sunset by their vendor. Google Universal "
                    "Analytics stopped processing data in July 2023 and Google "
                    "Optimize was retired in September 2023. Anything still firing "
                    "is collecting into a dead destination and adding page weight."
                ),
                scope=f"Homepage scripts of {source}",
                remediation="Remove the deprecated tag and migrate to the successor product.",
                tags=["tracking", "deprecated", "housekeeping"],
            )
        )

    # ---- privacy-friendly tools (positive signal) --------------------------
    friendly = [r for r in hits if r.privacy_friendly]
    if friendly:
        findings.append(
            Finding(
                id="marketing.tracking.privacy_friendly",
                title=f"Privacy-friendly analytics in use: {', '.join(r.name for r in friendly)}",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(
                    "\n".join(f"{r.name} ({r.vendor})" for r in friendly), source=source
                ),
                reasoning=(
                    "These tools are cookieless or aggregate-only by design and are "
                    "generally outside the scope of consent requirements. They show "
                    "deliberate measurement hygiene."
                ),
                scope=f"Homepage scripts of {source}",
                tags=["tracking", "privacy", "strength"],
            )
        )

    # ---- measurement coverage ---------------------------------------------
    has_analytics = any(r.category in {"analytics", "product-analytics"} for r in hits)
    if not has_analytics:
        findings.append(
            Finding(
                id="marketing.tracking.no_analytics",
                title="No general analytics platform detected",
                category=Category.MARKETING,
                kind=FindingKind.GAP,
                severity=Severity.LOW,
                confidence=Confidence.NEEDS_REVIEW,
                evidence=Evidence.text(
                    f"Detected categories: {', '.join(sorted(by_category)) or '(none)'}",
                    source=source,
                ),
                reasoning=(
                    "No first-party analytics platform (GA4, Matomo, Plausible, "
                    "Mixpanel, PostHog etc.) was matched. If the business relies on "
                    "understanding traffic and conversions, this is a measurement "
                    "gap — not a security or compliance issue."
                ),
                scope=f"Homepage scripts of {source}",
                tags=["analytics", "measurement-gap", "needs-review"],
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
