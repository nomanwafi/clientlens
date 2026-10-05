"""Third-party request surface.

Third-party domains are extracted from the parsed document — every script,
stylesheet, image, iframe, link preload and font the page asks the browser
to fetch. This is the site's *actual* data-sharing surface, not a guess.
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

RESOURCE_TAGS = (
    ("script", "src"),
    ("link", "href"),
    ("img", "src"),
    ("iframe", "src"),
    ("source", "src"),
    ("video", "src"),
    ("audio", "src"),
    ("embed", "src"),
    ("object", "data"),
    ("form", "action"),
)


@register_probe(
    id="marketing.third_party",
    category=Category.MARKETING,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("html",),
    title="Third-party request surface",
    description="Every external domain the homepage asks the browser to contact.",
    tags=("third-party", "privacy", "performance", "supply-chain"),
)
async def check_third_party(ctx: ProbeContext) -> list[Finding]:
    """Enumerate the external origins referenced by the homepage."""
    html = ctx.require("html")
    findings: list[Finding] = []
    source = html.final_url
    host = urlparse(html.base_url).hostname or ""
    apex_host = host[4:] if host.startswith("www.") else host

    external: dict[str, list[str]] = {}  # domain -> resource types

    for tag_name, attr in RESOURCE_TAGS:
        for tag in html.soup.find_all(tag_name):
            value = tag.get(attr)
            if not value or not isinstance(value, str):
                continue
            url = value.strip()
            if url.startswith("//"):
                url = "https:" + url
            if not url.startswith("http"):
                continue
            parsed = urlparse(url)
            d = parsed.hostname or ""
            if not d or d == host or d.endswith("." + apex_host):
                continue
            external.setdefault(d, []).append(tag_name)

    if not external:
        findings.append(
            Finding(
                id="marketing.third_party.none",
                title="No third-party origins referenced",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text("All referenced resources are same-origin.", source=source),
                reasoning=(
                    "The homepage loads everything from its own origin. This is the "
                    "strongest privacy and supply-chain posture — no external "
                    "vendor can see the page's visitors or inject code into it."
                ),
                scope=f"Resource references of {source}",
                tags=["third-party", "privacy", "strength"],
            )
        )
        return findings

    # ---- inventory ---------------------------------------------------------
    lines = []
    for domain, kinds in sorted(external.items(), key=lambda kv: -len(kv[1])):
        unique_kinds = sorted(set(kinds))
        lines.append(f"{domain}  ({len(kinds)}x: {', '.join(unique_kinds)})")

    findings.append(
        Finding(
            id="marketing.third_party.inventory",
            title=f"Homepage contacts {len(external)} third-party origin(s)",
            category=Category.MARKETING,
            kind=FindingKind.OBSERVATION,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            evidence=Evidence.text(
                "\n".join(lines), summary=f"{len(external)} origins", source=source
            ),
            reasoning=(
                "Every one of these origins receives the visitor's IP, user-agent "
                "and referrer (subject to Referrer-Policy) and can set or read "
                "state. This is the site's real data-sharing surface — it should "
                "match what the privacy notice claims."
            ),
            scope=f"Resource references of {source}",
            tags=["third-party", "privacy", "inventory"],
        )
    )

    # ---- script-bearing origins (supply chain risk) ------------------------
    script_origins = sorted({d for d, kinds in external.items() if "script" in kinds})
    if script_origins:
        findings.append(
            Finding(
                id="marketing.third_party.script_origins",
                title=f"{len(script_origins)} third-party origin(s) can execute JavaScript on this page",
                category=Category.MARKETING,
                kind=FindingKind.EXPOSURE,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.urls([f"https://{d}/" for d in script_origins], source=source),
                reasoning=(
                    "Each of these origins loads a <script> into the page. That "
                    "script runs with the page's full privileges — it can read "
                    "every keystroke, form field and cookie (that isn't HttpOnly). "
                    "A compromise of any one vendor is a compromise of this page. "
                    "This is the supply-chain risk that is most often overlooked."
                ),
                scope=f"<script> references of {source}",
                remediation=(
                    "Audit each vendor; use Subresource Integrity where the vendor "
                    "supports it, and load non-critical third-party scripts with "
                    "async/defer and a strict CSP."
                ),
                tags=["third-party", "supply-chain", "scripts"],
            )
        )

    # ---- iframe origins ----------------------------------------------------
    iframe_origins = sorted({d for d, kinds in external.items() if "iframe" in kinds})
    if iframe_origins:
        findings.append(
            Finding(
                id="marketing.third_party.iframes",
                title=f"{len(iframe_origins)} third-party origin(s) embedded via iframe",
                category=Category.MARKETING,
                kind=FindingKind.OBSERVATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.urls([f"https://{d}/" for d in iframe_origins], source=source),
                reasoning=(
                    "Embedded iframes (video players, chat widgets, maps) load a "
                    "full third-party page inside this one. They are isolated by "
                    "the same-origin policy but still share the visitor's attention "
                    "and can fingerprint."
                ),
                scope=f"<iframe> references of {source}",
                tags=["third-party", "iframes"],
            )
        )

    return findings
