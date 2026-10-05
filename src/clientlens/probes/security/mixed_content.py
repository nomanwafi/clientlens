"""Mixed content detection.

Reads the parsed HTML and reports insecure subresource references. Directly
observable from the document source.
"""

from __future__ import annotations

from urllib.parse import urljoin

from ...core.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    FindingKind,
    Severity,
)
from ...core.registry import ProbeContext, ProbeMode, ProbePhase, register_probe

MIXED_ATTRS = (
    ("script", "src"),
    ("img", "src"),
    ("iframe", "src"),
    ("source", "src"),
    ("video", "src"),
    ("audio", "src"),
    ("link", "href"),
    ("form", "action"),
)


@register_probe(
    id="security.mixed_content",
    category=Category.SECURITY,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("html",),
    title="Mixed content",
    description="Insecure http:// subresources referenced from an https document.",
    tags=("transport", "mixed-content", "browser-enforcement"),
)
async def check_mixed_content(ctx: ProbeContext) -> list[Finding]:
    """Scan the parsed HTML for http:// subresource references."""
    html = ctx.require("html")
    findings: list[Finding] = []

    insecure: list[tuple[str, str, str]] = []  # (tag, attr, url)

    for tag_name, attr in MIXED_ATTRS:
        for tag in html.soup.find_all(tag_name):
            value = tag.get(attr)
            if not value:
                continue
            absolute = urljoin(html.base_url, str(value))
            if absolute.startswith("http://"):
                insecure.append((tag_name, attr, absolute))

    # Inline CSS url() references.
    for style_tag in html.soup.find_all("style"):
        if style_tag.string and "http://" in style_tag.string:
            for match in _extract_urls(style_tag.string):
                if match.startswith("http://"):
                    insecure.append(("style", "css-url", match))

    if not insecure:
        findings.append(
            Finding(
                id="security.mixed_content.none",
                title="No mixed content references found",
                category=Category.SECURITY,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(
                    f"Scanned {len(MIXED_ATTRS)} attribute types across the document.",
                    source=html.final_url,
                ),
                reasoning="No http:// subresource references were found in the homepage markup.",
                scope=f"HTML source of {html.final_url}",
                tags=["mixed-content", "strength"],
            )
        )
        return findings

    passive = [i for i in insecure if i[0] in {"img", "source", "video", "audio"}]
    active = [i for i in insecure if i not in passive]

    if active:
        findings.append(
            Finding(
                id="security.mixed_content.active",
                title=f"{len(active)} active mixed-content reference(s) found",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.urls([f"<{t} {a}=\"{u}\">" for t, a, u in active[:25]], source=html.final_url),
                reasoning=(
                    "Active mixed content (scripts, iframes, stylesheets, forms) is "
                    "loaded over http:// inside an https page. Browsers block these "
                    "outright, so the resource silently fails to load — and where it "
                    "is not blocked, an on-path attacker can replace the script with "
                    "arbitrary code running in the page's origin."
                ),
                scope=f"HTML source of {html.final_url}",
                remediation="Change these references to https:// or protocol-relative //.",
                tags=["mixed-content", "active", "transport"],
            )
        )

    if passive:
        findings.append(
            Finding(
                id="security.mixed_content.passive",
                title=f"{len(passive)} passive mixed-content reference(s) found",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.urls([f"<{t} {a}=\"{u}\">" for t, a, u in passive[:25]], source=html.final_url),
                reasoning=(
                    "Passive mixed content (images, media) is downgraded to http://. "
                    "Browsers allow it with a warning, but the content is exposed to "
                    "tampering and the page is marked 'not fully secure'."
                ),
                scope=f"HTML source of {html.final_url}",
                remediation="Serve these assets over https://.",
                tags=["mixed-content", "passive", "transport"],
            )
        )

    return findings


def _extract_urls(css: str) -> list[str]:
    import re

    return re.findall(r"url\(\s*['\"]?([^'\")\s]+)['\"]?\s*\)", css)
