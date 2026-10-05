"""PWA & icon readiness.

Manifest, service worker hints, favicon/touch-icon coverage and theme
colour — the installable-app surface of the site.
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
    id="marketing.pwa",
    category=Category.MARKETING,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("html",),
    title="PWA & icon readiness",
    description="Web app manifest, service worker hints, favicon and touch icons.",
    tags=("pwa", "icons", "mobile", "branding"),
)
async def check_pwa(ctx: ProbeContext) -> list[Finding]:
    """Check for manifest, service worker and icon coverage."""
    html = ctx.require("html")
    findings: list[Finding] = []
    source = html.final_url

    # ---- manifest ----------------------------------------------------------
    manifest_link = html.soup.find("link", rel="manifest")
    if manifest_link and manifest_link.get("href"):
        findings.append(
            Finding(
                id="marketing.pwa.manifest_present",
                title="Web app manifest linked",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node(
                    "link[rel=manifest]",
                    f'<link rel="manifest" href="{manifest_link.get("href")}">',
                    source=source,
                ),
                reasoning=(
                    "A manifest enables install-to-homescreen and defines the app's "
                    "name, icons and theme colour."
                ),
                scope=f"HTML <head> of {source}",
                tags=["pwa", "strength"],
            )
        )
    else:
        findings.append(
            Finding(
                id="marketing.pwa.manifest_missing",
                title="No web app manifest",
                category=Category.MARKETING,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node("link[rel=manifest]", "(absent)", source=source),
                reasoning=(
                    "Without a manifest the site cannot be installed as an app and "
                    "gets no custom name/icon when a user adds it to their home "
                    "screen. Only relevant if an installable experience is a goal."
                ),
                scope=f"HTML <head> of {source}",
                tags=["pwa"],
            )
        )

    # ---- service worker hint -----------------------------------------------
    inline_blob = "\n".join(html.inline_scripts())
    has_sw_hint = (
        "serviceWorker.register" in inline_blob or "navigator.serviceWorker" in inline_blob
    )
    if has_sw_hint:
        findings.append(
            Finding(
                id="marketing.pwa.service_worker",
                title="Service worker registration detected",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.LIKELY,
                evidence=Evidence.html_node("script", "navigator.serviceWorker", source=source),
                reasoning=(
                    "A service worker registration call was found in the page's "
                    "inline scripts. Service workers enable offline behaviour, "
                    "caching strategies and push notifications."
                ),
                scope=f"Inline scripts of {source}",
                tags=["pwa", "offline", "strength"],
            )
        )

    # ---- favicon ------------------------------------------------------------
    icons = html.soup.find_all(
        "link",
        rel=lambda v: (
            v
            and any(
                r.lower()
                in {
                    "icon",
                    "shortcut icon",
                    "apple-touch-icon",
                    "apple-touch-icon-precomposed",
                    "mask-icon",
                }
                for r in (v if isinstance(v, list) else [v])
            )
        ),
    )
    if not icons:
        findings.append(
            Finding(
                id="marketing.pwa.no_icon",
                title="No favicon declared",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node("link[rel*=icon]", "(none)", source=source),
                reasoning=(
                    "With no favicon, browser tabs show a generic globe and the "
                    "brand is absent from bookmarks, history and search results "
                    "(Google shows favicons in mobile results). It also generates "
                    "a 404 on every visit."
                ),
                scope=f"HTML <head> of {source}",
                remediation='Add <link rel="icon" href="/favicon.ico"> and an apple-touch-icon.',
                tags=["pwa", "branding", "icons"],
            )
        )
    else:
        apple = [
            i
            for i in icons
            if "apple-touch-icon" in (i.get("rel") and " ".join(i.get("rel")) or "").lower()
        ]
        findings.append(
            Finding(
                id="marketing.pwa.icons_present",
                title=f"{len(icons)} icon declaration(s) found"
                + (" (incl. apple-touch-icon)" if apple else " (no apple-touch-icon)"),
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH if apple else FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.urls([str(i.get("href", "")) for i in icons[:10]], source=source),
                reasoning=(
                    "Icons declared for browser chrome"
                    + (
                        " and iOS home screen."
                        if apple
                        else ". Add an apple-touch-icon (180x180) for iOS home-screen adds."
                    )
                ),
                scope=f"HTML <head> of {source}",
                tags=["pwa", "icons"],
            )
        )

    # ---- theme colour -------------------------------------------------------
    theme_color = html.meta(name="theme-color")
    if theme_color:
        findings.append(
            Finding(
                id="marketing.pwa.theme_color",
                title=f"Theme colour declared: {theme_color}",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node("meta[name=theme-color]", theme_color, source=source),
                reasoning="Browser UI is tinted to the brand colour on mobile.",
                scope=f"HTML <head> of {source}",
                tags=["pwa", "branding", "strength"],
            )
        )

    return findings
