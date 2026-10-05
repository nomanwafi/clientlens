"""Consent platform detection and consent-mode posture.

Detection is heuristic by nature (banners are rendered client-side in many
stacks), so these findings are ``LIKELY`` or ``NEEDS_REVIEW``, never
``CONFIRMED``. The one exception is the absence of any consent signal combined
with the presence of advertising pixels, which is a directly observed state.
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
    id="marketing.consent",
    category=Category.MARKETING,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("html", "http_response"),
    title="Consent management & cookie banner posture",
    description="Which CMP is present and whether Google Consent Mode is initialised.",
    tags=("privacy", "gdpr", "consent", "compliance"),
)
async def check_consent(ctx: ProbeContext) -> list[Finding]:
    """Detect the consent platform and consent-mode initialisation."""
    html = ctx.require("html")
    resp = ctx.require("http_response")
    findings: list[Finding] = []
    source = html.final_url

    script_srcs = html.scripts()
    inline_blob = "\n".join(html.inline_scripts())
    html_blob = html.raw
    cookie_names = _cookie_names(resp.headers)

    platforms = fingerprints.match_consent_platform(
        html_blob=html_blob + "\n" + inline_blob,
        script_srcs=script_srcs,
        cookie_names=cookie_names,
    )

    has_ad_pixels = _has_advertising_tracking(html, cookie_names)

    # ---- CMP present -------------------------------------------------------
    if platforms:
        names = ", ".join(p.name for p in platforms)
        findings.append(
            Finding(
                id="marketing.consent.platform_detected",
                title=f"Consent platform detected: {names}",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.LIKELY,
                evidence=Evidence.text(
                    "Detected via: " + ", ".join(p.name for p in platforms),
                    source=source,
                ),
                reasoning=(
                    "A consent management platform is present in the page source. "
                    "This is a positive signal for privacy posture. Note that "
                    "presence of the banner does not by itself prove that tags are "
                    "actually blocked before consent — that needs a runtime check."
                ),
                scope=f"HTML source and cookies of {source}",
                tags=["privacy", "consent", "strength"],
            )
        )
    else:
        severity = Severity.MEDIUM if has_ad_pixels else Severity.LOW
        findings.append(
            Finding(
                id="marketing.consent.platform_not_detected",
                title="No consent management platform detected",
                category=Category.MARKETING,
                kind=FindingKind.GAP,
                severity=severity,
                confidence=Confidence.NEEDS_REVIEW,
                evidence=Evidence.text(
                    "No bundled CMP signature matched HTML source, inline scripts or cookies.",
                    source=source,
                ),
                reasoning=(
                    "No cookie banner or consent platform was detected in the "
                    "page source. Many CMPs render client-side after a second "
                    "request, so this is a detection gap rather than a proven "
                    "absence.\n\n"
                    + (
                        "IMPORTANT: advertising pixels were also detected on this "
                        "page. If those fire without consent, that is the specific "
                        "pattern regulators act on most often."
                        if has_ad_pixels
                        else "No advertising pixels were detected either, which "
                        "lowers the privacy impact of a missing banner."
                    )
                ),
                scope=f"HTML source and cookies of {source}",
                remediation=(
                    "Deploy a CMP and gate non-essential tags behind explicit "
                    "consent before they load."
                ),
                tags=["privacy", "consent", "needs-review"],
            )
        )

    # ---- Google Consent Mode ----------------------------------------------
    consent_mode_signals = [
        "consent_mode",
        "consentMode",
        "ad_storage",
        "analytics_storage",
        "gtag('consent'",
        'gtag("consent"',
        "update_consent",
    ]
    blob = (html_blob + "\n" + inline_blob).lower()
    has_consent_mode = any(sig.lower() in blob for sig in consent_mode_signals)
    has_gtm_or_ga = _has_google_tagging(html, cookie_names)

    if has_consent_mode:
        findings.append(
            Finding(
                id="marketing.consent.google_consent_mode",
                title="Google Consent Mode initialisation detected",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.LIKELY,
                evidence=Evidence.text(
                    "Signals: " + ", ".join(s for s in consent_mode_signals if s.lower() in blob),
                    source=source,
                ),
                reasoning=(
                    "Consent Mode lets Google tags run in a restricted state before "
                    "consent and expand afterwards, which preserves conversion "
                    "modelling while honouring the user's choice."
                ),
                scope=f"HTML source of {source}",
                tags=["privacy", "consent", "google", "strength"],
            )
        )
    elif has_gtm_or_ga:
        findings.append(
            Finding(
                id="marketing.consent.google_no_consent_mode",
                title="Google tags present but Consent Mode not initialised",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.LIKELY,
                evidence=Evidence.text(
                    "Google tagging detected; no consent_mode / ad_storage / "
                    "analytics_storage default call found in the page source.",
                    source=source,
                ),
                reasoning=(
                    "Google tags are loaded without a Consent Mode default call. "
                    "In that configuration the tags assume consent and begin "
                    "collecting immediately, which is the behaviour most likely to "
                    "be non-compliant in consent-required jurisdictions."
                ),
                scope=f"HTML source of {source}",
                remediation=(
                    "Add `gtag('consent', 'default', {...})` before any Google tag "
                    "loads, and `gtag('consent', 'update', {...})` on consent."
                ),
                tags=["privacy", "consent", "google"],
            )
        )

    # ---- privacy link presence --------------------------------------------
    has_privacy_link = _has_privacy_link(html)
    if not has_privacy_link:
        findings.append(
            Finding(
                id="marketing.consent.privacy_link_missing",
                title="No privacy policy link found on the homepage",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.LIKELY,
                evidence=Evidence.text(
                    "No anchor with privacy/terms/cookie wording found in the rendered HTML.",
                    source=source,
                ),
                reasoning=(
                    "A privacy notice is a legal requirement in most jurisdictions "
                    "once any personal data is collected, which it is as soon as "
                    "analytics run. Its absence from the homepage makes it hard for "
                    "a user or a regulator to find."
                ),
                scope=f"HTML <body> of {source}",
                remediation="Link the privacy policy (and cookie policy) from the footer of every page.",
                tags=["privacy", "legal", "needs-review"],
            )
        )

    return findings


def _has_advertising_tracking(html, cookie_names: list[str]) -> bool:
    script_srcs = html.scripts()
    hits = fingerprints.match_trackers(
        script_srcs=script_srcs,
        inline_scripts=html.inline_scripts(),
        cookie_names=cookie_names,
        html_blob=html.raw,
    )
    return any(h.category == "advertising" for h in hits)


def _has_google_tagging(html, cookie_names: list[str]) -> bool:
    script_srcs = html.scripts()
    blob = "\n".join(script_srcs + html.inline_scripts()).lower()
    if "googletagmanager.com" in blob or "google-analytics.com" in blob or "gtag(" in blob:
        return True
    return any(c.startswith("_ga") for c in cookie_names)


def _has_privacy_link(html) -> bool:
    keywords = (
        "privacy",
        "privacidad",
        "datenschutz",
        "confidentialit",
        "cookie policy",
        "cookies",
        "privacy-policy",
        "privacy_policy",
        "terms",
        "terms-of-service",
        "terms-of-use",
        "legal",
    )
    for a in html.soup.find_all("a", href=True):
        text = (a.get_text(strip=True) or "").lower()
        href = str(a["href"]).lower()
        blob = f"{text} {href}"
        if any(k in blob for k in keywords):
            return True
    return False


def _cookie_names(headers: dict[str, str]) -> list[str]:
    out: list[str] = []
    for key, value in headers.items():
        if key.lower() != "set-cookie":
            continue
        first = value.split(";")[0]
        if "=" in first:
            out.append(first.split("=", 1)[0].strip())
    return out
