"""Image hygiene — layout stability and modern formats.

Images are the most common cause of layout shift and the largest share of page
weight. This probe measures what the shipped markup declares, so the numbers
are exact for the homepage document.
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

MODERN_FORMATS = (".webp", ".avif")
LEGACY_FORMATS = (".png", ".jpg", ".jpeg", ".gif", ".bmp")


@register_probe(
    id="marketing.images",
    category=Category.MARKETING,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("html",),
    title="Image hygiene",
    description="Declared dimensions, lazy loading and modern format usage.",
    tags=("images", "performance", "seo", "core-web-vitals"),
)
async def check_images(ctx: ProbeContext) -> list[Finding]:
    """Inspect every <img> for the attributes that prevent layout shift."""
    html = ctx.require("html")
    findings: list[Finding] = []
    source = html.final_url

    images = html.soup.find_all("img")
    if not images:
        findings.append(
            Finding(
                id="marketing.images.none",
                title="No <img> elements on the homepage",
                category=Category.MARKETING,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node("img", "(none)", source=source),
                reasoning="The homepage has no image elements to assess.",
                scope=f"<img> elements of {source}",
                tags=["images"],
            )
        )
        return findings

    missing_dims: list[str] = []
    lazy: int = 0
    modern: int = 0
    legacy: int = 0

    for img in images:
        src = str(img.get("src", ""))[:80]
        has_dims = img.get("width") and img.get("height")
        if not has_dims:
            missing_dims.append(src or "(no src)")

        if img.get("loading") == "lazy":
            lazy += 1

        path = urlparse(str(img.get("src", ""))).path.lower()
        if path.endswith(MODERN_FORMATS):
            modern += 1
        elif path.endswith(LEGACY_FORMATS):
            legacy += 1

    total = len(images)
    counts = Evidence.text(
        f"total: {total}\n"
        f"missing width/height: {len(missing_dims)}\n"
        f"lazy-loaded: {lazy}\n"
        f"modern formats (webp/avif): {modern}\n"
        f"legacy formats (png/jpg/gif): {legacy}",
        source=source,
    )

    # ---- layout stability: declared dimensions -----------------------------
    if missing_dims:
        findings.append(
            Finding(
                id="marketing.images.missing_dimensions",
                title=f"{len(missing_dims)} of {total} image(s) declare no width/height",
                category=Category.MARKETING,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.urls(
                    missing_dims[:15], summary=f"{len(missing_dims)}/{total}", source=source
                ),
                reasoning=(
                    "Without width/height in the markup the browser cannot reserve "
                    "space before the image loads, so content below it jumps when "
                    "it arrives. That jump is Cumulative Layout Shift — a Core Web "
                    "Vitals metric Google uses. This is the single most common CLS "
                    "cause on image-heavy pages."
                ),
                scope=f"<img> elements of {source}",
                remediation=(
                    "Add width and height attributes (the intrinsic pixel size) to "
                    "every <img>. The browser scales via CSS; the attributes only "
                    "reserve the aspect ratio."
                ),
                tags=["images", "core-web-vitals", "cls"],
            )
        )
    else:
        findings.append(
            Finding(
                id="marketing.images.dimensions_declared",
                title=f"All {total} image(s) declare width/height",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=counts,
                reasoning="Every image reserves its layout space before loading — CLS-safe markup.",
                scope=f"<img> elements of {source}",
                tags=["images", "strength"],
            )
        )

    # ---- lazy loading ------------------------------------------------------
    if total >= 3 and lazy == 0:
        findings.append(
            Finding(
                id="marketing.images.no_lazy_loading",
                title=f"No image uses lazy loading ({total} images)",
                category=Category.MARKETING,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=counts,
                reasoning=(
                    f'All {total} images load immediately. `loading="lazy"` on '
                    "below-the-fold images defers their download, which shortens "
                    "the initial load. Above-the-fold images should stay eager — "
                    "lazy-loading the hero image makes LCP worse, not better."
                ),
                scope=f"<img> elements of {source}",
                tags=["images", "performance"],
            )
        )

    # ---- format modernity --------------------------------------------------
    if legacy and not modern:
        findings.append(
            Finding(
                id="marketing.images.legacy_formats",
                title=f"Images use legacy formats only ({legacy} png/jpg/gif)",
                category=Category.MARKETING,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=counts,
                reasoning=(
                    f"{legacy} image(s) use png/jpg/gif and none use WebP or AVIF. "
                    "WebP is typically 25-35% smaller than JPEG at the same "
                    "quality, which directly improves Largest Contentful Paint on "
                    "image-heavy pages."
                ),
                scope=f"<img> elements of {source}",
                tags=["images", "performance"],
            )
        )
    elif modern:
        findings.append(
            Finding(
                id="marketing.images.modern_formats",
                title=f"Modern image formats in use ({modern} WebP/AVIF)",
                category=Category.MARKETING,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=counts,
                reasoning="The page ships WebP/AVIF, which deliver the same visual quality at meaningfully lower bytes.",
                scope=f"<img> elements of {source}",
                tags=["images", "strength"],
            )
        )

    return findings
