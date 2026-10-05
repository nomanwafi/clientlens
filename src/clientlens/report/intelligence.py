"""Report intelligence — executive summary, priority roadmap, quick wins.

Turns the raw finding list into the two things a client actually reads first:
an executive summary and a prioritised action plan. Everything here is derived
deterministically from the findings — no free-text invention.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.models import (
    Category,
    Confidence,
    Finding,
    FindingKind,
    ScanResult,
    Severity,
)

# Heuristic effort estimates per finding id prefix.
# "quick" = a config/header/DNS change, minutes to ship.
# "planned" = code or process change, days.
EFFORT_QUICK_PREFIXES = (
    "security.headers.",
    "security.dns.caa",
    "security.email_auth.spf",
    "security.email_auth.dmarc",
    "marketing.seo.title",
    "marketing.seo.description",
    "marketing.seo.canonical",
    "marketing.seo.robots",
    "marketing.social.",
    "marketing.schema.",
    "security.cookies.",
    "security.exposure.",
    "marketing.sitemap.",
)


@dataclass
class ActionItem:
    finding_id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: Category
    remediation: str
    effort: str  # quick | planned
    impact: int  # 0-100, for ordering
    tags: list[str] = field(default_factory=list)

    @property
    def is_quick_win(self) -> bool:
        return self.effort == "quick"


@dataclass
class ExecutiveSummary:
    """What a decision-maker reads in the first 30 seconds."""

    headline: str
    risk_score: int
    risk_label: str
    posture: str  # strong | acceptable | needs-attention | critical
    total_findings: int
    critical_count: int
    high_count: int
    confirmed_count: int
    needs_review_count: int
    security_findings: int
    marketing_findings: int
    top_security_themes: list[str]
    top_marketing_themes: list[str]
    strengths_count: int
    coverage_note: str


def confidence_badge(conf: Confidence) -> str:
    return {
        Confidence.CONFIRMED: "Confirmed",
        Confidence.LIKELY: "Likely",
        Confidence.NEEDS_REVIEW: "Needs review",
    }[conf]


def severity_label(sev: Severity) -> str:
    return sev.value.upper()


def risk_label(score: int) -> str:
    if score >= 70:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 30:
        return "Moderate"
    if score >= 15:
        return "Low"
    return "Minimal"


def posture_label(result: ScanResult) -> str:
    score = result.risk_score
    counts = result.counts_by_severity
    if counts.get("critical", 0) > 0 or score >= 70:
        return "critical"
    if counts.get("high", 0) > 0 or score >= 45:
        return "needs-attention"
    if score >= 20:
        return "acceptable"
    return "strong"


def build_executive_summary(result: ScanResult) -> ExecutiveSummary:
    counts = result.counts_by_severity
    conf = result.counts_by_confidence

    security = result.findings_for(Category.SECURITY)
    marketing = result.findings_for(Category.MARKETING)

    actionable_sec = [
        f
        for f in security
        if f.kind in {FindingKind.MISCONFIGURATION, FindingKind.EXPOSURE}
        and f.confidence is Confidence.CONFIRMED
        and f.severity.weight >= Severity.LOW.weight
    ]
    actionable_mkt = [
        f
        for f in marketing
        if f.kind in {FindingKind.MISCONFIGURATION, FindingKind.GAP}
        and f.severity.weight >= Severity.LOW.weight
    ]

    posture = posture_label(result)
    label = risk_label(result.risk_score)

    headline = _headline(posture, counts)

    themes_sec = _themes(
        actionable_sec,
        [
            ("email", "Email authentication & anti-spoofing"),
            ("headers", "HTTP security headers"),
            ("tls", "TLS / transport security"),
            ("cookies", "Cookie attributes"),
            ("exposure", "Exposed files & endpoints"),
            ("subdomains", "Attack surface"),
            ("dns", "DNS configuration"),
            ("mixed-content", "Mixed content"),
            ("redirects", "Redirect handling"),
            ("cors", "Cross-origin policy"),
        ],
    )
    themes_mkt = _themes(
        actionable_mkt,
        [
            ("seo", "On-page SEO fundamentals"),
            ("schema", "Structured data / rich results"),
            ("social", "Social sharing metadata"),
            ("tracking", "Tracking & measurement"),
            ("consent", "Consent & privacy compliance"),
            ("performance", "Performance / Core Web Vitals"),
            ("links", "Link health"),
            ("sitemap", "Crawlability & sitemap"),
            ("tech-stack", "Technology stack"),
        ],
    )

    return ExecutiveSummary(
        headline=headline,
        risk_score=result.risk_score,
        risk_label=label,
        posture=posture,
        total_findings=len(result.findings),
        critical_count=counts.get("critical", 0),
        high_count=counts.get("high", 0),
        confirmed_count=conf.get("confirmed", 0),
        needs_review_count=conf.get("needs_review", 0),
        security_findings=len(security),
        marketing_findings=len(marketing),
        top_security_themes=themes_sec,
        top_marketing_themes=themes_mkt,
        strengths_count=len(result.strongest_points),
        coverage_note=(
            f"Passive scan of one page. "
            f"{len(result.coverage_gaps)} coverage area(s) were not tested — "
            "see the gap list before concluding anything is clean."
        ),
    )


def build_action_plan(result: ScanResult, limit: int = 10) -> list[ActionItem]:
    """Prioritised remediation list, most impactful first.

    Only actionable items appear here — strengths, neutral observations and
    coverage gaps are excluded so the list stays useful.
    """
    actionable = [
        f
        for f in result.findings
        if f.kind
        in {
            FindingKind.MISCONFIGURATION,
            FindingKind.EXPOSURE,
            FindingKind.VULNERABILITY_VECTOR,
        }
        and f.remediation
    ]

    def impact(f: Finding) -> float:
        conf_w = {
            Confidence.CONFIRMED: 1.0,
            Confidence.LIKELY: 0.6,
            Confidence.NEEDS_REVIEW: 0.3,
        }[f.confidence]
        sev_w = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 12,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 0.5,
        }[f.severity]
        return sev_w * conf_w

    actionable.sort(key=lambda f: -impact(f))

    items: list[ActionItem] = []
    for f in actionable[:limit]:
        effort = "quick" if _is_quick(f) else "planned"
        items.append(
            ActionItem(
                finding_id=f.id,
                title=f.title,
                severity=f.severity,
                confidence=f.confidence,
                category=f.category,
                remediation=f.remediation,
                effort=effort,
                impact=int(min(100, impact(f) * 4)),
                tags=f.tags,
            )
        )
    return items


def split_quick_wins(items: list[ActionItem]) -> tuple[list[ActionItem], list[ActionItem]]:
    quick = [i for i in items if i.is_quick_win]
    planned = [i for i in items if not i.is_quick_win]
    return quick, planned


# --------------------------------------------------------------------------- #
def _is_quick(f: Finding) -> bool:
    return any(f.id.startswith(prefix) for prefix in EFFORT_QUICK_PREFIXES)


def _themes(findings: list[Finding], mapping: list[tuple[str, str]]) -> list[str]:
    hits: list[str] = []
    for token, label in mapping:
        for f in findings:
            if token in f.tags or token in f.id:
                if label not in hits:
                    hits.append(label)
                break
    return hits[:6]


def _headline(posture: str, counts: dict[str, int]) -> str:
    crit = counts.get("critical", 0)
    high = counts.get("high", 0)
    if posture == "critical":
        return (
            f"Immediate attention required — {crit} critical and {high} high-impact issue(s) found."
        )
    if posture == "needs-attention":
        return f"Needs attention this week — {high} high-impact issue(s) identified."
    if posture == "acceptable":
        return (
            "Overall posture is acceptable — a short list of improvements would tighten it further."
        )
    return "Strong posture — only hygiene-level improvements remain."
