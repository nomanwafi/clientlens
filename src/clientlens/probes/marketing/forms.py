"""Form hygiene — action/method/label/sensitive-field analysis.

Every form on the homepage is checked for the mistakes that cost both
conversions (unlabeled inputs) and privacy (sensitive fields via GET).
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


@register_probe(
    id="marketing.forms",
    category=Category.MARKETING,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("html",),
    title="Form hygiene",
    description="Form actions, methods, labels and sensitive-field handling.",
    tags=("forms", "accessibility", "security", "conversion"),
)
async def check_forms(ctx: ProbeContext) -> list[Finding]:
    """Analyse every form on the homepage."""
    html = ctx.require("html")
    findings: list[Finding] = []
    source = html.final_url

    forms = html.soup.find_all("form")
    if not forms:
        findings.append(
            Finding(
                id="marketing.forms.none",
                title="No forms on the homepage",
                category=Category.MARKETING,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.html_node("form", "(none)", source=source),
                reasoning="No <form> elements found on the homepage.",
                scope=f"HTML <form> elements of {source}",
                tags=["forms"],
            )
        )
        return findings

    findings.append(
        Finding(
            id="marketing.forms.count",
            title=f"{len(forms)} form(s) on the homepage",
            category=Category.MARKETING,
            kind=FindingKind.OBSERVATION,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            evidence=Evidence.text(f"{len(forms)} <form> elements", source=source),
            reasoning="Forms are the primary conversion surface; their hygiene affects both conversion and security.",
            scope=f"HTML <form> elements of {source}",
            tags=["forms", "conversion"],
        )
    )

    for idx, form in enumerate(forms):
        action = str(form.get("action", ""))
        method = str(form.get("method", "get")).lower()
        action_host = urlparse(action).hostname if action.startswith("http") else ""

        # Sensitive fields submitted via GET end up in the URL.
        has_password = form.find("input", attrs={"type": "password"}) is not None
        has_email = form.find("input", attrs={"type": "email"}) is not None

        if method == "get" and (has_password or has_email):
            findings.append(
                Finding(
                    id=f"marketing.forms.form_{idx}_get_sensitive",
                    title=f"Form {idx + 1} submits sensitive fields via GET",
                    category=Category.MARKETING,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.html_node("form", str(form)[:300], source=source),
                    reasoning=(
                        "A GET form puts its field values in the URL query string. "
                        "URLs end up in browser history, server logs, referrer "
                        "headers and analytics tools — so an email or password "
                        "submitted this way is written into logs in the clear."
                    ),
                    scope=f"Form {idx + 1} of {source}",
                    remediation="Change the form method to POST.",
                    tags=["forms", "security", "privacy"],
                )
            )

        # Cross-origin action.
        if action_host and action_host != urlparse(html.base_url).hostname:
            findings.append(
                Finding(
                    id=f"marketing.forms.form_{idx}_cross_origin",
                    title=f"Form {idx + 1} submits to a different origin ({action_host})",
                    category=Category.MARKETING,
                    kind=FindingKind.OBSERVATION,
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.html_node("form", f'action="{action}"', source=source),
                    reasoning=(
                        f"The form posts to {action_host}. This is common for "
                        "third-party form handlers and payment processors. Confirm "
                        "the destination is expected and covered by the privacy notice."
                    ),
                    scope=f"Form {idx + 1} of {source}",
                    tags=["forms", "privacy", "third-party"],
                )
            )

        # Unlabeled inputs.
        inputs = form.find_all(["input", "select", "textarea"])
        unlabeled = 0
        for inp in inputs:
            itype = (inp.get("type") or "").lower()
            if itype in {"hidden", "submit", "button", "image", "reset"}:
                continue
            has_label = (
                (inp.get("id") and form.find("label", attrs={"for": inp.get("id")}))
                or inp.get("aria-label")
                or inp.get("aria-labelledby")
                or inp.get("placeholder")
            )
            if not has_label:
                unlabeled += 1

        if unlabeled:
            findings.append(
                Finding(
                    id=f"marketing.forms.form_{idx}_unlabeled",
                    title=f"Form {idx + 1} has {unlabeled} input(s) without a label",
                    category=Category.MARKETING,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.html_node("form", str(form)[:250], source=source),
                    reasoning=(
                        "Inputs without a <label>, aria-label or placeholder are "
                        "invisible to screen readers and harder to complete. This "
                        "directly lowers form completion rate."
                    ),
                    scope=f"Form {idx + 1} of {source}",
                    remediation="Add a <label for> (or aria-label) to every input.",
                    tags=["forms", "accessibility", "conversion"],
                )
            )

    return findings
