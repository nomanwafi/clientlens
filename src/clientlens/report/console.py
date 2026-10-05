"""Rich terminal report.

The console output is designed to be readable at a glance and to make the
confidence level impossible to miss — a heuristic never looks like a confirmed
fact on screen.
"""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..branding import AUTHOR_DISPLAY, PROJECT
from ..core.models import (
    Category,
    Confidence,
    Finding,
    FindingKind,
    ScanResult,
    Severity,
)
from .intelligence import build_action_plan, build_executive_summary, split_quick_wins

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}

CONFIDENCE_MARK = {
    Confidence.CONFIRMED: ("●", "green"),
    Confidence.LIKELY: ("◐", "yellow"),
    Confidence.NEEDS_REVIEW: ("○", "magenta"),
}

KIND_MARK = {
    FindingKind.MISCONFIGURATION: ("⚠", "yellow"),
    FindingKind.EXPOSURE: ("!", "red"),
    FindingKind.VULNERABILITY_VECTOR: ("?", "red"),
    FindingKind.STRENGTH: ("✓", "green"),
    FindingKind.OBSERVATION: ("·", "dim"),
    FindingKind.GAP: ("~", "magenta"),
}

CATEGORY_ICON = {
    Category.SECURITY: "🛡",
    Category.MARKETING: "📈",
    Category.SHARED: "⚙",
}


def render(
    result: ScanResult, console: Console | None = None, *, show_evidence: bool = False
) -> None:
    """Render a full scan result to the terminal."""
    c = console or Console(width=110)

    _render_header(result, c)
    _render_exec_summary(result, c)
    _render_summary(result, c)
    _render_top_actions(result, c)
    _render_category_sections(result, c, show_evidence=show_evidence)
    _render_review_queue(result, c)
    _render_coverage(result, c)
    _render_footer(result, c)


def _render_header(result: ScanResult, c: Console) -> None:
    t = result.target
    title = Text()
    title.append(f"  {PROJECT}  ", style="bold white on blue")
    title.append("  ")
    title.append(t.domain, style="bold")
    title.append(f"   ({t.apex})", style="dim")

    meta = Text()
    meta.append("scan_id ", style="dim")
    meta.append(f"{result.scan_id}\n", style="bold")
    meta.append("mode    ", style="dim")
    meta.append(f"{result.scan_mode}\n", style="bold")
    meta.append("started ", style="dim")
    meta.append(f"{result.started_at}\n")
    meta.append("elapsed ", style="dim")
    meta.append(f"{result.duration_ms / 1000:.1f}s\n")
    meta.append("probes  ", style="dim")
    meta.append(f"{result.probes_run} run, {result.probes_failed} failed\n")
    meta.append("author  ", style="dim")
    meta.append(AUTHOR_DISPLAY, style="italic")

    c.print(Panel(meta, title=title, border_style="blue", expand=False))


def _render_exec_summary(result: ScanResult, c: Console) -> None:
    exec_ = build_executive_summary(result)

    color = {
        "critical": "red",
        "needs-attention": "yellow",
        "acceptable": "cyan",
        "strong": "green",
    }[exec_.posture]

    c.print()
    c.rule("[bold]Executive summary[/bold]")
    c.print()
    c.print(f"  [{color} bold]{exec_.headline}[/{color} bold]")
    c.print()
    c.print(
        f"  {exec_.security_findings} security + {exec_.marketing_findings} marketing findings · "
        f"[green]{exec_.confirmed_count} confirmed[/green] · "
        f"[magenta]{exec_.needs_review_count} needs review[/magenta] · "
        f"[green]{exec_.strengths_count} strengths[/green]"
    )
    if exec_.top_security_themes or exec_.top_marketing_themes:
        c.print()
        c.print("  [dim]Top themes:[/dim]")
        for t in exec_.top_security_themes:
            c.print(f"    [blue]▸[/blue] {t}")
        for t in exec_.top_marketing_themes:
            c.print(f"    [cyan]▸[/cyan] {t}")


def _render_top_actions(result: ScanResult, c: Console) -> None:
    plan = build_action_plan(result, limit=8)
    if not plan:
        return

    quick, planned = split_quick_wins(plan)

    c.print()
    c.rule("[bold]Priority actions[/bold]")

    if quick:
        c.print()
        c.print(
            "  [green bold]⚡ Quick wins[/green bold]  [dim](config/header/DNS — minutes)[/dim]"
        )
        for a in quick[:5]:
            sev_style = SEVERITY_STYLE[a.severity]
            c.print(f"    [{sev_style}]●[/{sev_style}] {a.title}")
            c.print(f"      [dim]{a.remediation.splitlines()[0][:96]}[/dim]")

    if planned:
        c.print()
        c.print("  [blue bold]🗓  Planned work[/blue bold]  [dim](code/process — schedule it)[/dim]")
        for a in planned[:5]:
            sev_style = SEVERITY_STYLE[a.severity]
            c.print(f"    [{sev_style}]●[/{sev_style}] {a.title}")
            c.print(f"      [dim]{a.remediation.splitlines()[0][:96]}[/dim]")


def _render_summary(result: ScanResult, c: Console) -> None:
    counts = result.counts_by_severity
    len(result.findings)

    table = Table(box=box.SIMPLE_HEAVY, expand=False, show_header=True, header_style="bold")
    table.add_column("Severity", width=10)
    table.add_column("Count", justify="right", width=6)
    table.add_column("Confidence", justify="right", width=12)

    conf = result.counts_by_confidence
    conf_text = f"● {conf['confirmed']}  ◐ {conf['likely']}  ○ {conf['needs_review']}"

    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        n = counts.get(sev.value, 0)
        style = SEVERITY_STYLE[sev]
        table.add_row(
            Text(SEVERITY_LABEL[sev], style=style),
            Text(str(n), style=style if n else "dim"),
            Text(conf_text if sev is Severity.INFO else "", style="dim"),
        )

    c.print()
    c.rule("[bold]Findings[/bold]")
    c.print(table)

    # Risk score bar
    score = result.risk_score
    color = "red" if score >= 60 else "yellow" if score >= 30 else "green"
    bar_len = 30
    filled = int(score / 100 * bar_len)
    bar = "█" * filled + "░" * (bar_len - filled)
    c.print()
    c.print(f"  Risk score  [{color}]{bar}[/{color}]  [{color} bold]{score}[/] / 100")
    c.print("  [dim]weighted toward confirmed findings — heuristics contribute less[/dim]")


def _render_category_sections(result: ScanResult, c: Console, *, show_evidence: bool) -> None:
    for category in (Category.SECURITY, Category.MARKETING):
        findings = [f for f in result.findings if f.category is category]
        if not findings:
            continue

        icon = CATEGORY_ICON.get(category, "")
        c.print()
        c.rule(f"[bold]{icon}  {category.value.title()}[/bold]")
        _render_finding_table(findings, c, show_evidence=show_evidence)


def _render_finding_table(findings: list[Finding], c: Console, *, show_evidence: bool) -> None:
    # Sort: highest severity first, strengths last.
    order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    findings = sorted(
        findings,
        key=lambda f: (
            f.kind is FindingKind.STRENGTH,
            order[f.severity],
            f.id,
        ),
    )

    table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold")
    table.add_column(" ", width=2, no_wrap=True)
    table.add_column("Sev", width=9, no_wrap=True)
    table.add_column("Finding", ratio=3, overflow="fold")
    table.add_column("Conf", width=5, no_wrap=True)
    table.add_column("Scope", ratio=1, overflow="fold")

    for f in findings:
        kind_char, kind_style = KIND_MARK.get(f.kind, ("·", "dim"))
        conf_char, conf_style = CONFIDENCE_MARK[f.confidence]

        table.add_row(
            Text(kind_char, style=kind_style),
            Text(SEVERITY_LABEL[f.severity], style=SEVERITY_STYLE[f.severity]),
            Text(f.title, style="bold" if f.severity.weight >= 2 else ""),
            Text(conf_char, style=conf_style),
            Text(f.scope or "", style="dim"),
        )

        if show_evidence and f.evidence.raw:
            ev = f.evidence.raw[:400]
            table.add_row("", "", Text(f"  ↳ evidence: {ev}", style="dim"), "", "")

    c.print(table)


def _render_review_queue(result: ScanResult, c: Console) -> None:
    needs = result.needs_review
    if not needs:
        return

    c.print()
    c.rule("[bold magenta]Needs manual review[/bold magenta]")
    c.print(
        "  [dim]These findings are heuristics or coverage gaps. They are NOT confirmed "
        "problems and should not be reported to a client as such.[/dim]"
    )
    c.print()

    for f in needs:
        icon = "○"
        c.print(f"  [magenta]{icon}[/] [bold]{f.title}[/bold]")
        if f.reasoning:
            first_line = f.reasoning.splitlines()[0]
            c.print(f"      [dim]{first_line}[/dim]")


def _render_coverage(result: ScanResult, c: Console) -> None:
    if not result.coverage_gaps:
        return

    c.print()
    c.rule("[bold]What this scan did NOT test[/bold]")
    c.print("  [dim]Silence is not a clean result. These gaps are explicit.[/dim]")
    c.print()

    for gap in result.coverage_gaps:
        c.print(f"  [dim]~[/dim] {gap}")


def _render_footer(result: ScanResult, c: Console) -> None:
    strengths = result.strongest_points
    c.print()
    if strengths:
        c.rule("[bold green]Strengths[/bold green]")
        for f in strengths[:12]:
            c.print(f"  [green]✓[/] {f.title}")
        if len(strengths) > 12:
            c.print(f"  [dim]... and {len(strengths) - 12} more[/dim]")

    c.print()
    c.print(
        "  [dim]ClientLens reports observations with evidence. It does not replace a "
        "penetration test and does not certify any system as secure.[/dim]"
    )
    if result.notes:
        for note in result.notes:
            c.print(f"  [dim]{note}[/dim]")
    c.print()
