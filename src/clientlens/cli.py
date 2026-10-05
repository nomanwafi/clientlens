"""ClientLens command-line interface.

The CLI is deliberately conservative: it refuses to scan without an explicit
authorisation acknowledgement, and it always states what was not tested.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from . import __version__
from .branding import AUTHOR_DISPLAY
from .core.config import ScanConfig
from .core.engine import ScanEngine
from .core.exceptions import AuthorizationRequired, ClientLensError, InvalidTarget
from .core.models import ScanResult
from .core.registry import REGISTRY
from .report import console as console_report
from .report.csv_export import write_csv
from .report.html_export import write_html
from .report.json_export import write_json

app = typer.Typer(
    name="clientlens",
    help=(
        "Unified client audit engine — security + marketing reconnaissance "
        "in one evidence-backed report."
    ),
    add_completion=True,
    no_args_is_help=True,
)

console = Console()

AUTH_NOTICE = (
    "[bold yellow]Authorisation required.[/bold yellow]\n\n"
    "Only scan domains you own or have written permission to test.\n"
    "Pass [bold]--i-am-authorized[/bold] to confirm."
)


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #
@app.command()
def scan(
    target: str = typer.Argument(..., help="Domain or URL to audit, e.g. example.com"),
    i_am_authorized: bool = typer.Option(
        False,
        "--i-am-authorized",
        help="Confirm you are authorised to scan this target. Required.",
    ),
    active: bool = typer.Option(
        False,
        "--active",
        help="Enable active probes (path enumeration, open-redirect tests, CORS probes).",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the JSON report to this path.",
    ),
    html: Path | None = typer.Option(
        None,
        "--html",
        help="Write the HTML report to this path (print-ready, use Print -> Save as PDF).",
    ),
    pdf: Path | None = typer.Option(
        None,
        "--pdf",
        help="Write a PDF report to this path (requires the optional 'pdf' extra).",
    ),
    show_evidence: bool = typer.Option(
        False,
        "--show-evidence",
        "-e",
        help="Include raw evidence snippets in the console output.",
    ),
    preset: str | None = typer.Option(
        "standard",
        "--preset",
        help="Probe set: quick (~10 probes), standard (~24), deep (~33).",
    ),
    include: list[str] | None = typer.Option(
        None,
        "--include",
        "-i",
        help="Only run probes whose id starts with this prefix (repeatable).",
    ),
    exclude: list[str] | None = typer.Option(
        None,
        "--exclude",
        "-x",
        help="Skip probes whose id starts with this prefix (repeatable).",
    ),
    csv: Path | None = typer.Option(
        None,
        "--csv",
        help="Write a CSV export of findings to this path.",
    ),
    timeout: float = typer.Option(12.0, "--timeout", help="Per-request timeout in seconds."),
    rate: float = typer.Option(
        5.0, "--rate", help="Maximum requests per second against the target."
    ),
    max_requests: int = typer.Option(
        120, "--max-requests", help="Hard cap on total requests for the whole scan."
    ),
    crtsh: bool = typer.Option(
        True, "--crtsh/--no-crtsh", help="Use crt.sh for subdomain discovery (free, no key)."
    ),
    allow_private: bool = typer.Option(
        False, "--allow-private", help="Allow scanning private/loopback addresses."
    ),
    save: bool = typer.Option(
        True,
        "--save/--no-save",
        help="Save the scan to the local history database (used by the dashboard).",
    ),
) -> None:
    """Run a full audit against one target."""
    if not i_am_authorized:
        console.print(Panel(AUTH_NOTICE, title="Refused", border_style="red"))
        raise typer.Exit(code=2)

    config = ScanConfig(
        authorized=True,
        allow_active=active,
        allow_private=allow_private,
        timeout_s=timeout,
        rate_limit_per_second=rate,
        max_requests_per_scan=max_requests,
        use_crtsh=crtsh,
        include_probes=list(include or []),
        exclude_probes=list(exclude or []),
        preset=preset,
    )

    console.print()
    console.print(
        f"  [bold blue]ClientLens[/bold blue] v{__version__}  ·  [bold]{target}[/bold]"
        f"  ·  preset=[bold]{preset}[/bold] · mode=[bold]{config.scan_mode}[/bold]"
    )
    console.print(
        "  [dim]Request budget: "
        f"{max_requests} requests max, {rate}/sec rate limit, "
        f"{timeout}s timeout[/dim]"
    )
    console.print()

    engine = ScanEngine(config)

    try:
        result = asyncio.run(engine.run(target))
    except AuthorizationRequired as exc:
        console.print(Panel(str(exc), title="Refused", border_style="red"))
        raise typer.Exit(code=2) from exc
    except InvalidTarget as exc:
        console.print(Panel(f"[red]{exc}[/red]", title="Invalid target", border_style="red"))
        raise typer.Exit(code=2) from exc
    except ClientLensError as exc:
        console.print(Panel(f"[red]{exc}[/red]", title="Scan error", border_style="red"))
        raise typer.Exit(code=1) from exc
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted.[/yellow]")
        raise typer.Exit(code=130) from None

    console_report.render(result, console, show_evidence=show_evidence)

    if save:
        try:
            from .storage.db import Storage

            record = Storage().save(result)
            console.print(f"  [dim]saved to history[/dim] ({record.id})")
        except Exception as exc:  # noqa: BLE001 - storage failure must not break the scan
            console.print(f"  [yellow]history save skipped[/yellow] — {exc}")

    if output:
        write_json(result, output)
        console.print(f"  [green]JSON report[/green] → {output}")
    if html:
        write_html(result, html)
        console.print(f"  [green]HTML report[/green] → {html}")
    if csv:
        write_csv(result, csv)
        console.print(f"  [green]CSV report[/green]  → {csv}")
    if pdf:
        try:
            from .report.pdf_export import write_pdf

            write_pdf(result, pdf)
            console.print(f"  [green]PDF report[/green]  → {pdf}")
        except ImportError as exc:
            console.print(f"  [yellow]PDF skipped[/yellow] — {exc}")
        except Exception as exc:  # noqa: BLE001
            console.print(f"  [yellow]PDF failed[/yellow] — {exc}")
            console.print(
                "  [dim]Open the HTML report in a browser and use Print -> Save as PDF instead.[/dim]"
            )

    console.print()

    # Exit code reflects whether anything needs attention.
    counts = result.counts_by_severity
    if counts.get("critical", 0) or counts.get("high", 0):
        raise typer.Exit(code=3)


# --------------------------------------------------------------------------- #
# probes
# --------------------------------------------------------------------------- #
@app.command()
def probes(
    preset: str | None = typer.Option(
        None,
        "--preset",
        help="Show which probes run under a given preset.",
    ),
) -> None:
    """List every available probe."""
    import clientlens.probes  # noqa: F401  - triggers registration

    table_rows = []
    for pid in REGISTRY.ids():
        spec = REGISTRY.get(pid)
        table_rows.append((pid, spec.phase.value, spec.mode.value, spec.category.value, spec.title))

    # Determine subset if --preset is supplied.
    included_ids: set[str] | None = None
    if preset:
        cfg = ScanConfig(authorized=True, preset=preset, allow_active=True)
        # Use the same filtering logic the engine uses.
        from .core.engine import ScanEngine

        included_ids = {s.id for s in ScanEngine(cfg)._select_specs()}

    console.print()
    total = len(table_rows)
    shown = 0
    console.print(f"[bold]Registered probes[/bold] ({total})")
    console.print()
    for pid, _phase, mode, cat, title in table_rows:
        if included_ids is not None and pid not in included_ids:
            continue
        shown += 1
        mode_style = "yellow" if mode == "active" else "dim"
        preset_marker = "  " if included_ids is None else "✓ "
        console.print(
            f"  {preset_marker}[bold]{pid:38}[/bold]  [{mode_style}]{mode:7}[/{mode_style}]  {cat:10}  {title}"
        )
    if included_ids is not None:
        console.print()
        console.print(f"  [dim]{shown} of {total} probes selected by the '{preset}' preset.[/dim]")
    console.print()
    console.print(
        "  [dim]Active probes only run with --active. Passive probes make 1-5 requests total.[/dim]"
    )
    console.print()


# --------------------------------------------------------------------------- #
# dashboard
# --------------------------------------------------------------------------- #
@app.command()
def dashboard(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address."),
    port: int = typer.Option(8765, "--port", help="Port to listen on."),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on code change."),
) -> None:
    """Serve the local scan-history dashboard.

    Read-only: it lists and renders saved scans. Scanning stays in the CLI so
    the authorisation acknowledgement cannot be bypassed by a web form.
    """
    try:
        import uvicorn
    except ImportError as exc:
        console.print(
            "[yellow]Dashboard requires the optional 'web' extra.[/yellow]\n"
            "Install with: uv sync --extra web"
        )
        raise typer.Exit(code=2) from exc

    console.print()
    console.print(f"  [bold blue]ClientLens dashboard[/bold blue] → http://{host}:{port}")
    console.print(
        "  [dim]Read-only. Scanning is not available from the web UI. Press Ctrl+C to stop.[/dim]"
    )
    console.print()

    uvicorn.run(
        "clientlens.web.app:app",
        host=host,
        port=port,
        reload=reload,
        log_level="warning",
    )


# --------------------------------------------------------------------------- #
# diff
# --------------------------------------------------------------------------- #
@app.command()
def diff(
    before: str = typer.Argument(..., help="Scan id of the earlier scan."),
    after: str = typer.Argument(..., help="Scan id of the later scan."),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON instead of a table."),
) -> None:
    """Compare two saved scans of the same domain."""
    from .storage.db import Storage

    storage = Storage()
    try:
        result = storage.diff(before, after)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc

    if json_out:
        import json as _json

        console.print_json(_json.dumps(result))
        return

    console.print()
    console.print(f"[bold]Scan diff[/bold]  {before} → {after}")
    console.print(
        f"  risk score  {result['before']['risk']} → {result['after']['risk']} "
        f"({result['risk_delta']:+d})"
    )
    console.print()

    console.print(f"[bold]New findings[/bold] ({len(result['added'])})")
    for f in result["added"]:
        console.print(f"  [red]![/] [{f['severity']}] {f['title']}  [dim]{f['id']}[/dim]")
    if not result["added"]:
        console.print("  [dim]none[/dim]")

    console.print()
    console.print(f"[bold]Resolved findings[/bold] ({len(result['removed'])})")
    for f in result["removed"]:
        console.print(f"  [green]✓[/] [{f['severity']}] {f['title']}  [dim]{f['id']}[/dim]")
    if not result["removed"]:
        console.print("  [dim]none[/dim]")

    console.print()
    console.print(f"[bold]Severity changes[/bold] ({len(result['changed'])})")
    for f in result["changed"]:
        console.print(f"  [yellow]~[/] {f['before']} → {f['after']}  {f['title']}")
    if not result["changed"]:
        console.print("  [dim]none[/dim]")
    console.print()


# --------------------------------------------------------------------------- #
# history
# --------------------------------------------------------------------------- #
@app.command()
def history(
    domain: str | None = typer.Option(None, "--domain", "-d", help="Filter by domain."),
    limit: int = typer.Option(25, "--limit", "-n", help="Maximum rows to show."),
) -> None:
    """List saved scans."""
    from .storage.db import Storage

    rows = Storage().list_scans(domain=domain, limit=limit)
    if not rows:
        console.print(
            "[dim]No saved scans. Run `clientlens scan <domain> --i-am-authorized` first.[/dim]"
        )
        return

    console.print()
    console.print(f"[bold]Scan history[/bold] ({len(rows)} shown)")
    console.print()
    for r in rows:
        started = r.started_at.strftime("%Y-%m-%d %H:%M") if r.started_at else "?"
        risk_color = (
            "red"
            if (r.risk_score or 0) >= 60
            else "yellow"
            if (r.risk_score or 0) >= 30
            else "green"
        )
        console.print(
            f"  [bold]{r.domain:24}[/bold]  {started}  "
            f"[{risk_color}]{r.risk_score or 0:3d}[/{risk_color}]  "
            f"{r.findings_total or 0:3d} findings  "
            f"[red]{r.findings_critical or 0}c[/red] [yellow]{r.findings_high or 0}h[/yellow]  "
            f"[dim]{r.id}[/dim]"
        )
    console.print()
    console.print(
        "  [dim]Open the dashboard with `clientlens dashboard` to view full reports.[/dim]"
    )
    console.print()


# --------------------------------------------------------------------------- #
# version
# --------------------------------------------------------------------------- #
@app.command()
def version() -> None:
    """Print the ClientLens version."""
    console.print(f"clientlens {__version__}")
    console.print(f"author: {AUTHOR_DISPLAY}")


# --------------------------------------------------------------------------- #
# report (regenerate from a saved JSON scan)
# --------------------------------------------------------------------------- #
@app.command()
def report(
    json_path: Path = typer.Argument(..., help="A JSON scan file previously written with -o."),
    html: Path | None = typer.Option(None, "--html", help="Write HTML report to this path."),
    pdf: Path | None = typer.Option(None, "--pdf", help="Write PDF report to this path."),
) -> None:
    """Regenerate reports from a saved JSON scan."""
    from .report.json_export import load_json

    if not json_path.exists():
        console.print(f"[red]File not found:[/red] {json_path}")
        raise typer.Exit(code=2)

    data = load_json(json_path)
    result = _scan_result_from_dict(data)
    console_report.render(result, console)
    if html:
        write_html(result, html)
        console.print(f"  [green]HTML report[/green] → {html}")
    if pdf:
        try:
            from .report.pdf_export import write_pdf

            write_pdf(result, pdf)
            console.print(f"  [green]PDF report[/green]  → {pdf}")
        except ImportError as exc:
            console.print(f"  [yellow]PDF skipped[/yellow] — {exc}")


# --------------------------------------------------------------------------- #
def _scan_result_from_dict(data: dict) -> ScanResult:
    from .core.models import (
        Category,
        Confidence,
        Evidence,
        EvidenceType,
        Finding,
        FindingKind,
        ScanTarget,
        Severity,
    )

    t = data["target"]
    target = ScanTarget(
        raw=t["raw"],
        domain=t["domain"],
        apex=t["apex"],
        scheme=t.get("scheme", "https"),
        base_url=t.get("base_url", ""),
        resolved_ips=t.get("resolved_ips", []),
    )

    findings = []
    for fd in data.get("findings", []):
        ev = fd.get("evidence", {})
        findings.append(
            Finding(
                id=fd["id"],
                title=fd["title"],
                category=Category(fd["category"]),
                kind=FindingKind(fd["kind"]),
                severity=Severity(fd["severity"]),
                confidence=Confidence(fd["confidence"]),
                evidence=Evidence(
                    type=EvidenceType(ev.get("type", "text")),
                    raw=ev.get("raw", ""),
                    summary=ev.get("summary", ""),
                    source=ev.get("source", ""),
                    captured_at=ev.get("captured_at", ""),
                ),
                reasoning=fd.get("reasoning", ""),
                scope=fd.get("scope", ""),
                remediation=fd.get("remediation", ""),
                references=fd.get("references", []),
                tags=fd.get("tags", []),
                probe_id=fd.get("probe_id", ""),
                target=fd.get("target", ""),
                recorded_at=fd.get("recorded_at", ""),
            )
        )

    return ScanResult(
        target=target,
        scan_id=data.get("scan_id", ""),
        started_at=data.get("started_at", ""),
        finished_at=data.get("finished_at", ""),
        duration_ms=data.get("duration_ms", 0),
        clientlens_version=data.get("clientlens_version", __version__),
        scan_mode=data.get("scan_mode", "passive"),
        authorized=data.get("authorized", False),
        findings=findings,
        notes=data.get("notes", []),
        coverage_gaps=data.get("coverage_gaps", []),
    )


def main() -> None:  # pragma: no cover
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
