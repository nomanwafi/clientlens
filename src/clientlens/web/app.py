"""FastAPI dashboard for ClientLens scan history.

Read-only by default: it lists past scans, renders a saved scan as HTML and
diffs two scans. It never scans anything — scanning stays in the CLI so that
the authorisation acknowledgement cannot be bypassed by a web form.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse

from ..core.models import ScanResult
from ..report.html_export import render_html
from ..storage.db import Storage

TEMPLATES = Path(__file__).parent / "templates"

app = FastAPI(
    title="ClientLens dashboard",
    description="View and compare saved ClientLens scans. Scanning is not available from the web UI.",
    version="0.1.0",
)

_storage: Storage | None = None


def get_storage() -> Storage:
    global _storage
    if _storage is None:
        _storage = Storage()
    return _storage


def set_storage(storage: Storage) -> None:
    """Used by tests to inject an isolated database."""
    global _storage
    _storage = storage


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
@app.get("/api/scans")
def api_scans(domain: str | None = Query(None), limit: int = Query(50, le=200)):
    rows = get_storage().list_scans(domain=domain, limit=limit)
    return [
        {
            "id": r.id,
            "domain": r.domain,
            "apex": r.apex,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "risk_score": r.risk_score,
            "findings_total": r.findings_total,
            "critical": r.findings_critical,
            "high": r.findings_high,
            "medium": r.findings_medium,
            "low": r.findings_low,
            "confirmed": r.confirmed,
            "needs_review": r.needs_review,
            "scan_mode": r.scan_mode,
        }
        for r in rows
    ]


@app.get("/api/scans/{scan_id}")
def api_scan(scan_id: str):
    record = get_storage().get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="scan not found")
    return json.loads(record.payload)


@app.get("/api/scans/{scan_id}/findings")
def api_findings(scan_id: str, confidence: str | None = None, severity: str | None = None):
    record = get_storage().get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="scan not found")
    payload = json.loads(record.payload)
    findings = payload.get("findings", [])
    if confidence:
        findings = [f for f in findings if f["confidence"] == confidence]
    if severity:
        findings = [f for f in findings if f["severity"] == severity]
    return findings


@app.get("/api/diff/{before_id}/{after_id}")
def api_diff(before_id: str, after_id: str):
    try:
        return get_storage().diff(before_id, after_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/domains")
def api_domains():
    return get_storage().domains()


# --------------------------------------------------------------------------- #
# HTML pages
# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse)
def dashboard(domain: str | None = Query(None)):
    storage = get_storage()
    rows = storage.list_scans(domain=domain, limit=100)
    domains = storage.domains()

    cards = [
        {
            "id": r.id,
            "domain": r.domain,
            "started": r.started_at.strftime("%Y-%m-%d %H:%M") if r.started_at else "",
            "risk": r.risk_score or 0,
            "findings": r.findings_total or 0,
            "critical": r.findings_critical or 0,
            "high": r.findings_high or 0,
            "confirmed": r.confirmed or 0,
            "needs_review": r.needs_review or 0,
            "mode": r.scan_mode,
        }
        for r in rows
    ]

    return HTMLResponse(_dashboard_html(cards, domains, domain))


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_page(scan_id: str):
    record = get_storage().get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="scan not found")
    result = _result_from_payload(json.loads(record.payload))
    return HTMLResponse(render_html(result))


@app.get("/diff/{before_id}/{after_id}", response_class=HTMLResponse)
def diff_page(before_id: str, after_id: str):
    try:
        diff = get_storage().diff(before_id, after_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return HTMLResponse(_diff_html(diff))


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _result_from_payload(data: dict) -> ScanResult:
    from .. import __version__
    from ..core.models import (
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


def _dashboard_html(cards: list[dict], domains: list[str], active: str | None) -> str:
    rows_html = ""
    for c in cards:
        risk_color = "#c81e1e" if c["risk"] >= 60 else "#b45309" if c["risk"] >= 30 else "#15803d"
        rows_html += f"""
        <tr>
          <td><a href="/scans/{c['id']}"><strong>{c['domain']}</strong></a>
              <div class="tiny">{c['id']}</div></td>
          <td>{c['started']}</td>
          <td><span class="pill" style="background:{risk_color}">{c['risk']}</span></td>
          <td>{c['findings']}</td>
          <td>{c['critical']} / {c['high']}</td>
          <td>{c['confirmed']}</td>
          <td>{c['needs_review']}</td>
          <td><span class="mode">{c['mode']}</span></td>
        </tr>"""

    filter_html = '<a class="chip {"on" if not active else ""}" href="/">all</a>'
    for d in domains:
        cls = "on" if active == d else ""
        filter_html += f'<a class="chip {cls}" href="/?domain={d}">{d}</a>'

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ClientLens · dashboard</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ margin:0; padding:32px; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif;
         color:#12161c; background:#f7f9fa; font-size:14px; }}
  .wrap {{ max-width:1100px; margin:0 auto; }}
  header {{ display:flex; align-items:baseline; gap:14px; margin-bottom:8px; }}
  .brand {{ background:#12161c; color:#fff; padding:5px 12px; font-weight:700;
            font-size:12px; letter-spacing:0.5px; text-transform:uppercase; }}
  h1 {{ font-size:24px; margin:0; letter-spacing:-0.4px; }}
  .sub {{ color:#6b7480; margin:0 0 22px 0; }}
  table {{ width:100%; border-collapse:collapse; background:#fff;
           border:1px solid #e2e6ea; border-radius:10px; overflow:hidden; }}
  th {{ text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:0.7px;
        color:#6b7480; padding:11px 14px; border-bottom:1px solid #e2e6ea; background:#fbfcfd; }}
  td {{ padding:12px 14px; border-bottom:1px solid #eef1f3; vertical-align:top; }}
  tr:last-child td {{ border-bottom:none; }}
  a {{ color:#1a56db; text-decoration:none; }}
  a:hover {{ text-decoration:underline; }}
  .tiny {{ color:#98a1ab; font-size:11px; font-family:ui-monospace,Menlo,monospace; }}
  .pill {{ display:inline-block; min-width:34px; text-align:center; color:#fff;
           border-radius:20px; padding:2px 10px; font-weight:700; font-size:12px; }}
  .mode {{ background:#eef1f3; border-radius:4px; padding:2px 8px; font-size:11px;
           text-transform:uppercase; letter-spacing:0.5px; color:#6b7480; }}
  .chips {{ margin:0 0 18px 0; display:flex; flex-wrap:wrap; gap:7px; }}
  .chip {{ background:#fff; border:1px solid #e2e6ea; border-radius:20px;
           padding:4px 13px; font-size:12px; color:#6b7480; text-decoration:none; }}
  .chip.on {{ background:#12161c; color:#fff; border-color:#12161c; }}
  .empty {{ background:#fff; border:1px dashed #d5dbe0; border-radius:10px;
            padding:40px; text-align:center; color:#6b7480; }}
  .empty code {{ background:#f2f4f6; padding:3px 8px; border-radius:4px; }}
</style></head>
<body><div class="wrap">
<header><div class="brand">ClientLens</div><h1>Scan history</h1></header>
<p class="sub">Saved scans on this machine. Scanning is not available from the web UI —
use the CLI, which requires an explicit authorisation acknowledgement.</p>
<div class="chips">{filter_html}</div>
{'<table><tr><th>Target</th><th>Scanned</th><th>Risk</th><th>Findings</th><th>Crit/High</th><th>Confirmed</th><th>Needs review</th><th>Mode</th></tr>' + rows_html + '</table>' if cards else '<div class="empty">No scans yet.<br><br>Run one with<br><code>clientlens scan example.com --i-am-authorized -o scan.json</code></div>'}
</div></body></html>"""


def _diff_html(diff: dict) -> str:
    def rows(items, fmt):
        if not items:
            return '<tr><td colspan="3" style="color:#98a1ab">none</td></tr>'
        return "".join(fmt(i) for i in items)

    added = rows(
        diff["added"],
        lambda f: f'<tr><td>{f["severity"]}</td><td>{f["title"]}</td><td class="tiny">{f["id"]}</td></tr>',
    )
    removed = rows(
        diff["removed"],
        lambda f: f'<tr><td>{f["severity"]}</td><td>{f["title"]}</td><td class="tiny">{f["id"]}</td></tr>',
    )
    changed = rows(
        diff["changed"],
        lambda f: f'<tr><td>{f["before"]} → {f["after"]}</td><td>{f["title"]}</td><td class="tiny">{f["id"]}</td></tr>',
    )

    delta = diff["risk_delta"]
    delta_color = "#c81e1e" if delta > 0 else "#15803d" if delta < 0 else "#6b7480"

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ClientLens · diff</title>
<style>
  * {{ box-sizing:border-box; }}
  body {{ margin:0; padding:32px; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif;
         color:#12161c; background:#f7f9fa; font-size:14px; }}
  .wrap {{ max-width:1000px; margin:0 auto; }}
  h1 {{ font-size:24px; margin:0 0 6px; letter-spacing:-0.4px; }}
  .sub {{ color:#6b7480; margin:0 0 24px; }}
  h2 {{ font-size:12px; text-transform:uppercase; letter-spacing:1px; color:#6b7480;
        border-bottom:1px solid #e2e6ea; padding-bottom:7px; margin:26px 0 11px; }}
  table {{ width:100%; border-collapse:collapse; background:#fff;
           border:1px solid #e2e6ea; border-radius:9px; overflow:hidden; }}
  th {{ text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:0.6px;
        color:#6b7480; padding:10px 13px; border-bottom:1px solid #e2e6ea; background:#fbfcfd; }}
  td {{ padding:10px 13px; border-bottom:1px solid #eef1f3; }}
  .tiny {{ color:#98a1ab; font-size:11px; font-family:ui-monospace,Menlo,monospace; }}
  .delta {{ font-size:30px; font-weight:750; letter-spacing:-1px; }}
</style></head>
<body><div class="wrap">
<h1>Scan diff</h1>
<p class="sub">{diff['before']['scan_id']} → {diff['after']['scan_id']}</p>
<p>Risk score <span class="delta" style="color:{delta_color}">{diff['after']['risk']}</span>
<span style="color:#6b7480">({delta:+d} from {diff['before']['risk']})</span></p>

<h2>New findings ({len(diff['added'])})</h2>
<table><tr><th>Severity</th><th>Finding</th><th>ID</th></tr>{added}</table>

<h2>Resolved findings ({len(diff['removed'])})</h2>
<table><tr><th>Severity</th><th>Finding</th><th>ID</th></tr>{removed}</table>

<h2>Severity changes ({len(diff['changed'])})</h2>
<table><tr><th>Change</th><th>Finding</th><th>ID</th></tr>{changed}</table>
</div></body></html>"""


def create_app(storage: Storage | None = None) -> FastAPI:
    if storage is not None:
        set_storage(storage)
    return app
