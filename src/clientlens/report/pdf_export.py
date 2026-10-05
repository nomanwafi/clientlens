"""PDF report generator.

Uses xhtml2pdf, which implements only a subset of CSS. This module renders a
dedicated, table-based template designed for that subset rather than reusing
the screen HTML — the result is a genuinely usable client deliverable.

If the optional ``xhtml2pdf`` dependency is not installed, the CLI tells the
user to open the HTML report and print to PDF instead of failing.
"""

from __future__ import annotations

import io
from pathlib import Path

from jinja2 import BaseLoader, Environment, select_autoescape

from ..branding import AUTHOR_DISPLAY, PROJECT, URL
from ..core.models import Category, Finding, ScanResult
from .intelligence import build_action_plan, build_executive_summary, split_quick_wins

PDF_TEMPLATE = r"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  @page { size: a4; margin: 1.5cm 1.4cm 1.7cm 1.4cm; }
  body { font-family: Helvetica, Arial, sans-serif; font-size: 9pt; color: #1a1a1a; line-height: 1.4; }

  .cover { background: #0b3d91; color: #ffffff; padding: 14pt 16pt; margin: 0 0 12pt 0; }
  .cover .brand { font-size: 9pt; font-weight: bold; letter-spacing: 1.2pt; text-transform: uppercase; opacity: 0.9; }
  .cover h1 { font-size: 22pt; margin: 6pt 0 2pt 0; color: #ffffff; }
  .cover .sub { font-size: 9pt; opacity: 0.92; }
  .cover .by { font-size: 8pt; text-transform: uppercase; letter-spacing: 1.2pt; opacity: 0.85; margin-top: 8pt; }

  h1 { font-size: 20pt; margin: 0 0 2pt 0; color: #111111; }
  h2 { font-size: 10.5pt; margin: 15pt 0 6pt 0; color: #111111; border-bottom: 1.2pt solid #111111; padding-bottom: 3pt; text-transform: uppercase; letter-spacing: 0.8pt; }
  h3 { font-size: 9.5pt; margin: 10pt 0 4pt 0; color: #222222; }
  p  { margin: 0 0 5pt 0; }
  .muted { color: #666666; }
  .tiny  { font-size: 7.5pt; color: #777777; }
  .mono  { font-family: Courier, monospace; font-size: 8pt; }

  table { width: 100%; border-collapse: collapse; }
  .meta td { border: 0.5pt solid #cccccc; padding: 4pt 6pt; font-size: 8.5pt; }
  .meta td.k { background: #f2f2f2; color: #444444; width: 22%; font-size: 7.5pt; text-transform: uppercase; letter-spacing: 0.5pt; }

  .riskbox { border: 1pt solid #cccccc; padding: 8pt 10pt; margin: 8pt 0 10pt 0; background: #f7f7f7; }
  .riskbox .score { font-size: 22pt; font-weight: bold; }

  .sevbar td { border: 0.5pt solid #cccccc; padding: 5pt 6pt; text-align: center; font-size: 8pt; }
  .sevbar td.n { font-size: 15pt; font-weight: bold; }
  .sev-critical { background: #b91c1c; color: #ffffff; }
  .sev-high     { background: #dc2626; color: #ffffff; }
  .sev-medium   { background: #d97706; color: #ffffff; }
  .sev-low      { background: #2563eb; color: #ffffff; }
  .sev-info     { background: #dddddd; color: #333333; }

  .exec { border: 1pt solid #cccccc; padding: 10pt 12pt; margin: 8pt 0 12pt 0; background: #fbfcfd; }
  .exec .headline { font-size: 11pt; font-weight: bold; margin: 0 0 6pt 0; }
  .exec .pills { margin-top: 6pt; }
  .exec .pill { display: inline-block; background: #eef2f6; border: 0.5pt solid #d5dbe0; padding: 1pt 7pt; margin: 1pt 2pt 1pt 0; font-size: 8pt; color: #333333; }

  .road td { vertical-align: top; width: 50%; padding: 6pt 8pt; border: 0.5pt solid #cccccc; }
  .road .lane-h { font-weight: bold; font-size: 9pt; margin-bottom: 5pt; }
  .road .lane-h.quick { color: #059669; }
  .road .lane-h.planned { color: #1565d8; }
  .road .item { margin: 6pt 0; padding-left: 7pt; border-left: 2.5pt solid #cccccc; font-size: 8.5pt; }
  .road .item.quick { border-left-color: #059669; }
  .road .item.planned { border-left-color: #1565d8; }
  .road .item .t { font-weight: bold; }
  .road .item .m { color: #666666; font-size: 7.5pt; }

  .finding { border: 0.5pt solid #cccccc; margin: 0 0 7pt 0; }
  .finding-head { background: #f2f2f2; padding: 5pt 7pt; border-bottom: 0.5pt solid #cccccc; }
  .finding-head .title { font-size: 9.5pt; font-weight: bold; }
  .badge { display: inline-block; padding: 1pt 5pt; font-size: 7pt; font-weight: bold; letter-spacing: 0.4pt; color: #ffffff; }
  .badge-critical { background: #b91c1c; }
  .badge-high     { background: #dc2626; }
  .badge-medium   { background: #d97706; }
  .badge-low      { background: #2563eb; }
  .badge-info     { background: #888888; }
  .conf { display: inline-block; padding: 1pt 5pt; font-size: 7pt; font-weight: bold; border: 0.5pt solid #999999; color: #333333; background: #ffffff; }
  .conf-confirmed   { border-color: #15803d; color: #15803d; }
  .conf-likely      { border-color: #a16207; color: #a16207; }
  .conf-needs_review{ border-color: #7c3aed; color: #7c3aed; }

  .finding-body { padding: 6pt 7pt; }
  .kv { margin: 3pt 0; font-size: 8pt; }
  .kv .k { color: #666666; text-transform: uppercase; font-size: 7pt; letter-spacing: 0.4pt; }
  .evidence { background: #f6f6f6; border-left: 2pt solid #999999; padding: 4pt 6pt; margin: 4pt 0; font-family: Courier, monospace; font-size: 6.5pt; color: #333333; white-space: pre-wrap; word-wrap: break-word; overflow-wrap: break-word; }
  .remediation { background: #eef6ee; border-left: 2.5pt solid #15803d; padding: 4pt 6pt; margin: 5pt 0 0 0; }
  .remediation .k { color: #15803d; font-size: 7pt; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5pt; }

  .gaps { background: #f5f3ff; border: 0.5pt solid #d8b4fe; padding: 7pt 9pt; }
  .gaps li { margin: 3pt 0; font-size: 8.5pt; }
  .note { border: 0.5pt solid #cccccc; background: #f7f7f7; padding: 7pt 9pt; margin: 12pt 0 0 0; font-size: 8pt; color: #444444; }

  .sig { margin-top: 14pt; border-top: 0.5pt solid #cccccc; padding-top: 6pt; font-size: 8pt; color: #555555; }
  .sig .who { font-weight: bold; letter-spacing: 0.5pt; }
</style>
</head>
<body>

<div class="cover">
  <div class="brand">{{ project }} · web presence audit</div>
  <h1>{{ result.target.domain }}</h1>
  <div class="sub">Apex {{ result.target.apex }} · scan {{ result.scan_id }} · {{ result.scan_mode }} mode · {{ result.finished_at[:10] }}</div>
  <div class="by">Prepared by {{ author }}</div>
</div>

<h2>Executive summary</h2>
<div class="exec">
  <p class="headline">{{ exec.headline }}</p>
  <p>
    This audit reviewed <b>{{ result.target.domain }}</b> across
    <b>{{ exec.security_findings }}</b> security and <b>{{ exec.marketing_findings }}</b>
    marketing dimensions. Of {{ exec.total_findings }} findings,
    <b>{{ exec.confirmed_count }}</b> are confirmed with evidence,
    <b>{{ exec.needs_review_count }}</b> require manual verification, and
    <b>{{ exec.strengths_count }}</b> are things the site already does well.
  </p>
  {% if exec.top_security_themes or exec.top_marketing_themes %}
  <div class="pills">
    {% for t in exec.top_security_themes %}<span class="pill">{{ t }}</span>{% endfor %}
    {% for t in exec.top_marketing_themes %}<span class="pill">{{ t }}</span>{% endfor %}
  </div>
  {% endif %}
</div>

<table class="meta">
  <tr>
    <td class="k">Risk score</td><td><b>{{ result.risk_score }} / 100</b> ({{ exec.risk_label }})</td>
    <td class="k">Findings</td><td>{{ result.findings|length }}</td>
  </tr>
  <tr>
    <td class="k">Confirmed</td><td>{{ result.counts_by_confidence.confirmed }}</td>
    <td class="k">Likely</td><td>{{ result.counts_by_confidence.likely }}</td>
    <td class="k">Needs review</td><td>{{ result.counts_by_confidence.needs_review }}</td>
  </tr>
  <tr>
    <td class="k">Resolved IPs</td><td colspan="3">{{ result.target.resolved_ips|join(', ') if result.target.resolved_ips else '—' }}</td>
  </tr>
  <tr>
    <td class="k">Scanned</td><td>{{ result.started_at[:19] }} UTC</td>
    <td class="k">Duration</td><td>{{ '%.1f'|format(result.duration_ms / 1000) }}s · {{ result.probes_run }} probes</td>
  </tr>
</table>

<h2>Severity summary</h2>
<table class="sevbar">
  <tr>
    <td class="sev-critical"><div class="n">{{ result.counts_by_severity.critical }}</div>CRITICAL</td>
    <td class="sev-high"><div class="n">{{ result.counts_by_severity.high }}</div>HIGH</td>
    <td class="sev-medium"><div class="n">{{ result.counts_by_severity.medium }}</div>MEDIUM</td>
    <td class="sev-low"><div class="n">{{ result.counts_by_severity.low }}</div>LOW</td>
    <td class="sev-info"><div class="n">{{ result.counts_by_severity.info }}</div>INFO</td>
  </tr>
</table>

{% if quick_wins or planned_items %}
<h2>Priority roadmap</h2>
<table class="road">
  <tr>
    <td>
      <div class="lane-h quick">Quick wins</div>
      {% for a in quick_wins %}
      <div class="item quick">
        <div class="t">{{ a.title }}</div>
        <div class="m">{{ a.severity.value|upper }} · {{ a.category.value }} · {{ a.confidence.label }}</div>
      </div>
      {% else %}<div class="item">No quick wins identified.</div>{% endfor %}
    </td>
    <td>
      <div class="lane-h planned">Planned work</div>
      {% for a in planned_items %}
      <div class="item planned">
        <div class="t">{{ a.title }}</div>
        <div class="m">{{ a.severity.value|upper }} · {{ a.category.value }} · {{ a.confidence.label }}</div>
      </div>
      {% else %}<div class="item">No planned items identified.</div>{% endfor %}
    </td>
  </tr>
</table>
{% endif %}

{% for category in categories %}
{% set items = findings_by_category.get(category, []) %}
{% if items %}
<h2>{{ category|title }} findings ({{ items|length }})</h2>

{% for f in items %}
<div class="finding">
  <div class="finding-head">
    <span class="badge badge-{{ f.severity.value }}">{{ f.severity.value|upper }}</span>
    &nbsp;&nbsp;<span class="title">{{ f.title }}</span>
    &nbsp;&nbsp;<span class="conf conf-{{ f.confidence.value }}">{{ f.confidence.label|upper }}</span>
  </div>
  <div class="finding-body">
    {% if f.reasoning %}<p>{{ f.reasoning }}</p>{% endif %}
    <p class="kv">
      <span class="k">Type</span> {{ f.kind.value|replace('_',' ')|title }}
      {% if f.scope %} &nbsp; <span class="k">Scope</span> {{ f.scope }}{% endif %}
      {% if f.probe_id %} &nbsp; <span class="k">Probe</span> {{ f.probe_id }}{% endif %}
    </p>
    {% if f.evidence.raw %}
    <div class="evidence">{{ f.evidence.raw|evidence_snippet }}</div>
    {% endif %}
    {% if f.remediation %}
    <div class="remediation"><div class="k">Recommended action</div>{{ f.remediation }}</div>
    {% endif %}
  </div>
</div>
{% endfor %}
{% endif %}
{% endfor %}

{% if result.coverage_gaps %}
<h2>What this scan did not test</h2>
<div class="gaps">
  <p class="tiny">Silence is not a clean result. These gaps are explicit so that an untested area is never mistaken for a healthy one.</p>
  <ul>
    {% for g in result.coverage_gaps %}<li>{{ g }}</li>{% endfor %}
  </ul>
</div>
{% endif %}

{% if result.needs_review %}
<h2>Manual review queue ({{ result.needs_review|length }})</h2>
<div class="gaps">
  <p class="tiny">These findings are heuristics or detection gaps. They are NOT confirmed problems and must not be presented as verified issues.</p>
  <ul>
    {% for f in result.needs_review %}<li><b>{{ f.title }}</b> — {{ f.reasoning.split('\n')[0] }}</li>{% endfor %}
  </ul>
</div>
{% endif %}

<div class="note">
  <b>About this report.</b>
  {{ project }} reports <i>observations with evidence</i>. Every finding marked
  CONFIRMED is backed by raw data captured during the scan and can be verified
  independently. Findings marked LIKELY are high-accuracy heuristics. Findings
  marked NEEDS MANUAL REVIEW require human verification before any action is
  taken. This report is not a penetration test, does not certify any system as
  secure, and does not claim the absence of vulnerabilities.
</div>

<div class="sig">
  <div class="who">{{ author }}</div>
  <div>{{ project }} v{{ result.clientlens_version }} · {{ url }} · generated {{ result.finished_at[:19] }} UTC</div>
</div>

</body>
</html>
"""


def _evidence_snippet(raw: str, limit: int = 380) -> str:
    """Truncate evidence and hard-wrap long lines for xhtml2pdf."""
    text = raw[:limit]
    if len(raw) > limit:
        text += "\n… (truncated)"
    wrapped: list[str] = []
    for line in text.splitlines():
        while len(line) > 96:
            wrapped.append(line[:96])
            line = "  " + line[96:]
        wrapped.append(line)
    return "\n".join(wrapped)


def render_pdf(result: ScanResult) -> bytes:
    """Render the PDF as bytes. Raises ImportError if xhtml2pdf is missing."""
    try:
        from xhtml2pdf import pisa
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "PDF export requires the optional 'pdf' extra. "
            "Install with: uv sync --extra pdf\n"
            "Alternatively open the HTML report in a browser and use Print -> Save as PDF."
        ) from exc

    env = Environment(loader=BaseLoader(), autoescape=select_autoescape(["html"]))
    env.filters["evidence_snippet"] = _evidence_snippet
    template = env.from_string(PDF_TEMPLATE)

    findings_by_category: dict[str, list[Finding]] = {}
    for f in result.findings:
        findings_by_category.setdefault(f.category.value, []).append(f)

    exec_summary = build_executive_summary(result)
    action_plan = build_action_plan(result, limit=12)
    quick_wins, planned_items = split_quick_wins(action_plan)

    html = template.render(
        result=result,
        findings_by_category=findings_by_category,
        categories=[Category.SECURITY.value, Category.MARKETING.value, Category.SHARED.value],
        exec=exec_summary,
        quick_wins=quick_wins,
        planned_items=planned_items,
        author=AUTHOR_DISPLAY,
        project=PROJECT,
        url=URL,
    )

    buffer = io.BytesIO()
    pisa_status = pisa.CreatePDF(html, dest=buffer, encoding="utf-8")
    if pisa_status.err:
        raise RuntimeError(f"PDF rendering failed with {pisa_status.err} error(s)")
    return buffer.getvalue()


def write_pdf(result: ScanResult, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(render_pdf(result))
    return p
