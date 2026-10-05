"""HTML report generator — client-facing deliverable.

Self-contained single file: inline CSS, no external requests, opens offline.
Print-ready by design — "Print → Save as PDF" produces a clean deliverable.

Design goals
------------
- Reads like a consulting deliverable, not a tool dump.
- Executive summary first, priority roadmap second, detail last.
- Confidence and evidence visible at a glance.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import BaseLoader, Environment, select_autoescape

from ..branding import AUTHOR_DISPLAY, PROJECT, TAGLINE, URL
from ..core.models import (
    Category,
    Confidence,
    Finding,
    FindingKind,
    ScanResult,
    Severity,
)
from .intelligence import (
    build_action_plan,
    build_executive_summary,
    split_quick_wins,
)

TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ result.target.domain }} — ClientLens audit</title>
<style>
  :root {
    --ink: #0e1520;
    --ink2: #1b2634;
    --muted: #5b6774;
    --faint: #8a95a1;
    --line: #e3e8ee;
    --bg: #f4f6f9;
    --card: #ffffff;
    --brand: #0b3d91;
    --brand2: #1565d8;
    --accent: #06b6d4;
    --critical: #b91c1c;
    --high: #dc2626;
    --medium: #d97706;
    --low: #2563eb;
    --info: #64748b;
    --good: #059669;
    --goodbg: #ecfdf5;
    --warnbg: #fff7ed;
    --reviewbg: #f5f3ff;
    --review: #7c3aed;
  }
  * { box-sizing: border-box; }
  html { -webkit-text-size-adjust: 100%; }
  body {
    margin: 0; background: var(--bg);
    font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: var(--ink); line-height: 1.6; font-size: 14px;
  }
  .wrap { max-width: 1080px; margin: 0 auto; padding: 0 24px 60px; }

  /* ---------- header band ---------- */
  .band {
    background: linear-gradient(135deg, #0b3d91 0%, #1565d8 55%, #06b6d4 100%);
    color: #fff; padding: 40px 0 34px; margin-bottom: 32px;
  }
  .band .wrap { padding-bottom: 0; }
  .brandrow { display: flex; justify-content: space-between; align-items: center; margin-bottom: 26px; }
  .logo { display: flex; align-items: center; gap: 11px; }
  .logomark {
    width: 34px; height: 34px; border-radius: 9px;
    background: rgba(255,255,255,0.16); border: 1px solid rgba(255,255,255,0.35);
    display: flex; align-items: center; justify-content: center;
    font-weight: 800; font-size: 15px; letter-spacing: 0.5px;
  }
  .logoname { font-weight: 750; font-size: 17px; letter-spacing: -0.3px; }
  .logotag { font-size: 11px; opacity: 0.8; }
  .byline { font-size: 11px; text-transform: uppercase; letter-spacing: 1.4px; opacity: 0.85; }
  .byline b { font-weight: 700; }

  h1 { font-size: 34px; letter-spacing: -1px; margin: 0 0 6px; font-weight: 750; }
  .domain-sub { font-size: 14px; opacity: 0.9; }
  .domain-sub code { background: rgba(255,255,255,0.18); padding: 2px 8px; border-radius: 5px; font-size: 12px; }

  .bandstats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-top: 26px; }
  .bstat {
    background: rgba(255,255,255,0.12); border: 1px solid rgba(255,255,255,0.22);
    border-radius: 12px; padding: 13px 15px; backdrop-filter: blur(2px);
  }
  .bstat .k { font-size: 10px; text-transform: uppercase; letter-spacing: 1.1px; opacity: 0.8; }
  .bstat .v { font-size: 22px; font-weight: 750; letter-spacing: -0.5px; margin-top: 2px; }

  /* ---------- executive summary ---------- */
  .card {
    background: var(--card); border: 1px solid var(--line); border-radius: 14px;
    box-shadow: 0 1px 3px rgba(14,21,32,0.05);
  }
  .exec { padding: 26px 28px; margin-bottom: 26px; }
  .exec-top { display: flex; gap: 28px; align-items: center; flex-wrap: wrap; }
  .gauge {
    flex-shrink: 0; width: 150px; text-align: center;
  }
  .gauge .num { font-size: 52px; font-weight: 800; letter-spacing: -2px; line-height: 1; }
  .gauge .lbl { font-size: 11px; text-transform: uppercase; letter-spacing: 1.2px; color: var(--muted); margin-top: 4px; }
  .gauge .risklbl { display: inline-block; margin-top: 9px; padding: 3px 13px; border-radius: 20px; font-size: 11px; font-weight: 700; color: #fff; }
  .risklbl.critical { background: var(--critical); }
  .risklbl.high { background: var(--high); }
  .risklbl.moderate { background: var(--medium); }
  .risklbl.low { background: var(--low); }
  .risklbl.minimal { background: var(--good); }

  .exec-body { flex: 1; min-width: 260px; }
  .exec-body .headline { font-size: 17px; font-weight: 650; letter-spacing: -0.2px; margin: 0 0 12px; }
  .exec-body p { margin: 0 0 10px; color: var(--ink2); }
  .themepills { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 14px; }
  .themepill {
    background: var(--bg); border: 1px solid var(--line); border-radius: 20px;
    padding: 4px 12px; font-size: 11.5px; color: var(--ink2); font-weight: 550;
  }
  .themepill::before { content: "▸ "; color: var(--brand2); }

  .metarow {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px;
    margin-top: 20px; padding-top: 18px; border-top: 1px solid var(--line);
  }
  .meta .k { font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: var(--faint); }
  .meta .v { font-size: 14.5px; font-weight: 650; margin-top: 1px; }

  /* ---------- sections ---------- */
  h2 {
    font-size: 12px; text-transform: uppercase; letter-spacing: 1.3px; color: var(--muted);
    margin: 38px 0 14px; display: flex; align-items: center; gap: 10px;
  }
  h2 .line { flex: 1; height: 1px; background: var(--line); }
  h2 .count { background: var(--ink); color: #fff; border-radius: 20px; padding: 2px 10px; font-size: 10.5px; }

  /* ---------- severity strip ---------- */
  .sevstrip { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 18px 0 26px; }
  .sev {
    border-radius: 12px; padding: 15px 14px; color: #fff; text-align: center;
    position: relative; overflow: hidden;
  }
  .sev .n { font-size: 30px; font-weight: 800; letter-spacing: -1px; line-height: 1; }
  .sev .l { font-size: 10px; text-transform: uppercase; letter-spacing: 1.1px; margin-top: 5px; opacity: 0.92; }
  .sev.critical { background: linear-gradient(160deg, #b91c1c, #7f1d1d); }
  .sev.high { background: linear-gradient(160deg, #dc2626, #991b1b); }
  .sev.medium { background: linear-gradient(160deg, #d97706, #b45309); }
  .sev.low { background: linear-gradient(160deg, #2563eb, #1d4ed8); }
  .sev.info { background: linear-gradient(160deg, #64748b, #475569); }
  .sev.zero { background: #e7ecf1; color: var(--faint); }
  .sev.zero .n { font-weight: 700; }

  /* ---------- roadmap ---------- */
  .roadmap { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 10px; }
  .lane { padding: 18px 20px; }
  .lane h3 { margin: 0 0 4px; font-size: 14px; font-weight: 700; display: flex; align-items: center; gap: 8px; }
  .lane .lane-sub { font-size: 12px; color: var(--muted); margin-bottom: 12px; }
  .lane.quick h3 { color: var(--good); }
  .lane.planned h3 { color: var(--brand2); }
  .action {
    border-left: 3px solid var(--line); padding: 8px 0 8px 14px; margin: 9px 0;
  }
  .action .a-title { font-weight: 620; font-size: 13px; }
  .action .a-meta { font-size: 11px; color: var(--muted); margin-top: 3px; }
  .action .a-fix { font-size: 12px; color: var(--ink2); margin-top: 5px; }
  .action .sevtag { font-size: 9.5px; font-weight: 700; letter-spacing: 0.5px; padding: 1px 7px; border-radius: 4px; color: #fff; }
  .action.quick-act { border-left-color: var(--good); }
  .action.planned-act { border-left-color: var(--brand2); }

  /* ---------- findings ---------- */
  .finding { background: var(--card); border: 1px solid var(--line); border-radius: 12px; margin: 11px 0; overflow: hidden; }
  .finding .head { display: flex; align-items: flex-start; gap: 13px; padding: 14px 18px; }
  .chip {
    flex-shrink: 0; font-size: 9.5px; font-weight: 750; letter-spacing: 0.7px;
    text-transform: uppercase; padding: 3px 9px; border-radius: 5px; color: #fff; margin-top: 2px;
  }
  .chip.critical { background: var(--critical); }
  .chip.high { background: var(--high); }
  .chip.medium { background: var(--medium); }
  .chip.low { background: var(--low); }
  .chip.info { background: var(--info); }
  .finding .title { font-weight: 650; font-size: 14.5px; flex: 1; letter-spacing: -0.1px; }
  .conf {
    flex-shrink: 0; font-size: 10px; font-weight: 650; padding: 3px 9px;
    border-radius: 20px; border: 1px solid var(--line); background: #fff;
  }
  .conf.confirmed { color: var(--good); border-color: #a7f3d0; background: var(--goodbg); }
  .conf.likely { color: var(--medium); border-color: #fde68a; background: var(--warnbg); }
  .conf.needs_review { color: var(--review); border-color: #ddd6fe; background: var(--reviewbg); }

  .finding .body { padding: 0 18px 16px 68px; }
  .finding .reasoning { margin: 0 0 10px; color: var(--ink2); font-size: 13.5px; white-space: pre-wrap; }
  .kv { display: grid; grid-template-columns: 84px 1fr; gap: 4px 14px; font-size: 12px; margin: 8px 0 10px; }
  .kv .k { color: var(--faint); text-transform: uppercase; font-size: 9.5px; letter-spacing: 0.8px; padding-top: 2px; }
  .kv .v { color: var(--ink2); word-break: break-word; }
  .kv .v code { background: var(--bg); padding: 1px 6px; border-radius: 4px; font-size: 11px; }

  .evidence {
    background: #0d1521; color: #c8d6e5; border-radius: 8px; padding: 11px 14px;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px;
    white-space: pre-wrap; word-break: break-word; max-height: 200px; overflow: auto;
  }
  details summary {
    cursor: pointer; font-size: 11.5px; color: var(--brand2); font-weight: 600;
    margin: 6px 0; user-select: none;
  }
  details summary::before { content: "▸ "; }
  details[open] summary::before { content: "▾ "; }
  details summary:hover { text-decoration: underline; }

  .remediation {
    background: var(--goodbg); border-left: 3px solid var(--good);
    padding: 10px 14px; margin-top: 11px; border-radius: 0 8px 8px 0;
  }
  .remediation .k { color: var(--good); font-size: 9.5px; text-transform: uppercase; letter-spacing: 0.8px; font-weight: 750; margin-bottom: 4px; }
  .remediation .v { font-size: 12.5px; color: var(--ink2); white-space: pre-wrap; }
  .remediation .v code { background: #d1fae5; padding: 1px 6px; border-radius: 4px; font-size: 11px; }

  .tags { margin-top: 10px; }
  .tag {
    display: inline-block; background: var(--bg); border: 1px solid var(--line);
    color: var(--muted); border-radius: 20px; padding: 1px 9px; font-size: 10.5px; margin: 2px 4px 2px 0;
  }
  .refs { margin-top: 8px; font-size: 11.5px; }
  .refs a { color: var(--brand2); word-break: break-all; }

  /* ---------- review + gaps ---------- */
  .gaps { background: var(--reviewbg); border: 1px solid #ddd6fe; border-radius: 12px; padding: 18px 22px; }
  .gaps p { margin: 0 0 10px; color: var(--ink2); font-size: 12.5px; }
  .gaps ul { margin: 6px 0 0; padding-left: 20px; }
  .gaps li { margin: 7px 0; color: var(--ink2); font-size: 13px; }

  .note {
    margin-top: 32px; padding: 16px 20px; background: var(--card);
    border: 1px solid var(--line); border-radius: 12px; color: var(--muted); font-size: 12px;
  }

  /* ---------- footer ---------- */
  footer {
    margin-top: 38px; padding-top: 20px; border-top: 1px solid var(--line);
    display: flex; justify-content: space-between; flex-wrap: wrap; gap: 10px;
    color: var(--faint); font-size: 11px;
  }
  footer .sig { text-align: right; }
  footer .sig .who { font-weight: 700; color: var(--muted); letter-spacing: 0.4px; }

  @media (max-width: 700px) {
    .roadmap { grid-template-columns: 1fr; }
    .sevstrip { grid-template-columns: repeat(5, 1fr); }
    h1 { font-size: 26px; }
  }

  @media print {
    body { background: #fff; padding: 0; }
    .band { padding: 24px 0 20px; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .finding { break-inside: avoid; box-shadow: none; }
    .card { box-shadow: none; }
    h2 { break-after: avoid; }
    .evidence { max-height: none; }
    .exec { break-inside: avoid; }
    footer { page-break-inside: avoid; }
  }
</style>
</head>
<body>

<div class="band">
  <div class="wrap">
    <div class="brandrow">
      <div class="logo">
        <div class="logomark">CL</div>
        <div>
          <div class="logoname">{{ project }}</div>
          <div class="logotag">{{ tagline }}</div>
        </div>
      </div>
      <div class="byline">Prepared by <b>{{ author }}</b></div>
    </div>

    <h1>{{ result.target.domain }}</h1>
    <div class="domain-sub">
      Web presence audit · apex <code>{{ result.target.apex }}</code> ·
      scan <code>{{ result.scan_id }}</code> · {{ result.scan_mode }} mode · {{ result.finished_at[:10] }}
    </div>

    <div class="bandstats">
      <div class="bstat"><div class="k">Risk score</div><div class="v">{{ result.risk_score }}<span style="font-size:13px;opacity:0.7">/100</span></div></div>
      <div class="bstat"><div class="k">Findings</div><div class="v">{{ result.findings|length }}</div></div>
      <div class="bstat"><div class="k">Critical / High</div><div class="v">{{ result.counts_by_severity.critical }} / {{ result.counts_by_severity.high }}</div></div>
      <div class="bstat"><div class="k">Confirmed</div><div class="v">{{ result.counts_by_confidence.confirmed }}</div></div>
      <div class="bstat"><div class="k">Duration</div><div class="v">{{ '%.1f'|format(result.duration_ms/1000) }}s</div></div>
    </div>
  </div>
</div>

<div class="wrap">

  <!-- Executive summary -->
  <div class="card exec">
    <div class="exec-top">
      <div class="gauge">
        <div class="num">{{ result.risk_score }}</div>
        <div class="lbl">Business risk</div>
        <div class="risklbl {{ exec.risk_label|lower }}">{{ exec.risk_label }}</div>
      </div>
      <div class="exec-body">
        <p class="headline">{{ exec.headline }}</p>
        <p>
          This audit reviewed <strong>{{ result.target.domain }}</strong> across
          <strong>{{ exec.security_findings }}</strong> security and
          <strong>{{ exec.marketing_findings }}</strong> marketing dimensions.
          Of {{ exec.total_findings }} findings, <strong>{{ exec.confirmed_count }}</strong>
          are confirmed with evidence, <strong>{{ exec.needs_review_count }}</strong>
          require manual verification, and <strong>{{ exec.strengths_count }}</strong>
          are things the site already does well.
        </p>
        {% if exec.top_security_themes or exec.top_marketing_themes %}
        <div class="themepills">
          {% for t in exec.top_security_themes %}<span class="themepill">{{ t }}</span>{% endfor %}
          {% for t in exec.top_marketing_themes %}<span class="themepill">{{ t }}</span>{% endfor %}
        </div>
        {% endif %}
      </div>
    </div>

    <div class="metarow">
      <div class="meta"><div class="k">Target</div><div class="v">{{ result.target.domain }}</div></div>
      <div class="meta"><div class="k">Resolved IPs</div><div class="v">{{ result.target.resolved_ips|join(', ') if result.target.resolved_ips else '—' }}</div></div>
      <div class="meta"><div class="k">Scan mode</div><div class="v">{{ result.scan_mode|title }}</div></div>
      <div class="meta"><div class="k">Probes run</div><div class="v">{{ result.probes_run }} ({{ result.probes_failed }} failed)</div></div>
      <div class="meta"><div class="k">Engine</div><div class="v">{{ project }} v{{ result.clientlens_version }}</div></div>
    </div>
  </div>

  <!-- Severity strip -->
  <div class="sevstrip">
    {% for sev in ['critical','high','medium','low','info'] %}
    <div class="sev {{ sev }}{% if result.counts_by_severity[sev] == 0 %} zero{% endif %}">
      <div class="n">{{ result.counts_by_severity[sev] }}</div>
      <div class="l">{{ sev }}</div>
    </div>
    {% endfor %}
  </div>

  <!-- Priority roadmap -->
  {% if quick_wins or planned_items %}
  <h2><span>Priority roadmap</span><span class="count">{{ quick_wins|length + planned_items|length }}</span><span class="line"></span></h2>
  <div class="roadmap">
    <div class="card lane quick">
      <h3>⚡ Quick wins</h3>
      <div class="lane-sub">Config / header / DNS changes — typically minutes to ship</div>
      {% for a in quick_wins %}
      <div class="action quick-act">
        <div class="a-title">{{ a.title }} <span class="sevtag" style="background:{{ sev_color(a.severity) }}">{{ a.severity.value|upper }}</span></div>
        <div class="a-fix">{{ a.remediation.split('\n')[0] }}</div>
        <div class="a-meta">{{ a.category.value }} · {{ a.confidence.label }}</div>
      </div>
      {% else %}
      <div class="action"><div class="a-meta">No quick wins — nothing at this effort level.</div></div>
      {% endfor %}
    </div>
    <div class="card lane planned">
      <h3>🗓 Planned work</h3>
      <div class="lane-sub">Code or process changes — schedule into a sprint</div>
      {% for a in planned_items %}
      <div class="action planned-act">
        <div class="a-title">{{ a.title }} <span class="sevtag" style="background:{{ sev_color(a.severity) }}">{{ a.severity.value|upper }}</span></div>
        <div class="a-fix">{{ a.remediation.split('\n')[0] }}</div>
        <div class="a-meta">{{ a.category.value }} · {{ a.confidence.label }}</div>
      </div>
      {% else %}
      <div class="action"><div class="a-meta">No planned items identified.</div></div>
      {% endfor %}
    </div>
  </div>
  {% endif %}

  <!-- Findings by category -->
  {% for category in categories %}
  {% set items = findings_by_category.get(category, []) %}
  {% if items %}
  <h2><span>{{ category|title }} findings</span><span class="count">{{ items|length }}</span><span class="line"></span></h2>

  {% for f in items %}
  <div class="finding">
    <div class="head">
      <div class="chip {{ f.severity.value }}">{{ f.severity.value }}</div>
      <div class="title">{{ f.title }}</div>
      <div class="conf {{ f.confidence.value }}">{{ f.confidence.label }}</div>
    </div>
    <div class="body">
      {% if f.reasoning %}<p class="reasoning">{{ f.reasoning }}</p>{% endif %}
      <div class="kv">
        <div class="k">Type</div><div class="v">{{ f.kind.value|replace('_',' ')|title }}</div>
        {% if f.scope %}<div class="k">Scope</div><div class="v">{{ f.scope }}</div>{% endif %}
        {% if f.probe_id %}<div class="k">Probe</div><div class="v"><code>{{ f.probe_id }}</code></div>{% endif %}
      </div>
      {% if f.evidence.raw %}
      <details>
        <summary>Show evidence ({{ f.evidence.type.value }}{% if f.evidence.summary %} · {{ f.evidence.summary }}{% endif %})</summary>
        <div class="evidence">{{ f.evidence.raw }}</div>
        {% if f.evidence.source %}<div style="color:var(--faint);font-size:10.5px;margin-top:4px">source: {{ f.evidence.source }}</div>{% endif %}
      </details>
      {% endif %}
      {% if f.remediation %}
      <div class="remediation"><div class="k">Recommended action</div><div class="v">{{ f.remediation }}</div></div>
      {% endif %}
      {% if f.references %}
      <div class="refs">Reference: {% for r in f.references %}<a href="{{ r }}">{{ r }}</a>{% if not loop.last %}, {% endif %}{% endfor %}</div>
      {% endif %}
      {% if f.tags %}
      <div class="tags">{% for t in f.tags %}<span class="tag">{{ t }}</span>{% endfor %}</div>
      {% endif %}
    </div>
  </div>
  {% endfor %}
  {% endif %}
  {% endfor %}

  <!-- Coverage gaps -->
  {% if result.coverage_gaps %}
  <h2><span>What this scan did <em>not</em> test</span><span class="count">{{ result.coverage_gaps|length }}</span><span class="line"></span></h2>
  <div class="gaps">
    <p>Silence is not a clean result. These gaps are explicit so that an untested area is never mistaken for a healthy one.</p>
    <ul>
      {% for g in result.coverage_gaps %}<li>{{ g }}</li>{% endfor %}
    </ul>
  </div>
  {% endif %}

  <!-- Manual review queue -->
  {% if result.needs_review %}
  <h2><span>Manual review queue</span><span class="count">{{ result.needs_review|length }}</span><span class="line"></span></h2>
  <div class="gaps">
    <p>These findings are heuristics or detection gaps. They are <strong>not</strong> confirmed problems and must not be presented to a client as verified issues.</p>
    <ul>
      {% for f in result.needs_review %}<li><strong>{{ f.title }}</strong> — {{ f.reasoning.split('\n')[0] }}</li>{% endfor %}
    </ul>
  </div>
  {% endif %}

  <!-- About -->
  <div class="note">
    <strong>About this report.</strong>
    {{ project }} reports <em>observations with evidence</em>. Every finding marked
    <strong>Confirmed</strong> is backed by raw data captured during the scan and can be
    verified independently. Findings marked <strong>Likely</strong> are high-accuracy
    heuristics. Findings marked <strong>Needs manual review</strong> require human
    verification before any action is taken.
    <br><br>
    This report is not a penetration test, does not certify any system as secure, and does
    not claim the absence of vulnerabilities. Scanning was performed against the domains
    listed with explicit authorisation.
  </div>

  <footer>
    <div>
      <div style="font-weight:700;color:var(--muted);letter-spacing:0.4px">{{ project }} v{{ result.clientlens_version }}</div>
      <div>Generated {{ result.finished_at[:19] }} UTC · scan {{ result.scan_id }}</div>
    </div>
    <div class="sig">
      <div class="who">{{ author }}</div>
      <div>{{ url }}</div>
    </div>
  </footer>

</div>
</body>
</html>
"""


def render_html(result: ScanResult) -> str:
    env = Environment(loader=BaseLoader(), autoescape=select_autoescape(["html"]))
    template = env.from_string(TEMPLATE)

    findings_by_category: dict[str, list[Finding]] = {}
    for f in result.findings:
        findings_by_category.setdefault(f.category.value, []).append(f)

    exec_summary = build_executive_summary(result)
    action_plan = build_action_plan(result, limit=12)
    quick_wins, planned_items = split_quick_wins(action_plan)

    def sev_color(sev: Severity) -> str:
        return {
            Severity.CRITICAL: "#b91c1c",
            Severity.HIGH: "#dc2626",
            Severity.MEDIUM: "#d97706",
            Severity.LOW: "#2563eb",
            Severity.INFO: "#64748b",
        }[sev]

    return template.render(
        result=result,
        findings_by_category=findings_by_category,
        categories=[Category.SECURITY.value, Category.MARKETING.value, Category.SHARED.value],
        exec=exec_summary,
        action_plan=action_plan,
        quick_wins=quick_wins,
        planned_items=planned_items,
        sev_color=sev_color,
        author=AUTHOR_DISPLAY,
        project=PROJECT,
        tagline=TAGLINE,
        url=URL,
        Severity=Severity,
        Confidence=Confidence,
        FindingKind=FindingKind,
    )


def write_html(result: ScanResult, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(render_html(result), encoding="utf-8")
    return p
