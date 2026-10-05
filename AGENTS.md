# AGENTS.md — ClientLens

Guidance for anyone (human or agent) working in this repository.

## What this is

ClientLens is a **local, free, deterministic client audit engine** — security
and digital-marketing reconnaissance in one evidence-backed report. Author:
**Abdullah Al Noman** (see `src/clientlens/branding.py` — single source of
truth for author/project strings used in reports).

Hard product rules:

- **Free / local / 0-cost** — no paid APIs, no subscriptions, no telemetry.
- **Authorisation is mandatory** — scans refuse to run without
  `--i-am-authorized`. Never weaken this.
- **Evidence-backed claims** — every finding carries raw evidence and an
  explicit confidence level (`confirmed` / `likely` / `needs_review`). A
  heuristic must never be presented as a confirmed fact.
- **Silence ≠ clean** — the report must always state what was NOT tested
  (`coverage_gaps`).

## Commands

```bash
uv sync --all-extras          # install (Python 3.12+, uv)
uv run pytest -q              # tests (83+; must stay green)
uv run ruff check src tests   # lint
uv run ruff format src tests  # format
uv run clientlens probes      # list registered probes
uv run clientlens scan example.com --i-am-authorized
```

Run lint + tests before claiming any work is done.

## Layout

```
src/clientlens/
├── branding.py          AUTHOR / PROJECT constants — import, don't hardcode
├── cli.py               Typer CLI (scan, probes, history, diff, report, dashboard, version)
├── core/
│   ├── models.py        Finding, Evidence, Confidence, Severity, ScanResult
│   ├── registry.py      @register_probe plugin system
│   ├── engine.py        orchestrator — auth, budget, preset selection, phases
│   ├── config.py        ScanConfig — safety rails
│   └── target.py        target normalisation
├── probes/
│   ├── shared/          http_client, dns_client, html, fingerprints
│   ├── security/        18 probes
│   └── marketing/       14 probes
├── report/
│   ├── console.py       Rich terminal renderer
│   ├── html_export.py   print-ready HTML
│   ├── pdf_export.py    xhtml2pdf
│   ├── json_export.py   machine-readable
│   ├── csv_export.py    spreadsheet export
│   └── intelligence.py  executive summary + priority roadmap
├── storage/db.py        SQLite history + diff
└── web/app.py           FastAPI dashboard (read-only)
```

## Adding a probe

One file, one decorator. Nothing else changes except the import in
`probes/__init__.py`.

```python
@register_probe(
    id="security.example.thing",
    category=Category.SECURITY,
    mode=ProbeMode.PASSIVE,       # or ACTIVE (opt-in via --active)
    phase=ProbePhase.ANALYSE,
    requires=("http_response",),  # facts the engine guarantees
    title="...",
    description="...",
    tags=("...",),
)
async def check_thing(ctx: ProbeContext) -> list[Finding]:
    resp = ctx.require("http_response")
    ...
```

Rules for findings:

- `FindingKind.VULNERABILITY_VECTOR` can never be `CONFIRMED` (the model
  downgrades it to `LIKELY` automatically — don't fight it).
- Attach real evidence (`Evidence.http_headers`, `Evidence.html_node`,
  `Evidence.text`, ...) with a `source`.
- Include `reasoning` (why it matters) and `remediation` (what to do).
- Strengths are `FindingKind.STRENGTH` with `Severity.INFO`.

## Presets

`ScanConfig.preset` / `--preset` controls probe depth
(`engine.ScanEngine._select_specs`):

| Preset | Probes | Excludes |
|---|---|---|
| `quick` | ~15 | transport, DNSSEC, www, CSP deep, accessibility, forms, third-party, PWA, performance, tech_stack, schema, subdomains, cors, email_auth, exposure |
| `standard` | ~23 | deep-only: transport, DNSSEC, www, CSP deep, accessibility, forms, third-party, PWA |
| `deep` | 33 | nothing (still respects `--active` for active-mode probes) |

Explicit `--include` overrides the preset entirely.

## Accuracy contract (do not regress)

- `Finding.confidence` downgrade for `VULNERABILITY_VECTOR` lives in
  `models.py` — keep it.
- `ScanResult.risk_score` weights by confidence — a `needs_review` critical
  must never outrank a `confirmed` one.
- Coverage gaps are recorded in `engine._record_coverage_gaps` — extend, never
  remove.
- Tests assert *rules*, not re-implementations. Fixtures go in `tests/`.

## Style

- Ruff config in `pyproject.toml` (line length 100, py312).
- No comments unless they explain a non-obvious rule or safety property.
- Keep the author name exactly `ABDULLAH AL NOMAN` in user-facing output
  (imports from `branding.py`).
