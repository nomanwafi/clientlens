# ClientLens — Usage Guide

Complete reference for every command, option, probe and output format.

- [1. Install](#1-install)
- [2. Your first scan](#2-your-first-scan)
- [3. CLI command reference](#3-cli-command-reference)
- [4. All 38 probes](#4-all-38-probes)
- [5. Output formats](#5-output-formats)
- [6. The web dashboard](#6-the-web-dashboard)
- [7. Scan history & diffing](#7-scan-history--diffing)
- [8. Reading a report (confidence model)](#8-reading-a-report-confidence-model)
- [9. Real-world recipes](#9-real-world-recipes)
- [10. Tuning & safety](#10-tuning--safety)
- [11. Fingerprint databases](#11-fingerprint-databases)
- [12. Adding your own probe](#12-adding-your-own-probe)
- [13. Project layout](#13-project-layout)
- [14. API reference (JSON)](#14-api-reference-json)
- [15. Troubleshooting](#15-troubleshooting)

---

## 1. Install

### Requirements

- **Python 3.12+**
- **[uv](https://docs.astral.sh/uv/)** (recommended) or `pip`

### With uv (recommended)

```bash
git clone https://github.com/YOURNAME/clientlens.git
cd clientlens

# core only
uv sync

# core + PDF export + web dashboard + test tools
uv sync --all-extras
```

### With pip

```bash
pip install -e ".[pdf,web,dev]"
```

### Optional extras

| Extra | Adds | Install |
|---|---|---|
| *(none)* | Full CLI + console/JSON/HTML reports | `uv sync` |
| `pdf` | PDF report export (xhtml2pdf) | `uv sync --extra pdf` |
| `web` | FastAPI scan-history dashboard | `uv sync --extra web` |
| `dev` | pytest, respx, coverage | `uv sync --extra dev` |
| `all` | everything | `uv sync --all-extras` |

### Verify the install

```bash
uv run clientlens version
uv run clientlens probes
```

`clientlens probes` should list **38 probes**.

> **Note on `uv run`:** if you `pip install -e .` you can drop the `uv run`
> prefix and call `clientlens` directly. All examples below use `uv run`.

---

## 2. Your first scan

```bash
uv run clientlens scan example.com --i-am-authorized
```

That is the minimum. It will:

1. Fetch the homepage (1–5 HTTP requests total)
2. Capture the TLS certificate and public DNS records
3. Run the **standard preset** (security + marketing)
4. Print a report to the terminal

### Add report files

```bash
uv run clientlens scan example.com --i-am-authorized \
  --html report.html \
  --pdf  report.pdf \
  -o     report.json
```

| Flag | File | Use |
|---|---|---|
| `--html report.html` | `report.html` | Open in a browser. Print-ready — *Print → Save as PDF* gives a clean client deliverable. |
| `--pdf report.pdf` | `report.pdf` | Direct PDF (needs `--extra pdf`). |
| `-o report.json` | `report.json` | Machine-readable. Reuse with `clientlens report` later. |

### Go deeper with active probes

```bash
uv run clientlens scan example.com --i-am-authorized --active
```

Adds **10 active probes** — sensitive-path enumeration, open-redirect parameter
tests, CORS origin reflection, HTTP method enumeration, www-canonicalisation,
robots/security.txt inspection, sitemap health, broken-link spot-check.

> ⚠️ Active probes make additional requests to the target. Only use them on
> systems you are authorised to test.

### The authorisation flag

`--i-am-authorized` is **mandatory**. Without it:

```
╭────────────────────────── Refused ──────────────────────────╮
│ Authorisation required.                                     │
│                                                             │
│ Only scan domains you own or have written permission to     │
│ test. Pass --i-am-authorized to confirm.                    │
╰─────────────────────────────────────────────────────────────╯
```

Exit code `2`. There is no way around this — not via config, not via the web UI.

---

## 3. CLI command reference

```
clientlens [OPTIONS] COMMAND [ARGS]...
```

| Command | Purpose |
|---|---|
| `scan` | Run a full audit against one target |
| `probes` | List every available probe |
| `history` | List saved scans |
| `diff` | Compare two saved scans of the same domain |
| `report` | Regenerate reports from a saved JSON scan |
| `dashboard` | Serve the local scan-history dashboard |
| `version` | Print the version |

Shell completion:

```bash
clientlens --install-completion
```

---

### `clientlens scan`

```
clientlens scan <target> [OPTIONS]
```

**Argument**

| Name | Type | Description |
|---|---|---|
| `target` | str | Domain or URL. `example.com`, `www.example.com`, `https://shop.example.co.uk/path`, `example.com:8443` all work. |

**Options**

| Flag | Default | Description |
|---|---|---|
| `--i-am-authorized` | — | **Required.** Confirms you are authorised to scan this target. |
| `--active` | off | Enable active probes (path enumeration, open-redirect tests, CORS, robots/sitemap, broken links). |
| `--preset <name>` | `standard` | Probe set: `quick` (~16), `standard` (~27), `deep` (all 38). Explicit `--include` overrides the preset. |
| `-o, --output <path>` | — | Write the JSON report to this path. |
| `--html <path>` | — | Write a print-ready HTML report. |
| `--pdf <path>` | — | Write a PDF report (requires `--extra pdf`). |
| `--csv <path>` | — | Write a CSV export of findings (spreadsheet/tracker-friendly). |
| `-e, --show-evidence` | off | Include raw evidence snippets in the console output. |
| `-i, --include <prefix>` | — | Only run probes whose id starts with this prefix. Repeatable. Overrides `--preset`. |
| `-x, --exclude <prefix>` | — | Skip probes whose id starts with this prefix. Repeatable. |
| `--timeout <float>` | `12.0` | Per-request timeout in seconds. |
| `--rate <float>` | `5.0` | Maximum requests per second against the target. |
| `--max-requests <int>` | `120` | Hard cap on total requests for the whole scan. |
| `--crtsh` / `--no-crtsh` | `--crtsh` | Use crt.sh for subdomain discovery (free, no key). |
| `--allow-private` | off | Allow scanning private/loopback addresses (RFC1918, 127.0.0.1). |
| `--save` / `--no-save` | `--save` | Write the scan to the local history database. |
| `--help` | — | Show help and exit. |

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | Scan completed, no critical or high findings |
| `1` | Scan error |
| `2` | Refused (missing `--i-am-authorized`) or invalid target |
| `3` | Scan completed, **critical or high findings present** |
| `130` | Interrupted (Ctrl+C) |

> Exit code `3` is useful in CI: `clientlens scan $TARGET --i-am-authorized \|\| echo "needs attention"`.

**Examples**

```bash
# minimal
uv run clientlens scan example.com --i-am-authorized

# full client deliverable
uv run clientlens scan example.com --i-am-authorized \
  --html reports/example.html --pdf reports/example.pdf -o reports/example.json

# security only, show evidence inline
uv run clientlens scan example.com --i-am-authorized -i security -e

# marketing only
uv run clientlens scan example.com --i-am-authorized -i marketing

# skip the slow subdomain lookup
uv run clientlens scan example.com --i-am-authorized --no-crtsh

# be gentle with a fragile target
uv run clientlens scan example.com --i-am-authorized --rate 1 --max-requests 30

# scan a local staging box
uv run clientlens scan 10.0.0.5 --i-am-authorized --allow-private

# full active pass
uv run clientlens scan example.com --i-am-authorized --active --html r.html -o r.json
```

---

### `clientlens probes`

```
clientlens probes
```

Lists all registered probes with their phase, mode, category and title. No
options.

```bash
uv run clientlens probes
```

Output includes a reminder that active probes only run with `--active`.

---

### `clientlens history`

```
clientlens history [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `-d, --domain <str>` | — | Filter by domain. |
| `-n, --limit <int>` | `25` | Maximum rows to show. |

```bash
uv run clientlens history
uv run clientlens history --domain example.com --limit 10
```

```
  example.com     2026-10-04 10:15   47   40 findings  0c 1h  4cf8bad89c7b155c
```

Columns: domain · scan time · risk score · finding count · critical/high · scan id.

---

### `clientlens diff`

```
clientlens diff <before> <after> [--json]
```

Compares two saved scans of the same domain by finding fingerprint.

| Flag | Description |
|---|---|
| `--json` | Emit JSON instead of a human-readable table. |

```bash
uv run clientlens history                    # find the two scan ids
uv run clientlens diff 4cf8bad89c7b155c 8a1c22f0e4b93d71
uv run clientlens diff <before> <after> --json > delta.json
```

Reports: risk delta, newly appeared findings, resolved findings, severity
changes.

---

### `clientlens report`

```
clientlens report <json_path> [--html <path>] [--pdf <path>]
```

Regenerates reports from a JSON scan file written earlier with `-o`. Useful for
re-rendering a client deliverable without re-scanning.

```bash
uv run clientlens report reports/example.json --html reports/example.html --pdf reports/example.pdf
```

---

### `clientlens dashboard`

```
clientlens dashboard [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--host <str>` | `127.0.0.1` | Bind address. |
| `--port <int>` | `8765` | Port to listen on. |
| `--reload` | off | Auto-reload on code change (development). |

```bash
uv run clientlens dashboard
uv run clientlens dashboard --port 9000 --host 0.0.0.0
```

Read-only by design: it renders saved scans and diffs them. **Scanning is not
available from the web UI** so the authorisation acknowledgement cannot be
bypassed by a form.

---

### `clientlens version`

```bash
uv run clientlens version
# clientlens 0.1.0
```

---

## 4. All 38 probes

### How probes are organised

Each probe declares:

- **phase** — `capture` → `analyse` → `active` (execution order)
- **mode** — `passive` (1–5 requests) or `active` (extra requests, opt-in)
- **requires** — facts it needs (the engine guarantees these or skips it)

The engine runs `shared.capture` first (homepage + DNS + TLS), then every
analyse probe against that captured material — so passive probes never
re-fetch. Active probes run last and only with `--active`.

Presets choose the depth of the pass:

| Preset | Probes | Use when |
|---|---|---|
| `quick` | ~16 | First look at a lead or prospect — fast, still evidence-backed |
| `standard` (default) | ~27 | The everyday client audit |
| `deep` | 38 | Full coverage including transport, DNSSEC, CSP parsing, accessibility, forms, third-party surface, content depth, images, API surface |

`clientlens probes --preset deep` lists exactly which probes each preset runs.

### Security probes (20)

| Probe ID | Mode | What it reports |
|---|---|---|
| `security.headers` | passive | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP. Also flags ineffective values (`default-src *`, `unsafe-inline`, `max-age=0`) and server-banner disclosure. |
| `security.headers.csp_deep` | passive | Parses the CSP directive set: `unsafe-inline` / `unsafe-eval`, wildcard sources, missing hardening directives (`object-src`, `base-uri`, `frame-ancestors`, `form-action`), Report-Only mode (watching but not protecting). |
| `security.cookies` | passive | `Secure` / `HttpOnly` / `SameSite` flags per cookie; flags `SameSite=None` without `Secure`; identifies tracking cookies. |
| `security.tls` | passive | Negotiated protocol, certificate issuer, validity window, days to expiry, SAN coverage of the scanned hostname, chain length. |
| `security.dns` | passive | Full record inventory (A/AAAA/MX/NS/TXT/CAA/SOA); missing CAA; MX absent but SPF present; single-NS delegation. |
| `security.dns.dnssec` | passive | DNSKEY + DS presence. Distinguishes fully signed zones, broken chain of trust (signed but parent has no DS), and unsigned zones. |
| `security.dns.www_redirect` | **active** | Whether the www / bare variant resolves and one 301s to the other. Duplicate content is flagged; clean canonicalisation is a strength. |
| `security.email_auth` | passive | SPF (missing, multiple records, `+all`), DMARC (missing, `p=none`, `pct<100`, no `rua`), DKIM (real keys, **wildcard revoked-key detection**, revoked selectors), MTA-STS. |
| `security.redirects.chain` | passive | Redirect hop list; plaintext `http://` hop; chains ≥3 hops; cross-host destination. |
| `security.mixed_content` | passive | Active mixed content (scripts, iframes, stylesheets, forms) vs passive (images, media). |
| `security.transport.methods` | **active** | OPTIONS request; reports advertised methods and flags dangerous verbs (PUT, DELETE, TRACE, CONNECT, PATCH, TRACK). |
| `security.transport.https_enforcement` | passive | Whether `http://` redirects to `https://` (good), serves content (bad), or fails. |
| `security.transport.http_versions` | passive | Negotiated HTTP version (h2 vs h1), HTTP/3 availability via `Alt-Svc`. |
| `security.subdomains` | passive | Certificate Transparency names via crt.sh; flags staging/dev/admin/vpn-looking hosts; wildcard certificates. |
| `security.subdomain_takeover` | passive | CNAME sweep of 14 common names for dangling targets in takeover-prone services (GitHub Pages, Heroku, S3, CloudFront, Azure, Netlify, Vercel, Shopify, ...). Reported as a **vector** — confirming one is out of scope. |
| `security.exposure.paths` | **active** | 12 high-signal paths: `/.git/HEAD`, `/.git/config`, `/.env`, `/.svn/entries`, `/.DS_Store`, `/backup.zip`, `/dump.sql`, `/wp-config.php.bak`, `/phpinfo.php`, `/server-status`, `/actuator/health`, `/elmah.axd`. Reports only what actually answers, with content-shape validation. |
| `security.exposure.disclosure` | **active** | `robots.txt`, `security.txt` (RFC 9116, Expires field), `sitemap.xml`, `humans.txt`. |
| `security.exposure.api` | **active** | 12 API discovery paths (swagger.json, openapi.json, api-docs, swagger-ui, graphql, graphiql, openid-configuration, ...). Response is shape-validated so an SPA's catch-all HTML shell is not mistaken for a live spec. |
| `security.cors` | **active** | Sends 3 probe `Origin` headers and reports reflected `Access-Control-Allow-Origin`, especially with `Allow-Credentials: true`. Reported as a **vector**, never a confirmed vuln. |
| `security.redirects.open_vector` | **active** | Tests 8 redirect-parameter names plus URL-valued params. Reports external-host reflection as a **vector**. |

### Marketing probes (17)

| Probe ID | Mode | What it reports |
|---|---|---|
| `marketing.seo.meta` | passive | `<title>` presence and length, meta description length, canonical, `robots` meta (`noindex` is HIGH), hreflang inventory, h1 count, title/h1 token alignment. |
| `marketing.social` | passive | Open Graph completeness (`og:title`, `og:description`, `og:image`, `og:url`, `og:type`), Twitter Card presence, `og:image` over http://, og/title vs twitter/title mismatch. |
| `marketing.schema` | passive | JSON-LD block count and parse validity, schema.org type inventory, rich-result-relevant types, Organization/LocalBusiness entity presence, microdata/RDFa fallback detection. |
| `marketing.tracking` | passive | 43-vendor inventory: analytics, advertising pixels, session replay, product analytics, chat, CRM, A/B testing, email. Flags deprecated tools (UA, Google Optimize) and privacy-friendly ones (Plausible, Matomo, Fathom). |
| `marketing.consent` | passive | 20 consent-platform signatures (OneTrust, Cookiebot, Usercentrics, CookieYes, Termly, Iubenda, Osano, TrustArc, Didomi, Complianz, CookieFirst, Borlabs, Quantcast, Google Consent Mode, HubSpot, Squarespace, Shopify, WordPress GDPR, Elementor, Wix). Cross-checks advertising pixels vs consent presence. Privacy policy link detection. |
| `marketing.tech_stack` | passive | 119 rules across CMS, builder, framework, language, server, CDN, WAF, hosting, e-commerce, JS libraries, marketing tools. |
| `marketing.performance` | passive | TTFB (lab), HTML payload size, subresource count, compression, Cache-Control presence. Explicitly states that field Core Web Vitals are **not** collected. |
| `marketing.links` | passive | Internal/external counts and ratio, `nofollow`/`sponsored`/`ugc` usage, suspicious outbound links (IP-literal hosts, odd ports, URL shorteners). |
| `marketing.links.broken` | **active** | Samples up to 25 internal links and reports 4xx/5xx responses. |
| `marketing.sitemap` | **active** | robots.txt presence and groups, missing `Sitemap:` directive, Disallow rules covering CSS/JS (rendering hazard), sitemap presence/emptiness, `lastmod` coverage. |
| `marketing.accessibility` | passive | `<html lang>`, viewport meta (presence and zoom suppression), image `alt` coverage with exact counts. |
| `marketing.forms` | passive | Form count; sensitive fields (password/email) submitted via GET; cross-origin form actions; inputs without labels (conversion + accessibility). |
| `marketing.third_party` | passive | Every external origin the homepage contacts, with resource types. Script-bearing origins are flagged as supply-chain exposure; iframe origins observed. |
| `marketing.pwa` | passive | Web app manifest link, service worker registration hint, favicon / apple-touch-icon coverage, theme colour. |
| `marketing.content_depth` | passive | Visible word count, heading outline (h1-h6 counts + skips), text-to-HTML ratio. Thin content (<300 words) and healthy depth (600+) reported as findings. |
| `marketing.images` | passive | Per-`<img>` declared width/height (the CLS signal), lazy-loading usage, WebP/AVIF vs legacy format mix. |
| `marketing.soft_404` | **active** | One request to a random nonexistent path. A real 404 is a strength; a 200 (soft 404) or a redirect is a crawl/indexing problem. |

### Shared probe (1)

| Probe ID | Mode | What it does |
|---|---|---|
| `shared.capture` | passive | The single place that touches the network for passive scans. Fetches the homepage, resolves DNS, performs the TLS handshake. Publishes `http_response`, `html`, `dns`, `tls` facts for all downstream probes. |

---

## 5. Output formats

### Terminal (Rich)

The default. Colour-coded severity, confidence markers, and a clearly
separated **"Needs manual review"** section plus **"What this scan did NOT
test"**.

| Marker | Meaning |
|---|---|
| `●` | Confirmed |
| `◐` | Likely |
| `○` | Needs manual review |
| `⚠` | Misconfiguration |
| `!` | Exposure |
| `?` | Vulnerability vector |
| `✓` | Strength |
| `·` | Observation |
| `~` | Coverage gap |

Add `-e` / `--show-evidence` to inline the raw evidence.

### JSON (`-o report.json`)

```json
{
  "schema": {
    "name": "clientlens.scan",
    "version": "1.0",
    "confidence_levels": ["confirmed", "likely", "needs_review"]
  },
  "scan_id": "4cf8bad89c7b155c",
  "target": { "domain": "example.com", "apex": "example.com", ... },
  "started_at": "2026-10-04T10:15:22+00:00",
  "duration_ms": 2410,
  "scan_mode": "passive",
  "risk_score": 47,
  "counts": {
    "severity":  { "critical": 0, "high": 1, "medium": 7, "low": 10, "info": 22 },
    "confidence":{ "confirmed": 33, "likely": 4, "needs_review": 3 },
    "category":  { "security": 20, "marketing": 20, "shared": 0 },
    "findings": 40, "probes_run": 17, "probes_failed": 0
  },
  "findings": [
    {
      "id": "security.headers.hsts_missing",
      "title": "strict-transport-security header not present",
      "category": "security",
      "kind": "misconfiguration",
      "severity": "medium",
      "confidence": "confirmed",
      "evidence": {
        "type": "http_headers",
        "raw": "content-type: text/html\nserver: nginx\n...",
        "summary": "12 headers",
        "source": "GET https://example.com/",
        "captured_at": "2026-10-04T10:15:22+00:00"
      },
      "reasoning": "Without HSTS a first visit over http:// can be SSL-stripped...",
      "scope": "Response headers of https://example.com/",
      "remediation": "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`...",
      "references": [],
      "tags": ["headers", "missing-header"],
      "probe_id": "security.headers",
      "target": "example.com",
      "fingerprint": "a3f19c2b0e44"
    }
  ],
  "probe_results": [ ... ],
  "notes": ["HTTP request budget used: 1"],
  "coverage_gaps": [ "Active interaction tests were NOT run.", ... ]
}
```

**Field reference**

| Field | Description |
|---|---|
| `id` | Stable dotted identifier — use for diffing and suppression |
| `kind` | `observation` · `misconfiguration` · `exposure` · `vulnerability_vector` · `strength` · `gap` |
| `severity` | `info` · `low` · `medium` · `high` · `critical` (business impact) |
| `confidence` | `confirmed` · `likely` · `needs_review` |
| `evidence.raw` | The raw proof. Open it and verify independently. |
| `evidence.source` | Where the evidence came from (URL, DNS name) |
| `fingerprint` | 12-char hash used by `clientlens diff` |
| `coverage_gaps` | Explicit list of what was **not** tested |

### HTML (`--html report.html`)

Single self-contained file. Inline CSS, no external requests, opens offline.
Includes:

- Risk score bar and severity summary
- Every finding with confidence badge, reasoning, scope, evidence (collapsible),
  remediation and tags
- **"What this scan did not test"** section
- **"Manual review queue"** listing every `needs_review` finding
- Print stylesheet — *Print → Save as PDF* produces a clean client deliverable

### PDF (`--pdf report.pdf`)

A 8–12 page A4 document designed for xhtml2pdf's CSS subset: severity summary,
risk score, every finding with evidence and remediation, coverage gaps, manual
review queue, and a disclaimer block.

If the `pdf` extra is not installed the CLI says so and tells you to print the
HTML instead — it does not fail the scan.

---

## 6. The web dashboard

```bash
uv sync --extra web
uv run clientlens dashboard
# → http://127.0.0.1:8765
```

### Routes

| Route | Description |
|---|---|
| `GET /` | Scan history table with domain filter chips |
| `GET /scans/{id}` | Full HTML report for one scan |
| `GET /diff/{before}/{after}` | Side-by-side comparison page |
| `GET /api/scans` | JSON list (`?domain=&limit=`) |
| `GET /api/scans/{id}` | Full JSON payload |
| `GET /api/scans/{id}/findings` | Findings (`?confidence=`, `?severity=`) |
| `GET /api/diff/{before}/{after}` | Structured diff |
| `GET /api/domains` | Distinct domains in history |

### Examples

```bash
# all confirmed findings from a scan
curl 'http://127.0.0.1:8765/api/scans/4cf8bad89c7b155c/findings?confidence=confirmed'

# all critical findings
curl 'http://127.0.0.1:8765/api/scans/4cf8bad89c7b155c/findings?severity=critical'

# diff as JSON
curl 'http://127.0.0.1:8765/api/diff/<before>/<after>' | jq .added
```

> **Security note:** the dashboard binds to `127.0.0.1` by default. Only use
> `--host 0.0.0.0` on a network you trust — there is no authentication layer.

---

## 7. Scan history & diffing

Every scan is saved to a local SQLite database:

| OS | Default path |
|---|---|
| macOS / Linux | `~/.local/share/clientlens/scans.db` |
| Override | `CLIENTLENS_DB=/path/to/scans.db` |

```bash
# use a per-client database
CLIENTLENS_DB=~/.clientlens/acme.db uv run clientlens scan acme.com --i-am-authorized

# see what's saved
uv run clientlens history

# compare before/after a fix
uv run clientlens history -d acme.com
uv run clientlens diff <old-scan-id> <new-scan-id>
```

The diff reports:
- **Risk delta** (`+12`, `-5`)
- **New findings** (present in the later scan only)
- **Resolved findings** (present in the earlier scan only)
- **Severity changes** (`low → high`)

---

## 8. Reading a report (confidence model)

This is the part that matters most.

### Three confidence levels

| Badge | Meaning | What you may do with it |
|---|---|---|
| `● Confirmed` | Directly observed — DNS answer, header value, DOM node, TLS field. Raw evidence attached. | Report to the client as fact. |
| `◐ Likely` | High-accuracy heuristic — tech fingerprint, WAF detection, CT-log subdomains. | Report as "we detected X", note it is fingerprint-based. |
| `○ Needs manual review` | Heuristic or detection gap — consent compliance, vulnerability vectors, negative results. | **Do not report as a problem.** Verify first. |

### Hard rules the tool enforces

1. **Every finding has evidence.** Open `evidence.raw` and you can verify it
   yourself without trusting ClientLens.
2. **A `vulnerability_vector` can never be `confirmed`.** The data model
   downgrades it at construction time.
3. **Absence ≠ absence of the opposite.** "No trackers detected" means *not
   detected*, and says so explicitly.
4. **Coverage gaps are always listed.** Silence is never presented as a clean
   result.

### Severity is business impact, not CVSS

| Severity | Point value | Example |
|---|---|---|
| `critical` | 20 | Expired TLS certificate, exposed `.env` |
| `high` | 10 | No SPF/DMARC, active mixed content, `noindex` on a money page |
| `medium` | 4 | Missing HSTS/CSP, DMARC `p=none`, broken links |
| `low` | 1 | Missing `X-Content-Type-Options`, long redirect chain |
| `info` | 0 | Observations and strengths |

### Risk score

```
score = Σ (severity_points × confidence_weight)   capped at 100

confidence_weight:  confirmed 1.0  ·  likely 0.55  ·  needs_review 0.15
```

| Scenario | Score |
|---|---|
| 1 confirmed critical | 20 |
| 4 confirmed highs | 40 |
| 3 confirmed mediums | 12 |
| 20 confirmed lows | 20 |
| 1 critical but `needs_review` | 3 |

A pile of unverified heuristics can never outrank one confirmed critical.

---

## 9. Real-world recipes

### Pre-sales audit for a prospect

```bash
uv run clientlens scan prospect.com --i-am-authorized --no-crtsh \
  --html prospects/prospect.com.html --pdf prospects/prospect.com.pdf
# → email the PDF, keep the HTML for your own reference
```

### Full engagement scan

```bash
mkdir -p reports/2026-10-04-acme
uv run clientlens scan acme.com --i-am-authorized --active \
  --html reports/2026-10-04-acme/acme.html \
  --pdf  reports/2026-10-04-acme/acme.pdf \
  -o     reports/2026-10-04-acme/acme.json
```

### Monthly regression check

```bash
#!/usr/bin/env bash
# crontab: 0 6 1 * * /path/to/monthly.sh
set -euo pipefail
export CLIENTLENS_DB=~/.clientlens/monthly.db
MONTH=$(date +%Y-%m)
mkdir -p "reports/$MONTH"

for domain in acme.com beta.com gamma.com; do
  uv run clientlens scan "$domain" --i-am-authorized \
    --html "reports/$MONTH/$domain.html" -o "reports/$MONTH/$domain.json"
done

# diff against last month if a previous run exists
uv run clientlens history | tail -n +2
```

### Marketing-focused review

```bash
uv run clientlens scan client.com --i-am-authorized -i marketing --html mkt.html
```

### Security-focused review

```bash
uv run clientlens scan client.com --i-am-authorized --active -i security \
  --html sec.html -e
```

### Batch-scan a client list

```bash
#!/usr/bin/env bash
set -euo pipefail
while read -r domain; do
  echo "=== $domain ==="
  uv run clientlens scan "$domain" --i-am-authorized --no-crtsh \
    --html "reports/$domain.html" -o "reports/$domain.json" \
    || echo "  ⚠ $domain needs attention (exit $?)"
done < clients.txt
```

### Feed findings into a ticket

```bash
uv run clientlens scan acme.com --i-am-authorized -o scan.json
python - <<'PY'
import json
d = json.load(open("scan.json"))
for f in d["findings"]:
    if f["severity"] in ("critical", "high") and f["confidence"] == "confirmed":
        print(f"[{f['severity'].upper()}] {f['title']}")
        print(f"  why : {f['reasoning'].splitlines()[0]}")
        print(f"  fix : {f['remediation'].splitlines()[0]}")
        print()
PY
```

---

## 10. Tuning & safety

### Request budget

Every request goes through one rate limiter. Defaults:

| Setting | Default | Flag |
|---|---|---|
| Requests per second | 5 | `--rate` |
| Total request cap | 120 | `--max-requests` |
| Per-request timeout | 12s | `--timeout` |
| Concurrent requests | 6 | (config only) |

A typical **passive** scan uses **1–5 requests**. A full **active** scan uses
**30–60**.

### Being gentle

```bash
# fragile target
uv run clientlens scan fragile.example --i-am-authorized \
  --rate 1 --max-requests 25 --timeout 20 --no-crtsh
```

### Selecting probes

```bash
# only headers and cookies
uv run clientlens scan x.com --i-am-authorized -i security.headers -i security.cookies

# everything except subdomain lookup
uv run clientlens scan x.com --i-am-authorized -x security.subdomains

# skip all email checks (they do DNS queries)
uv run clientlens scan x.com --i-am-authorized -x security.email_auth
```

### Identifiability

All requests carry:

```
User-Agent: ClientLens/0.1 (authorized-audit; +https://github.com/clientlens/clientlens)
```

A defender can see exactly what is scanning them.

### What the tool refuses to do

- Scan without `--i-am-authorized`
- Scan private/loopback addresses without `--allow-private`
- Accept targets with shell metacharacters or whitespace
- Brute-force paths (12-entry wordlist only)
- Claim a vulnerability is confirmed
- Claim a system is "secure"
- Claim something is absent because it was not detected

---

## 11. Fingerprint databases

Bundled as JSON, editable without touching code:

```
src/clientlens/data/fingerprints/
├── tracking.json   43 trackers + 20 consent platforms
└── tech.json       119 technology rules
```

### Tracker entry

```json
{
  "id": "posthog",
  "name": "PostHog",
  "vendor": "PostHog",
  "category": "product-analytics",
  "src_patterns": ["posthog.com/array/", "posthog.js", "us.i.posthog.com"],
  "inline_patterns": ["posthog.init(", "posthog.capture("],
  "cookie_patterns": ["ph_", "posthog"],
  "consent_relevant": true,
  "privacy_friendly": false,
  "deprecated": false
}
```

Matching is case-insensitive substring matching against script `src`s, inline
script bodies, the raw HTML, and cookie names.

### Tech entry

```json
{
  "id": "nextjs",
  "name": "Next.js",
  "category": "framework",
  "html": ["_next/static/", "__NEXT_DATA__", "next/dist/"],
  "headers": { "x-nextjs-cache": ["*"] },
  "meta_generator": [],
  "cookies": []
}
```

Matched against raw HTML, response headers (`"*"` = any value), the
`<meta name="generator">` content, and cookie names.

### Categories

`cms` · `builder` · `framework` · `language` · `server` · `cdn` · `waf` ·
`hosting` · `ecommerce` · `cdn-js` · `analytics` · `marketing` · `security`

---

## 12. Adding your own probe

One file. Nothing else changes.

```python
# src/clientlens/probes/security/my_check.py

from ...core.models import (
    Category, Confidence, Evidence, Finding, FindingKind, Severity,
)
from ...core.registry import ProbeContext, ProbeMode, ProbePhase, register_probe


@register_probe(
    id="security.my_check",
    category=Category.SECURITY,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("http_response",),
    title="My custom check",
    description="Explain what this checks and why it matters.",
    tags=("custom",),
    timeout_s=15.0,
)
async def check_my_thing(ctx: ProbeContext) -> list[Finding]:
    """One-line summary used in `clientlens probes`."""
    resp = ctx.require("http_response")
    findings = []

    if "x-custom-header" not in resp.headers:
        findings.append(Finding(
            id="security.my_check.header_missing",
            title="x-custom-header not present",
            category=Category.SECURITY,
            kind=FindingKind.MISCONFIGURATION,
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            evidence=Evidence.http_headers(resp.headers, source=f"GET {resp.final_url}"),
            reasoning="Explain the consequence, not just the absence.",
            scope=f"Response headers of {resp.final_url}",
            remediation="Add `x-custom-header: ...`.",
            tags=["custom"],
        ))

    return findings
```

Then register it in `src/clientlens/probes/__init__.py`:

```python
from .security import my_check as _my_check  # noqa: F401
```

Run `uv run clientlens probes` — it should appear.

### Probe authoring rules

1. **Always return findings, never raise.** The engine catches exceptions but
   a probe that raises contributes nothing.
2. **Always attach evidence.** A finding without evidence is a bug.
3. **Set confidence honestly.** `CONFIRMED` only for directly observed values.
4. **Use `VULNERABILITY_VECTOR` for attack surface**, never for confirmed
   vulnerabilities.
5. **State the scope.** What exactly was inspected.
6. **Give remediation** for anything that is not a strength or a neutral
   observation.
7. **Respect the request budget.** Use `ctx.http_client`, not a bare `httpx`.

---

## 13. Project layout

```
clientlens/
├── pyproject.toml              project metadata, deps, ruff/pytest config
├── README.md                   overview + quick start
├── USAGE.md                    this file
├── LICENSE                     MIT
├── .gitignore
│
├── src/clientlens/
│   ├── __init__.py             __version__
│   ├── cli.py                  Typer CLI (scan, probes, history, diff, ...)
│   │
│   ├── core/
│   │   ├── models.py           Finding, Evidence, Confidence, Severity, ScanResult
│   │   ├── registry.py         @register_probe plugin system
│   │   ├── engine.py           async orchestrator + shared.capture probe
│   │   ├── config.py           ScanConfig — safety rails
│   │   ├── target.py           strict target parsing
│   │   └── exceptions.py
│   │
│   ├── probes/
│   │   ├── __init__.py         imports every probe module (registration)
│   │   ├── shared/
│   │   │   ├── http_client.py  rate-limited async client
│   │   │   ├── dns_client.py   DNS + TLS capture
│   │   │   ├── html.py         BeautifulSoup helpers
│   │   │   └── fingerprints.py signature matching engine
│   │   ├── security/           20 security probes
│   │   └── marketing/          17 marketing probes
│   │
│   ├── report/
│   │   ├── console.py          Rich terminal renderer
│   │   ├── json_export.py      machine-readable export
│   │   ├── html_export.py      self-contained HTML report
│   │   ├── pdf_export.py       xhtml2pdf renderer
│   │   ├── csv_export.py       spreadsheet/tracker export
│   │   └── intelligence.py     executive summary + priority roadmap
│   │
│   ├── storage/
│   │   └── db.py               SQLite history + diff
│   │
│   ├── web/
│   │   └── app.py              FastAPI dashboard
│   │
│   └── data/fingerprints/
│       ├── tracking.json       43 trackers + 20 consent platforms
│       └── tech.json           119 tech rules
│
└── tests/
    ├── test_models.py          model invariants + target parsing
    ├── test_engine.py          engine, registry, rate limit, renderers
    ├── test_probes.py          fixture-based probe behaviour
    └── test_storage.py         SQLite + diff + web API
```

---

## 14. API reference (JSON)

### Finding object

| Key | Type | Values |
|---|---|---|
| `id` | str | Stable dotted identifier |
| `title` | str | Human-readable headline |
| `category` | enum | `security` · `marketing` · `shared` |
| `kind` | enum | `observation` · `misconfiguration` · `exposure` · `vulnerability_vector` · `strength` · `gap` |
| `severity` | enum | `info` · `low` · `medium` · `high` · `critical` |
| `confidence` | enum | `confirmed` · `likely` · `needs_review` |
| `evidence` | object | `{type, raw, summary, source, captured_at}` |
| `reasoning` | str | Why it matters — states consequence, not just absence |
| `scope` | str | Exactly what was inspected |
| `remediation` | str | What to do about it |
| `references` | list[str] | URLs |
| `tags` | list[str] | Free-form labels |
| `probe_id` | str | Which probe produced it |
| `target` | str | Scanned hostname |
| `fingerprint` | str | 12-char hash used by `diff` |

### Evidence types

`http_headers` · `http_body_snippet` · `http_response` · `dns_record` ·
`tls_certificate` · `html_node` · `json_document` · `url_list` · `text` ·
`not_applicable`

### Confidence levels

| Value | Meaning |
|---|---|
| `confirmed` | Directly observed. Raw evidence attached. |
| `likely` | High-accuracy heuristic. |
| `needs_review` | Human verification required before acting. |

---

## 15. Troubleshooting

**`Authorisation required` / exit code 2**
Add `--i-am-authorized`. There is no bypass.

**`not a valid hostname` or `Invalid target`**
Check the domain. Targets with spaces, `;`, `|`, `$`, backticks etc. are
rejected on purpose.

**`<domain> has no public suffix`**
You passed an internal hostname. Add `--allow-private` if you really mean it.

**`private/loopback address`**
Add `--allow-private`.

**`Fingerprint database not found`**
Run from inside the repo (`uv run ...`), or reinstall with `uv sync`. The tool
looks for `data/fingerprints/` next to the package.

**`PDF skipped — PDF export requires the optional 'pdf' extra`**
```bash
uv sync --extra pdf
```
Or open the HTML in a browser and *Print → Save as PDF*.

**`Dashboard requires the optional 'web' extra`**
```bash
uv sync --extra web
```

**`crt.sh returned non-JSON` or subdomain probe shows `ct_unavailable`**
crt.sh is a free public service and is sometimes slow or rate-limited. Re-run
later, or use `--no-crtsh`.

**"No known tracking scripts detected" on a JS-heavy site**
Correct behaviour. Many SPAs (Next.js, Gatsby) load analytics from bundled
chunks, not from `<script src>` tags in the initial HTML. The finding says
*not detected*, never *not installed*. Verify in the browser devtools Network
tab.

**"No DKIM keys found for common selectors"**
This is a `needs_review` gap, not a defect. Many senders use non-standard
selector names. Check your mail provider's DKIM setup page.

**Scan is slow**
Subdomain enumeration (crt.sh) and email-auth DNS lookups each add 1–3s. Use
`--no-crtsh` and `-x security.email_auth` for a fast pass.

**A probe is failing**
```bash
uv run clientlens scan example.com --i-am-authorized -x security.email_auth
```
Every probe can be excluded individually. `probe_results` in the JSON shows
status and error per probe.

---

## Quick reference card

```bash
# install
uv sync --all-extras

# minimal scan
uv run clientlens scan example.com --i-am-authorized

# full client deliverable
uv run clientlens scan example.com --i-am-authorized \
  --html r.html --pdf r.pdf -o r.json

# deep scan
uv run clientlens scan example.com --i-am-authorized --active

# show evidence in terminal
uv run clientlens scan example.com --i-am-authorized -e

# only security / only marketing
uv run clientlens scan example.com --i-am-authorized -i security
uv run clientlens scan example.com --i-am-authorized -i marketing

# list probes
uv run clientlens probes

# history & diff
uv run clientlens history
uv run clientlens diff <before> <after>

# re-render from saved JSON
uv run clientlens report r.json --html r.html --pdf r.pdf

# dashboard
uv run clientlens dashboard

# tests & lint
uv run pytest
uvx ruff check src tests
```
