# ClientLens

![Python](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/tests-126%20passed-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)
![Cost](https://img.shields.io/badge/cost-free-00b894)
![Probes](https://img.shields.io/badge/probes-33-orange)

**Unified client audit engine** — security and digital-marketing reconnaissance
in one evidence-backed report. Free, local, and deterministic.

One command. One report. Both sides of a client's web presence.

```
clientlens scan example.com --i-am-authorized --html report.html --pdf report.pdf
```

---

## ৬০ সেকেন্ডে শুরু / Quick Start in 60 seconds

**কী লাগবে:** Python 3.12+ এবং [uv](https://docs.astral.sh/uv/)

```bash
# ১) কোড ডাউনলোড
git clone https://github.com/nomanwafi/clientlens.git
cd clientlens

# ২) ইনস্টল (একটাই কমান্ড)
uv sync --all-extras

# ৩) স্ক্যান চালাও (নিজের সাইটের নাম বসাও)
uv run clientlens scan example.com --i-am-authorized

# ৪) সুন্দর রিপোর্ট ফাইল বানাও
uv run clientlens scan example.com --i-am-authorized \
    --html report.html --pdf report.pdf
```

**হয়ে গেছে!** `report.html` ফাইলটা ব্রাউজারে খুলো — ক্লায়েন্টকে দেওয়ার মতো রিপোর্ট পাবে।

> ⚠️ **গুরুত্বপূর্ণ:** `--i-am-authorized` ছাড়া স্ক্যান চলবে না। শুধু সেই সাইট স্ক্যান করো
> যার মালিক তুমি বা যার অনুমতি তোমার কাছে লিখিত আছে।

---

## Documentation

| Document | What's in it |
|---|---|
| **[USAGE.md](USAGE.md)** | **Complete guide** — every command, every flag, all 33 probes, output formats, JSON schema, real-world recipes, troubleshooting |
| **[CHANGELOG.md](CHANGELOG.md)** | সব আপডেটের তালিকা — কী কী নতুন যোগ হয়েছে |
| [examples/](examples/) | Copy-paste scripts: batch scanning, action-list extraction, GitHub Actions CI |
| This README | Overview, accuracy contract, architecture |

**New here?** Read [USAGE.md §2 — Your first scan](USAGE.md#2-your-first-scan) first.

---

## Why

Security audits and marketing audits are usually done with different tools, at
different times, producing different deliverables. But the client only wants
one answer: **what is wrong with my site and what should I do about it?**

ClientLens does both in a single pass and produces a single client-ready
report — with evidence attached to every claim.

---

## কী কী পাবে / What you get

একটা স্ক্যানে তুমি পাবে **৫ রকম আউটপুট**:

| আউটপুট | কমান্ড | কাজে লাগে |
|---|---|---|
| 🖥️ **Terminal report** | (স্বয়ংক্রিয়) | দ্রুত দেখার জন্য — executive summary + priority actions |
| 🌐 **HTML report** | `--html report.html` | ক্লায়েন্টকে দেওয়ার জন্য — print-ready, সুন্দর ডিজাইন |
| 📄 **PDF report** | `--pdf report.pdf` | সরাসরি PDF পাঠানোর জন্য |
| 📊 **CSV export** | `--csv findings.csv` | Excel/Google Sheets-এ খুলে কাজ করার জন্য |
| 🔧 **JSON data** | `-o report.json` | প্রোগ্রাম্যাটিক ব্যবহারের জন্য |

### রিপোর্টে যা থাকে

- ✅ **Executive summary** — এক নজরে সব সমস্যা
- 🎯 **Priority actions** — "quick wins" (মিনিটে করা যায়) আর "planned work" (দিন লাগবে)
- 🔍 **Evidence** — প্রতিটা সমস্যার প্রমাণ সহ
- ⚠️ **Confidence level** — কোনটা confirmed, কোনটা শুধু অনুমান
- 🚫 **What was NOT tested** — কী কী পরীক্ষা করা হয়নি তাও লেখা থাকে

---

## Quick start

```bash
# 1. Install (Python 3.12+)
uv sync --all-extras

# 2. Scan a domain you are authorised to test
uv run clientlens scan example.com --i-am-authorized

# 3. Generate reports
uv run clientlens scan example.com --i-am-authorized \
    --html report.html --pdf report.pdf -o report.json

# 4. Deeper coverage (opt-in)
uv run clientlens scan example.com --i-am-authorized --active

# 5. View history in a dashboard
uv run clientlens dashboard
```

> **Authorisation is mandatory.** ClientLens refuses to scan without
> `--i-am-authorized`. Only scan domains you own or have written permission
> to test.

### Everything you can do

```bash
clientlens scan <domain>        # run an audit
clientlens probes               # list all 33 probes
clientlens history              # list saved scans
clientlens diff <before> <after>  # compare two scans
clientlens report <scan.json>   # re-render reports
clientlens dashboard            # web UI for scan history
clientlens version
```

Full reference for every flag and option: **[USAGE.md](USAGE.md)**.

---

## What it checks

**33 probes** — 25 passive, 8 active. Full detail in
**[USAGE.md §4](USAGE.md#4-all-33-probes)**. Presets (`--preset quick|standard|deep`)
choose how many run.

### Security (18 probes)

| Probe | What it reports |
|---|---|
| `security.headers` | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP + ineffective values + banner disclosure |
| `security.headers.csp_deep` | CSP directive parsing — `unsafe-inline`/`unsafe-eval`, wildcards, missing hardening directives, Report-Only mode |
| `security.cookies` | Secure / HttpOnly / SameSite flags, `SameSite=None` misuse, tracker cookies |
| `security.tls` | Certificate issuer, expiry window, SAN coverage, negotiated protocol |
| `security.dns` | A/AAAA/MX/NS/TXT/CAA inventory, missing CAA, single-NS delegation |
| `security.dns.dnssec` | DNSKEY/DS presence — signed zones, broken chain of trust at the parent |
| `security.dns.www_redirect` *(active)* | www / non-www DNS and canonicalisation behaviour |
| `security.email_auth` | SPF, DKIM (incl. wildcard/revoked-key detection), DMARC policy strength, MTA-STS |
| `security.redirects.chain` | Redirect hops, plaintext downgrade, long chains, cross-host jumps |
| `security.mixed_content` | Active and passive `http://` subresources |
| `security.transport.methods` *(active)* | OPTIONS method enumeration — dangerous verbs advertised by the server |
| `security.transport.https_enforcement` | Whether `http://` redirects to `https://` or serves content |
| `security.transport.http_versions` | HTTP/2 negotiation, HTTP/3 (QUIC) availability via alt-svc |
| `security.subdomains` | Certificate Transparency names, risky staging/admin hosts, wildcard certs |
| `security.exposure.paths` *(active)* | `.git`, `.env`, backups, dumps, phpinfo, admin/actuator endpoints |
| `security.exposure.disclosure` *(active)* | `robots.txt`, `security.txt` (RFC 9116), `sitemap.xml`, `humans.txt` |
| `security.cors` *(active)* | Origin reflection vector with/without credentials |
| `security.redirects.open_vector` *(active)* | Open-redirect parameter reflection |

### Marketing (14 probes)

| Probe | What it reports |
|---|---|
| `marketing.seo.meta` | Title, description, canonical, robots directives, heading structure, title/h1 alignment |
| `marketing.social` | Open Graph + Twitter Card completeness and consistency |
| `marketing.schema` | JSON-LD inventory, parse validity, rich-result types, Organization entity |
| `marketing.tracking` | Analytics/advertising/session-replay inventory (43 vendor signatures) |
| `marketing.consent` | CMP detection (20 platforms), Google Consent Mode, privacy link |
| `marketing.tech_stack` | CMS, framework, CDN, WAF, hosting, e-commerce (119 rules) |
| `marketing.performance` | TTFB, HTML payload, resource count, compression, cache headers |
| `marketing.links` | Internal/external ratio, nofollow/sponsored/ugc, suspicious outbound links |
| `marketing.links.broken` *(active)* | Sampled internal-link broken check |
| `marketing.sitemap` *(active)* | robots.txt health, asset blocking, sitemap validity, lastmod |
| `marketing.accessibility` | `lang`, viewport, zoom suppression, image alt coverage |
| `marketing.forms` | Form count, GET-with-sensitive-fields, cross-origin actions, unlabeled inputs |
| `marketing.third_party` | Every external origin the page contacts; script-bearing origins (supply chain) |
| `marketing.pwa` | Web app manifest, service worker hints, favicon / apple-touch-icon, theme colour |

### Shared (1 probe)

| Probe | What it does |
|---|---|
| `shared.capture` | The single network touchpoint for passive scans — homepage fetch, DNS, TLS handshake — published as facts for every downstream probe |

---

## Accuracy contract

This is the part that matters. ClientLens is designed so it **cannot** report
garbage.

### Every finding carries evidence

```json
{
  "id": "security.headers.hsts_missing",
  "title": "strict-transport-security header not present",
  "severity": "medium",
  "confidence": "confirmed",
  "evidence": {
    "type": "http_headers",
    "raw": "content-type: text/html\nserver: nginx\n...",
    "source": "GET https://example.com/"
  },
  "reasoning": "Without HSTS a first visit over http:// can be SSL-stripped...",
  "scope": "Response headers of https://example.com/",
  "remediation": "Add `Strict-Transport-Security: max-age=31536000`..."
}
```

Open `evidence.raw` and you can reach the same conclusion without trusting
ClientLens.

### Three confidence levels, never conflated

| Level | Meaning | Used for |
|---|---|---|
| `confirmed` | Directly observed — DNS answer, header value, DOM node, TLS field | Header presence, cert fields, DNS records, meta tags, tracking scripts |
| `likely` | High-accuracy heuristic | Tech fingerprints, WAF detection, CT-log subdomains |
| `needs_review` | Human verification required | Consent compliance, vulnerability vectors, negative results |

**Hard rule:** a `vulnerability_vector` finding can never be `confirmed`.
The model enforces it at construction time.

### Absence is never reported as presence

`Not detected` is a distinct state from `Absent`. A clean result always says
what was *not* tested:

```
What this scan did NOT test
  ~ Active interaction tests were NOT run (passive mode)
  ~ Field Core Web Vitals not collected
  ~ No authenticated testing was performed
  ~ No vulnerability exploitation was attempted
  ~ Subdomain enumeration is CT-log based
  ~ Traffic/ranking metrics are not collected
```

### Vulnerabilities are reported as vectors, not exploits

ClientLens says *"this parameter reflects an external host — verify manually"*.
It does **not** say *"you have an open redirect vulnerability"*. That
distinction is enforced in the data model.

### Risk score resists inflation

| Scenario | Score |
|---|---|
| 1 confirmed critical | 20 |
| 4 confirmed highs | 40 |
| 3 confirmed mediums | 12 |
| 20 confirmed lows | 20 |
| 1 critical but `needs_review` | 3 |

A pile of unverified heuristics can never outrank one confirmed critical.

---

## Cost: zero

Everything runs locally. No API keys, no subscriptions, no per-scan fees.

| Data source | Cost |
|---|---|
| DNS, TLS, HTTP | Free — direct connections |
| crt.sh (subdomains) | Free — no key required |
| Wappalyzer-derived rules | Bundled open source |
| Report generation | Local (Jinja2 + xhtml2pdf) |
| Storage | Local SQLite |

---

## CLI reference

Seven commands. Full details in **[USAGE.md §3](USAGE.md#3-cli-command-reference)**.

```
clientlens scan <target>        Run an audit
    --i-am-authorized           Required. Confirm permission to scan.
    --active                    Enable active probes (path enum, CORS, open-redirect)
    --preset <name>             Probe set: quick (~15) | standard (~23) | deep (~33)
    --html <path>               Write print-ready HTML report
    --pdf <path>                Write PDF report (requires --extra pdf)
    -o, --output <path>         Write JSON report
    --csv <path>                Write CSV export of findings
    -e, --show-evidence         Include evidence in console output
    -i, --include <prefix>      Only run matching probes (repeatable)
    -x, --exclude <prefix>      Skip matching probes (repeatable)
    --rate <n>                  Requests per second (default 5)
    --max-requests <n>          Hard request budget (default 120)
    --timeout <s>               Per-request timeout (default 12)
    --crtsh / --no-crtsh        Subdomain discovery (default on)
    --allow-private             Allow private/loopback targets
    --save / --no-save          Write to history database (default on)

clientlens history              List saved scans
clientlens diff <before> <after>  Compare two scans
clientlens report <scan.json>   Regenerate reports from saved JSON
clientlens dashboard            Serve the local scan-history dashboard
clientlens probes [--preset]    List all available probes
clientlens version
```

### Ready-made scripts

The [examples/](examples/) directory has copy-paste workflow scripts:

| Script | What it does |
|---|---|
| [`monthly-scan.sh`](examples/monthly-scan.sh) | Batch-scan a client list, write HTML/JSON per domain, flag anything with critical/high findings |
| [`extract-findings.py`](examples/extract-findings.py) | Turn a JSON scan into a prioritised action list — plain text for a ticket, or `--markdown` for a PR |
| [`github-workflow.yml`](examples/github-workflow.yml) | GitHub Actions job: weekly passive scan, upload reports as artifacts, fail the build on critical/high |

```bash
# example: pull just the confirmed high+ findings as a Markdown table
uv run clientlens scan acme.com --i-am-authorized -o acme.json
python examples/extract-findings.py acme.json --min-severity high \
        --confirmed-only --markdown --no-strengths > acme-ticket.md
```

---

## Web dashboard

```bash
uv sync --extra web
uv run clientlens dashboard          # http://127.0.0.1:8765
```

Read-only by design — it renders saved scans and diffs them. Scanning stays in
the CLI so the authorisation acknowledgement cannot be bypassed by a web form.

| Route | Purpose |
|---|---|
| `/` | Scan history with filters |
| `/scans/{id}` | Full HTML report for a scan |
| `/diff/{before}/{after}` | Side-by-side comparison |
| `/api/scans` | JSON list |
| `/api/scans/{id}` | Full JSON payload |
| `/api/scans/{id}/findings?confidence=confirmed` | Filtered findings |
| `/api/diff/{before}/{after}` | Structured diff |

---

## Architecture

```
src/clientlens/
├── core/
│   ├── models.py        Finding, Evidence, Confidence, Severity, ScanResult
│   ├── registry.py      Plugin system — @register_probe decorator
│   ├── engine.py        Async orchestrator with authorisation + budget
│   ├── config.py        Safety rails (rate limit, request budget, UA)
│   └── target.py        Strict target parsing
├── probes/
│   ├── shared/          http_client, dns_client, html, fingerprints
│   ├── security/        16 security probes
│   └── marketing/       12 marketing probes
├── report/              console, json, html, pdf, csv renderers + intelligence
├── storage/             SQLite scan history + diff
├── web/                 FastAPI dashboard
└── data/fingerprints/   tracking.json (43 vendors) + tech.json (119 rules)
```

### Adding a probe

One file. Nothing else changes.

```python
from clientlens.core.registry import register_probe
from clientlens.core.models import Category, Finding, ...

@register_probe(
    id="security.my_check",
    category=Category.SECURITY,
    requires=("http_response",),
)
async def check(ctx: ProbeContext) -> list[Finding]:
    resp = ctx.require("http_response")
    ...
    return [Finding(...)]
```

The engine discovers it automatically.

---

## Safety rails

1. **`--i-am-authorized` is mandatory** — no flag, no scan.
2. **Rate limited** — 5 req/sec default, hard budget of 120 requests.
3. **Identifiable** — `User-Agent: ClientLens/0.1 (authorized-audit; ...)`.
4. **Bounded active probes** — 20-path wordlist, not brute force.
5. **Private targets refused** — `--allow-private` required for RFC1918.
6. **Target validation** — malformed or shell-metacharacter input is rejected.

---

## Optional extras

```bash
uv sync --extra web      # FastAPI dashboard (FastAPI, uvicorn, SQLAlchemy)
uv sync --extra pdf      # PDF export (xhtml2pdf)
uv sync --extra dev      # pytest, respx, coverage
uv sync --all-extras     # everything
```

---

## Testing

```bash
uv run pytest                 # 83 tests
uv run pytest --cov           # with coverage
```

The suite covers the accuracy contract: confidence invariants, evidence
presence, rate limiting, authorisation enforcement, probe dependency ordering
and fixture-based probe behaviour.

---

## FAQ / সাধারণ প্রশ্ন

**প্র: এটা কি ফ্রি?**
হ্যাঁ, ১০০% ফ্রি। কোনো API key, subscription বা টাকা লাগে না। সবকিছু তোমার নিজের কম্পিউটারে চলে।

**প্র: কি আমি যেকোনো সাইট স্ক্যান করতে পারবো?**
না। শুধু সেই সাইট যার মালিক তুমি বা যার অনুমতি তোমার কাছে আছে। `--i-am-authorized` ফ্ল্যাগ ছাড়া স্ক্যান চলে না — এটা ইচ্ছাকৃত।

**প্র: রিপোর্টের তথ্য কতটা নির্ভরযোগ্য?**
প্রতিটা সমস্যার পাশে confidence level থাকে:
- **Confirmed** = সরাসরি প্রমাণ সহ দেখা গেছে
- **Likely** = অনুমান-ভিত্তিক, যাচাই করে নাও
- **Needs review** = মানুষের দেখা দরকার

**প্র: কি এটা হ্যাকার টুল?**
না। এটা defensive audit tool — সমস্যা খুঁজে বের করে ঠিক করার জন্য। কোনো exploit বা attack করে না।

**প্র: স্ক্যান করতে কত সময় লাগে?**
সাধারণত ১০-৩০ সেকেন্ড। `--preset quick` দিলে আরো দ্রুত।

**প্র: পুরনো স্ক্যানের সাথে তুলনা করা যায়?**
হ্যাঁ! `clientlens history` দিয়ে পুরনো স্ক্যান দেখো, `clientlens diff <before> <after>` দিয়ে তুলনা করো।

**প্র: সমস্যা পেলে কী করবো?**
[GitHub-এ issue দাও](https://github.com/nomanwafi/clientlens/issues)।

---

## Limitations

ClientLens is honest about what it is not:

- **Not a penetration test.** No exploitation, no authentication bypass.
- **Not a certification.** It never says "this site is secure".
- **Not exhaustive.** Subdomains come from CT logs; sensitive paths come from a
  12-entry high-signal wordlist; DKIM selectors are probed from a 14-name
  common list; "not detected" always means "not detected", never "absent".
- **Lab metrics only.** Core Web Vitals field data (CrUX) requires a data
  source this build does not use. Lab TTFB is not a CWV score.
- **No traffic/rank data.** Third-party marketing data sources are disabled;
  those fields show `N/A`.
- **No runtime analysis.** Tracking detection reads the initial HTML. Tags
  loaded from bundled JS chunks (common in Next.js/Gatsby) will not be seen —
  the report says *not detected*, and says why.

---

## Licence & Author

MIT — see [LICENSE](LICENSE).

**Built by ABDULLAH AL NOMAN**

> ClientLens reports observations with evidence. It does not replace a
> penetration test and does not certify any system as secure.
