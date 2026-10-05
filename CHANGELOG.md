# CHANGELOG — ClientLens

সব গুরুত্বপূর্ণ আপডেটের তালিকা। নতুন কিছু যোগ হলে এখানে লেখা হয়।

---

## v0.2.0 — Deep Scan Update (বড় আপডেট)

**তারিখ:** ২০২৬-১০-০৫

এই আপডেটে টুলটা আরো শক্তিশালী, সুন্দর আর সহজব্যবহারযোগ্য হয়েছে।

### 🔍 নতুন প্রোব (১০টা যোগ হয়েছে — মোট ৩৩টা)

**Security (নতুন ৫টা):**

| প্রোব | কী দেখে |
|---|---|
| `security.transport.methods` | সার্ভার কোন HTTP method মেনে নেয় — বিপজ্জনক method (PUT, DELETE, TRACE) থাকলে রিপোর্ট করে |
| `security.transport.https_enforcement` | `http://` কি `https://`-এ redirect করে, না সরাসরি content দেখায় |
| `security.transport.http_versions` | HTTP/2 বা HTTP/3 (QUIC) সাপোর্ট আছে কিনা |
| `security.dns.dnssec` | DNSSEC signing — DNSKEY/DS record আছে কিনা, chain of trust ঠিক আছে কিনা |
| `security.dns.www_redirect` | www আর non-www — কোনটা canonical, দুটোই কি content দেখাচ্ছে (duplicate content সমস্যা) |
| `security.headers.csp_deep` | CSP header এর ভেতরের বিশ্লেষণ — `unsafe-inline`, `unsafe-eval`, wildcard, missing directive |

**Marketing (নতুন ৪টা):**

| প্রোব | কী দেখে |
|---|---|
| `marketing.accessibility` | `lang` attribute, viewport meta, image `alt` text coverage |
| `marketing.forms` | ফর্মের সমস্যা — GET-এ sensitive তথ্য, cross-origin action, label ছাড়া input |
| `marketing.third_party` | পেজ কোন কোন বাইরের domain-এ request পাঠাচ্ছে — supply chain risk |
| `marketing.pwa` | Web app manifest, service worker, favicon, apple-touch-icon |

### 🎛️ নতুন CLI ফিচার

| ফিচার | কমান্ড | কাজ |
|---|---|---|
| **Preset সিস্টেম** | `--preset quick/standard/deep` | কতটুকু গভীর স্ক্যান করবে তা বেছে নাও |
| **Progress bar** | (স্বয়ংক্রিয়) | স্ক্যান চলার সময় দেখা যায় কতটুকু হয়েছে |
| **CSV export** | `--csv findings.csv` | Excel/Sheets-এ খোলার মতো ফাইল |
| **Probes preview** | `clientlens probes --preset deep` | কোন preset-এ কোন প্রোব চলবে দেখা যায় |

**Preset গুলো:**
- `quick` (~১৫ প্রোব) — দ্রুত এক নজরে দেখা
- `standard` (~২৩ প্রোব) — সাধারণ ক্লায়েন্ট অডিট (ডিফল্ট)
- `deep` (৩৩ প্রোব পুরো) — সম্পূর্ণ গভীর স্ক্যান

### 📊 রিপোর্ট উন্নতি

- **Executive summary** — এক নজরে পোস্টচার, risk score আর top themes
- **Priority actions** — "⚡ Quick wins" আর "🗓 Planned work" আলাদা করে দেখানো হয়
- **Author branding** — ABDULLAH AL NOMAN নাম সব রিপোর্টে থাকে
- **Console report** — সুন্দর ফরম্যাটিং, executive summary সহ

### 🧪 টেস্ট আর মান

- **১২৬টা টেস্ট** (আগে ছিল ৮৩টা) — সব পাস করছে
- **৪৩টা নতুন টেস্ট** নতুন প্রোবগুলোর জন্য
- **Bug fix:** `Registry.select`-এ prefix matching ঠিক করা হয়েছে
- **Bug fix:** preset exclusion সঠিক probe ID দিয়ে কাজ করছে
- **Cleanup:** `forms.py` আর `third_party.py` আলাদা ফাইলে সাজানো হয়েছে

### 📚 ডকুমেন্টেশন

- **README.md** — badges, ৬০ সেকেন্ডে quick start, FAQ, কী কী পাবে সেকশন
- **USAGE.md** — ৩৩টা প্রোবের বিস্তারিত, preset টেবিল
- **AGENTS.md** — ডেভেলপারদের জন্য (নতুন প্রোব যোগ করার নিয়ম)

---

## v0.1.0 — প্রথম রিলিজ

**তারিখ:** ২০২৬-১০-০৪

### যা দিয়ে শুরু

- **২৩টা প্রোব** (১৭ passive + ৬ active) — security + marketing
- **৪ রকম রিপোর্ট** — Console, HTML, PDF, JSON
- **CLI** — `scan`, `probes`, `history`, `diff`, `report`, `dashboard`, `version`
- **SQLite history** — পুরনো স্ক্যান সংরক্ষণ ও তুলনা
- **Web dashboard** — FastAPI দিয়ে রিপোর্ট দেখার UI
- **Accuracy contract** — evidence-backed finding, confidence model
- **Safety rails** — `--i-am-authorized` mandatory, rate limiting
- **৮৩টা টেস্ট**

---

## রোডম্যাপ (আগামী আপডেটে যা আসতে পারে)

- [ ] PyPI-তে publish — `pip install clientlens`
- [ ] GitHub Actions CI — প্রতি commit-এ টেস্ট চালানো
- [ ] Test coverage বাড়ানো (এখন ~৫৩%)
- [ ] আরো প্রোব: WAF detection, API endpoint discovery
- [ ] PDF report-এ আরো সুন্দর ডিজাইন
- [ ] বাংলা ভাষায় রিপোর্ট আউটপুট
