# PhishGuard — Compromised Email & Phishing Detection System

A professional-grade detection suite built with **Python (Flask)** on the backend and
**HTML / CSS / JavaScript** on the frontend, with a SQLite-backed investigation store.

```bash
pip install -r requirements.txt
python app.py            # → http://127.0.0.1:5000
```

Application entry points:

- `/` — marketing/landing page for the platform
- `/app` — the main analyst workspace dashboard
- `/admin/login` — administrative login for console access

Optional helpers:

```bash
python tests/smoke_test.py    # full API test suite (isolated temp database)
python tests/seed_demo.py     # reset the demo dataset shown on the dashboard
```

---

## Feature set

| Feature | Status | Where |
|---|---|---|
| **Email input / upload** — paste fields or drop an `.eml` file (headers, body, attachment hashes parsed automatically) | ✅ Essential | Analyze tab · `POST /api/parse-eml` |
| **Phishing detection** — verdict: clean / low risk / suspicious / phishing | ✅ Essential | Analyze tab |
| **Sender analysis** — display-name brand spoofing, raw-IP senders, disposable mailboxes, risky TLDs, deep subdomains, hyphen stuffing | ✅ Essential | `detector/engine.py` |
| **URL analysis** — IP URLs, `@`-cloaking, shorteners, punycode/IDN, subdomain depth, base64 blobs, brand-in-URL mismatch | ✅ Essential | `detector/engine.py` |
| **Domain analysis** — near-miss spelling (edit distance), look-alike domains, suspicious TLD & DDNS patterns | ✅ Essential | `detector/engine.py`, `detector/threat_intel.py` |
| **Email header analysis** — SPF/DKIM/DMARC + From vs Reply-To vs Return-Path vs DKIM `d=`, Received-chain forensics, origin IP, missing headers, bulk mailers | ✅ Essential | `detector/engine.py`, `detector/header_analysis.py` |
| **Content analysis** — urgency, threats, credential requests, financial bait, data harvesting, generic greetings, link-text ≠ href | ✅ Essential | `detector/engine.py` |
| **Attachment analysis** — executable/script types, macro documents, archives + SHA-256 hashing of uploaded attachments | ✅ Essential | `detector/engine.py`, `detector/pipeline.py` |
| **Risk score** — weighted 0–100 with per-category caps | ✅ Essential | `detector/engine.py` |
| **Detection explanation** — every point maps to a human-readable finding with remediation | ✅ Essential | report UI |
| **Compromised account detection** — 13 weighted takeover indicators (forwarding rules, recovery changes, MFA tampering, foreign Reply-To…) → takeover-likelihood score | ✅ Essential | Exposure tab · `POST /api/takeover` |
| **Login / activity monitoring** — off-hours logins, failed-login bursts, success-after-failure, unfamiliar device/IP, impossible travel, IP churn | ✅ Important | Activity tab · `POST /api/activity` |
| **Anomalous email activity** — send-volume spikes, recipient fan-out, new-recipient ratios, external-heavy audience, night sending, template subjects | ✅ Important | Activity tab |
| **IOC extraction** — URLs, domains, IPs, emails, MD5/SHA-1/SHA-256 hashes (incl. attachment hashes) with copy/export | ✅ Important | Analyze report · `GET /api/iocs` |
| **Threat intelligence** — bundled feed + analyst watchlist, CIDR support, optional AbuseIPDB enrichment | ✅ Important | Dashboard · `POST /api/ti/check` |
| **Alert generation** — automatic alerts at score ≥ 50 (severity graded) with ack/resolve workflow | ✅ Important | Dashboard · `GET /api/alerts` |
| **Investigation dashboard** — KPIs, verdict distribution, alerts, IOC table, TI workbench | ✅ Important | Dashboard tab |
| **Incident history** — server-side SQLite store; click any incident to reopen its full report | ✅ Important | Dashboard · `GET /api/incidents` |
| **Report generation** — copy as text, download JSON, print-styled report | ✅ Useful | Analyze / Activity / Exposure |
| **User feedback** — mark detections true/false positive; accuracy tracked on the dashboard | ✅ Useful | report footer, incident table |

---

## Architecture

```
app.py                    Flask app: 25 routes, security headers, incident/alert filing
storage.py                SQLite layer (incidents, alerts, custom IOC watchlist)
detector/
  engine.py               Core scoring: sender · urls · content · attachments · auth headers
  header_analysis.py      Identity & routing forensics on raw headers
  ioc.py                  Indicator extraction
  threat_intel.py         Feed + watchlist matching, AbuseIPDB enrichment
  activity.py             Login & sending-behaviour anomaly rules
  takeover.py             Account-takeover indicator weighting
  pipeline.py             .eml parsing + composition of all stages into one report
  rules.py                Keyword lists, brand→domain map, risk tables
data/ti_feed.json         Bundled threat-intel feed (drop in OpenPhish/URLhaus/OTX exports)
static/                   Frontend: index.html · style.css · script.js
tests/smoke_test.py       API test suite (isolated temp DB)
tests/seed_demo.py        Clean demo dataset for the dashboard
```

### API overview

```
POST /api/analyze        full email analysis          POST /api/activity      event-stream anomalies
POST /api/parse-eml      upload .eml                   POST /api/takeover      takeover assessment
GET  /api/indicators     takeover catalogue           GET  /api/stats         dashboard KPIs
GET  /api/incidents      incident history             GET  /api/incidents/<id> full report
POST /api/feedback       true/false positive          GET  /api/alerts        alert queue
PATCH /api/alerts/<id>   ack / resolve                GET  /api/iocs          aggregated indicators
GET  /api/ti/feed        feed info                    POST /api/ti/check      indicator lookup
POST /api/ti/add         watchlist add                GET  /api/watchlist     watchlist
POST /api/password-check k-anonymity HIBP             POST /api/breach-check  HIBP account lookup
GET  /api/health         version probe
```

Example:

```bash
curl -X POST http://127.0.0.1:5000/api/analyze -H "Content-Type: application/json" \
  -d '{"sender":"PayPal <alerts@paypa1.xyz)","subject":"URGENT verify your account",
       "body":"click http://192.0.2.55/login to verify your password"}'
```

---

## Scoring bands

| Domain | Verdicts |
|---|---|
| Email analysis | 0–24 clean · 25–49 low risk · 50–74 suspicious · 75–100 phishing |
| Activity monitoring | 0–24 normal · 25–49 moderate · 50–74 high · 75–100 critical |
| Takeover assessment | 0–24 no signals · 25–49 at risk · 50–74 likely takeover · 75–100 compromised |

## Notes

- **Security headers** on every response: CSP, `X-Frame-Options`, `nosniff`,
  `Referrer-Policy`, `Permissions-Policy`.
- **Password checks** use HIBP's k-anonymity range API — only 5 hash characters leave
  the machine. Account breach lookups need a free HIBP API key.
- The bundled TI feed is a small, documented starter set (cryptomining, DDNS abuse,
  RFC 5737 documentation ranges) — replace it with your own feed using the same JSON
  shape; IP reputation enrichment via AbuseIPDB is available by passing an API key to
  `POST /api/ti/check`.
- Scores are advisory. Every point is traceable to a human-readable finding so an
  analyst can see exactly *why* something was flagged.
