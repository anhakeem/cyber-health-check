# Cyber Health Check — System Architecture

**Phase:** design · **Status:** frozen v1.0 · **Date:** 2026-10-11
**Inputs:** [`results/market-research.md`](../results/market-research.md), [`results/threat-intel-sources.md`](../results/threat-intel-sources.md)

---

## 1. Design Goals (from research)

| Research finding | Architectural response |
|---|---|
| Gap: mid-market wants real-time alerts, not full DLP/policy | **Alert-first**, no DLP/policy engine in MVP |
| Must deploy in minutes, no proxy/DNS/agent changes | Browser extension + cloud API only; no infra changes |
| Must work across browsers | MV3 (Chrome/Edge/Brave) first; Firefox port is a later slice |
| Competitors $5–6/user/mo; DNS filtering $1–3 | Position at **$3–4/user/mo** (below Push Security) |
| Licensing: many free feeds ban commercial use | Only **commercially-safe feeds** in the stack (see §6) |
| Privacy is an enterprise buying gate | Privacy model is a **first-class deliverable**, not a footnote |

**Non-goals (v1):** DLP, URL rewriting/isolation, on-prem deployment, mobile, full SWG features.

---

## 2. Component Diagram

```
┌────────────────────────────────────────────────────────────┐
│  Browser (Chrome/Edge/Brave)                                 │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ MV3 Extension                                         │   │
│  │  ┌────────────┐  ┌──────────────┐  ┌───────────────┐  │   │
│  │  │ content.js │  │ background.js│  │ popup.js      │  │   │
│  │  │ (DOM watch)│  │ (SW: checks) │  │ (alert panel) │  │   │
│  │  └─────┬──────┘  └──────┬───────┘  └───────────────┘  │   │
│  │        │  chrome.runtime.sendMessage                   │   │
│  │  ┌─────▼──────────────────────────────┐               │   │
│  │  │ chrome.storage (token, allow/deny) │               │   │
│  │  └────────────────────────────────────┘               │   │
│  └────────────────────────┬─────────────────────────────┘   │
└───────────────────────────┼─────────────────────────────────┘
                            │ HTTPS/JSON (only our API)
                            ▼
┌────────────────────────────────────────────────────────────┐
│  FastAPI application (src/api/)                              │
│  /check-url  /check-domain  /alerts  /auth  /health          │
│  ┌──────────────────────┬───────────────────────────────┐   │
│  │ ReputationService    │ AlertService                  │   │
│  │ (verdict + cache)    │ (feed → team dashboard)       │   │
│  └──────────┬───────────┴───────────────┬───────────────┘   │
│  ┌──────────▼───────────────────────────▼───────────────┐   │
│  │ FeedIngestor (scheduled) + VerdictCache (TTL)        │   │
│  └──────────┬───────────────────────────────────────────┘   │
└─────────────┼───────────────────────────────────────────────┘
              │
   ┌──────────▼──────────────────────────────────┐
   │ Commercially-safe threat feeds (see §6)      │
   │  • PhishTank (free, commercial-safe)         │
   │  • MISP (self-hosted IOC aggregation)        │
   │  • AbuseIPDB Basic ($25/mo, IP rep)          │
   └──────────┬───────────────────────────────────┘
              │
        ┌─────▼──────┐   ┌──────────────────┐
        │  SQLite    │   │ Team Dashboard    │
        │ (verdicts, │   │ (public/, alert   │
        │  alerts,   │   │  feed + visibility)│
        │  audit)    │   └──────────────────┘
        └────────────┘
```

---

## 3. Data Model

```sql
-- Organizations + users (RBAC in enterprise phase)
CREATE TABLE orgs (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  tier       TEXT NOT NULL DEFAULT 'starter',  -- starter | professional | enterprise
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE users (
  id         TEXT PRIMARY KEY,
  org_id     TEXT NOT NULL REFERENCES orgs(id),
  email      TEXT UNIQUE NOT NULL,
  role       TEXT NOT NULL DEFAULT 'member',   -- owner | admin | member
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Cached reputation verdicts (TTL'd)
CREATE TABLE verdicts (
  indicator  TEXT NOT NULL,          -- url | domain | ip
  kind       TEXT NOT NULL,          -- url | domain | ip
  verdict    TEXT NOT NULL,          -- malicious | suspicious | clean | unknown
  category   TEXT,                   -- phishing | malware | c2 | spam
  confidence REAL,                   -- 0..1
  sources    TEXT,                   -- JSON array of feed ids
  fetched_at TIMESTAMP NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  PRIMARY KEY (kind, indicator)
);
CREATE INDEX idx_verdict_expiry ON verdicts(expires_at);

-- Alerts surfaced to the dashboard
CREATE TABLE alerts (
  id         TEXT PRIMARY KEY,
  org_id     TEXT REFERENCES orgs(id),
  user_id    TEXT REFERENCES users(id),
  indicator  TEXT NOT NULL,
  verdict    TEXT NOT NULL,
  category   TEXT,
  url        TEXT,
  severity   TEXT NOT NULL,          -- low | medium | high | critical
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_alerts_org_time ON alerts(org_id, created_at DESC);

-- Allow/deny overrides per org (false-positive handling)
CREATE TABLE overrides (
  org_id     TEXT NOT NULL REFERENCES orgs(id),
  indicator  TEXT NOT NULL,
  action     TEXT NOT NULL,          -- allow | deny
  created_by TEXT REFERENCES users(id),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (org_id, indicator)
);

-- Audit trail (compliance phase)
CREATE TABLE audit_log (
  id         TEXT PRIMARY KEY,
  org_id     TEXT,
  actor      TEXT,
  action     TEXT NOT NULL,
  target     TEXT,
  meta       TEXT,                   -- JSON
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

---

## 4. API Contract (frozen v1)

Base: `/api/v1` · JSON · single error shape (§5) · JWT bearer auth.

### `POST /api/v1/check-url`
**Request** `{ "url": "https://...", "user_id": "optional" }`
**Response 200**
```json
{ "indicator": "https://bad.example/login", "verdict": "malicious",
  "category": "phishing", "confidence": 0.97,
  "sources": ["phishtank","misp"], "cached": false }
```
**Behavior:** normalize URL → check `verdicts` cache → on miss query enabled feeds → store → return. **Never** fetch the target URL server-side without SSRF guards (§7).

### `POST /api/v1/check-domain`
Same shape, `kind=domain`. Accepts bare domains.

### `GET /api/v1/alerts?since=&severity=&limit=&offset=`
Paginated alert feed for the caller's org.

### `POST /api/v1/auth/login` / `POST /api/v1/auth/refresh`
JWT issue/refresh. `200` → `{ "access_token": "...", "refresh_token": "...", "expires_in": 3600 }`.

### `GET /api/v1/health`
`200` → `{ "status": "ok", "feeds": {"phishtank":"ok","misp":"ok","abuseipdb":"ok"} }`.

### Contract rules
- Additive-only fields; list endpoints paginate; rate-limit headers present.
- `check-url`/`check-domain` are **read-only and safe to retry** (idempotent by indicator).
- Verdicts are cached with TTL — a repeated check of the same indicator is cheap.

---

## 5. Error Shape (single format)

```json
{ "error": { "code": "VALIDATION_ERROR", "message": "url is required", "details": {} } }
```
Codes: `VALIDATION_ERROR` (422) · `UNAUTHENTICATED` (401) · `FORBIDDEN` (403) · `NOT_FOUND` (404) · `RATE_LIMITED` (429) · `UPSTREAM_ERROR` (502) · `INTERNAL` (500).

---

## 6. Threat-Intel Stack (commercial-safe only)

Derived directly from [`results/threat-intel-sources.md`](../results/threat-intel-sources.md):

| Feed | Use | Commercial | Cost |
|---|---|---|---|
| **PhishTank** | Phishing URL/domain verdicts | ✅ allowed free | $0 |
| **MISP** (self-hosted) | IOC aggregation + correlation | ✅ AGPL (use-as-is) | $0 |
| **AbuseIPDB Basic** | IP reputation | ✅ paid plan | $25/mo |
| Google Web Risk | Google-grade URL safety (optional) | ✅ paid | contact sales |
| URLhaus | Malware URLs | ⚠️ fair-use; commercial via Spamhaus | $0–var |
| ❌ VirusTotal Public | — | ❌ non-commercial | — |
| ❌ Google Safe Browsing (free) | — | ❌ non-commercial | — |
| ❌ OpenPhish Community | — | ❌ non-commercial | — |

**Rule:** a feed may only be enabled in a paid build if its commercial license is confirmed. The `FeedIngestor` carries a `commercial_ok: bool` per feed and refuses to enable a non-commercial feed when `tier != 'dev'`.

---

## 7. Privacy & Threat Model (product's own security)

Full document: [`privacy-threat-model.md`](privacy-threat-model.md). Summary:

**What leaves the browser:** the URL/domain being checked + a pseudonymous user id. **Not** page content, not cookies, not form data, not browsing history beyond the checked URL. Configurable org-level allowlist to exclude internal domains.

**STRIDE (product's own attack surface):**
| Threat | Mitigation |
|---|---|
| **S**poofing | JWT with short TTL + refresh; extension token in `chrome.storage.local`, never in page context |
| **T**ampering | TLS only; validate feed data (untrusted input) before storage |
| **R**epudiation | `audit_log` for all admin/override actions |
| **I**nfo disclosure | No page content collected; PII minimized; secrets server-side only |
| **D**oS | Per-user + per-org rate limits; verdict cache absorbs repeats |
| **E**levation | RBAC (owner/admin/member); tenant isolation enforced in every query |

**SSRF guard:** `check-url` must **not** fetch arbitrary user URLs. Reputation is resolved from feeds/cache only. If any future feature fetches a URL, it must block private ranges (RFC1918, loopback, link-local, metadata IPs).

---

## 8. Extension Design (MV3)

- `background.js` (service worker): owns all network calls, holds no page access, registers listeners at top level, state in `chrome.storage` (survives SW termination).
- `content.js`: observes navigation/URL changes; sends the URL to the SW; renders the alert banner. Minimal DOM access.
- `popup.js`: shows the current page verdict + recent alerts.
- **Permissions (minimum):** `storage`, `activeTab`, `alarms`; `host_permissions` = our API domain only. No `<all_urls>`, no broad host access, no remote code.
- Async `sendResponse` always returns `true`.

---

## 9. Cost Model (per 1,000 users / month, estimates)

| Item | Estimate |
|---|---|
| AbuseIPDB Basic | $25/mo flat |
| PhishTank / MISP | $0 |
| Infra (API + cache) | ~$20–50/mo |
| **Total** | **~$45–75/mo** → vs $3–4/user/mo → ~breakeven at ~15–20 users |

---

## 10. Frozen Decisions

1. Python 3.11 + FastAPI; SQLite for MVP; repository layer for Postgres migration.
2. Threat feeds gated by a `commercial_ok` flag — non-commercial feeds are dev-only.
3. Verdicts cached with TTL; repeated checks are cheap and retry-safe.
4. `check-url` never fetches the target URL (SSRF-safe by construction).
5. Extension is MV3, minimum permissions, no remote code.
6. Privacy model is a shipped deliverable, not documentation afterthought.

**Next:** implementation phase → `threat-engine` (TDD), then `api`, then `extension` + `dashboard`.
