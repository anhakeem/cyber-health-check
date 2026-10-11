# Cyber Health Check — Privacy Model & Threat Model

**Phase:** design · **Status:** v1.0 · **Date:** 2026-10-11

---

## 1. Privacy Model

Enterprise buyers gate on privacy. This document states exactly what data moves
and why — it is a product deliverable, not a legal footnote.

### 1.1 Data Flow

```
User navigates to URL
      │
      ▼
content.js extracts ONLY: the URL (origin + path) + tab id
      │
      ▼
background.js (service worker) sends: { url, anon_user_id, org_id } → our API
      │
      ▼
API resolves reputation from feeds/cache → returns verdict
      │
      ▼
Extension renders banner; API logs an alert row (if malicious/suspicious)
```

### 1.2 What is collected

| Data | Collected? | Purpose | Retention |
|---|---|---|---|
| URL / domain checked | ✅ Yes | Reputation lookup | 30 days (configurable) |
| Pseudonymous user id | ✅ Yes | Per-user rate limits, alert attribution | life of account |
| Org id | ✅ Yes | Tenant isolation | life of account |
| Page content (DOM/text) | ❌ **No** | — | — |
| Cookies / auth tokens | ❌ **No** | — | — |
| Form field values | ❌ **No** | — | — |
| Full browsing history | ❌ **No** | — | — |
| Keystrokes / clipboard | ❌ **No** | — | — |

### 1.3 Controls

- **Org allowlist:** internal/private domains are excluded from checks entirely.
- **Local-only mode (opt-in):** verdict cache served from a bundled feed snapshot
  so nothing leaves the browser for known indicators.
- **Data minimization:** the extension never reads page content — it only reports
  the URL the browser is already navigating to.
- **Deletion:** orgs can purge their alert history; account deletion removes all
  rows tied to the org within 30 days.

### 1.4 Trust boundary

The browser is **untrusted** relative to the API: every field from the extension
is validated at the API boundary (URL shape, lengths, types) before use. Feed
responses are also untrusted and validated before storage.

---

## 2. Threat Model (STRIDE — the product's own attack surface)

| STRIDE | Threat | Mitigation |
|---|---|---|
| **S**poofing | Attacker forges extension requests / steals a token | JWT short TTL + refresh; token in `chrome.storage.local`, never in page context; TLS only |
| **T**ampering | Poisoned feed data corrupts verdicts | Validate + normalize all feed input; `sources` provenance recorded; overrides audited |
| **R**epudiation | Admin denies changing an override | `audit_log` records actor, action, target, timestamp |
| **I**nfo disclosure | PII leaks; browsing patterns exposed | No page content; PII minimized; secrets server-side only; TLS everywhere |
| **D**oS | Abuse exhausts upstream feed quotas / cost | Per-user + per-org rate limits; verdict cache absorbs repeats; feed `commercial_ok` gating |
| **E**levation | Member escalates to admin; tenant escape | RBAC on every route; every query filters by `org_id`; isolation tests in CI |

### 2.1 SSRF (critical for this product)

`check-url` must **never** fetch an arbitrary user-supplied URL — that turns the
API into an SSRF pivot into internal networks. Reputation is resolved from feeds
and cache only.

If a future feature must fetch a URL, it MUST:
- resolve DNS and reject RFC1918 / loopback / link-local / CGNAT / metadata IPs,
- reject non-http(s) schemes,
- enforce a timeout and response size cap,
- not follow redirects into private ranges.

### 2.2 Extension-specific risks

| Risk | Mitigation |
|---|---|
| Malicious page reads extension internals | No page-context access; content script has minimal surface |
| Over-broad permissions scare buyers / increase review | Minimum permissions; `host_permissions` = our API only |
| Remote code injection | All JS bundled; no CDN/eval |
| SW terminated mid-flight loses state | State in `chrome.storage`, not globals |

---

## 3. Compliance posture (enterprise phase)

- `audit_log` is append-only and exportable (SOC 2 / ISO evidence).
- Alert data is scoped per org and purgable (GDPR erasure).
- No special-category data collected; DPIA is straightforward.
- SIEM export is opt-in per org.
