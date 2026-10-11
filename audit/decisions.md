# Audit Log — Cyber Health Check

Chronological record of decisions, changes, and rationale.

## 2026-10-11 — Project initialized

- **Decision:** Split "Cyber Health Check" out of the Loot Drop research as a standalone project.
  - **Why:** Plays directly to the owner's first-hand security skills (Kali red-team lab,
    pfSense/Pi-hole/dnscrypt home-lab, CCNP Enterprise) — a genuine moat, not a me-too product.
  - **Source:** https://www.loot-drop.io/ideas.html
- **Decision:** Tech stack = Python + FastAPI + Chrome MV3 extension + SQLite→Postgres.
  - **Why:** Same backend language as Hashtagger (reuse patterns), MV3 is the only viable
    extension target, SQLite defers infra until enterprise demand.
- **Decision:** Project lives at `/home/hermes/projects/cyber-health-check/` and is registered
  as a separate Hermes desktop Project (id `p_5e8d6d2f`) so it runs in its own session/workspace.
- **Decision:** Monetization = per-seat subscription: $29 / $99 / custom.
- **Decision:** Privacy model is a first-class design task (`privacy-design`), not an afterthought —
  telemetry leaving the browser must be explicit and defensible to enterprise buyers.

### Open items / blockers
- GitHub push pending: `gh` CLI not installed (needs sudo) and the fine-grained
  PAT in `~/.hermes/.env` cannot create repos via REST. Local git repo is ready to push.
- Threat-intel feed commercial-use licensing must be verified before any paid tier ships.

## 2026-10-11 — Research phase complete (2 subagents)

- **market-research.md:** 28 competitors mapped across 5 architectural segments.
  Key finding: mid-market gap between DNS filtering ($1–3/user/mo, can't detect
  phishing content) and enterprise browsers/SWG ($5–6/user/mo, complex). Market
  consolidating (Akamai/LayerX, CrowdStrike/Seraphic, Palo Alto/Talon). 86% of orgs
  increased browser-security spend.
- **threat-intel-sources.md:** 8 feeds evaluated for COMMERCIAL licensing.
  Commercially safe free: **PhishTank**, **MISP**. AbuseIPDB Basic $25/mo for IP rep.
  ❌ Must avoid in a paid product: VirusTotal public, Google Safe Browsing free,
  OpenPhish community, Spamhaus free DNSBL (all non-commercial).

## 2026-10-11 — Design phase complete

- **Decision:** Architecture frozen v1 — see `docs/architecture.md`.
  - **Positioning:** alert-first, deploy-in-minutes extension at $3–4/user/mo
    (below Push Security $5, above DNS filtering $1–3).
  - **Feed gating:** `FeedIngestor` carries `commercial_ok` per feed and refuses
    non-commercial feeds when `tier != 'dev'` — enforces the licensing research.
  - **SSRF-safe by construction:** `check-url` never fetches the target URL.
  - **Privacy model shipped** as `docs/privacy-threat-model.md`: no page content,
    no cookies, no history; only the checked URL + pseudonymous id.
  - **STRIDE model** complete; RBAC + tenant isolation enforced per query.
  - **API contract frozen** (additive-only, single error shape, rate-limit headers).

### Next
- Implementation phase: `threat-engine` (TDD) → `api` → `extension` + `dashboard`.

## 2026-10-11 — Implementation complete (engine, API, extension, dashboard, RBAC)

All TDD, all verified end-to-end against live servers.

- **threat-engine** (65→143 tests after review fixes): feed adapters, commercial
  licensing gate, SSRF-safe reputation service. Claude review found + we fixed a
  gate bypass, 12 SSRF bypasses, feed failure isolation, kind routing.
- **api** (`4e8f5c3`): check-url / check-domain / health; SSRF rejections → 422.
- **extension** (`50639bb`): MV3, service worker owns all calls, bounded verdict
  cache, warning banner. **Verified in real Chromium** (SW registered, CHECK_URL
  round-tripped a malicious verdict).
- **dashboard** (`ed45988`): AlertStore (SQLite, per-org isolation) + `GET /alerts`
  with severity filter/pagination + dashboard UI. Verified: othercorp sees 0.
- **auth / team-management** (`2412671`): `OrgStore` with owner>admin>member RBAC,
  table-driven permissions, tenant isolation. `/alerts` honors x-user-id;
  `/users` requires admin+. Verified live: member 403, owner 200, ghost 403.

**Test count: 171 passing.** Pushed to github.com/anhakeem/cyber-health-check.

### Next
- Enterprise remainder: SIEM integrations (Splunk HEC / ELK / syslog),
  compliance reporting, audit-log export. Optional — MVP + enterprise RBAC done.
