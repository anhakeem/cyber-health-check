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
