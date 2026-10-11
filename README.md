# Cyber Health Check

Browser extension + dashboard giving corporate teams real-time visibility into
the web threats their users actually hit — phishing, malicious domains,
credential-entry on lookalike sites, and known-bad IPs.

**Source:** [Loot Drop Startup Graveyard](https://www.loot-drop.io/ideas.html) — 29 upvotes
**Owner:** Ahmed Elhakeem (@AhmedTitan01) — CCNP Enterprise, Kali red-team lab
**License:** MIT

---

## The Problem

Corporate users browse the web all day. When someone lands on a phishing page or
a freshly-registered malicious domain, the security team usually finds out
*after* the fact — from a help-desk ticket or a breach report. There is no
lightweight, real-time layer that watches what the browser sees and flags
danger at the moment of exposure.

## The Product

1. **Browser extension (MV3)** — checks each navigated URL against reputation
   feeds, shows an alert badge, warns before credential entry on lookalikes.
2. **Threat engine** — ingests threat-intel feeds, caches verdicts, serves fast.
3. **Team dashboard** — live alert feed + org-wide threat visibility.

## The Owner's Edge

This is a security-native product built by someone who runs a Kali red-team lab,
a pfSense/Pi-hole/dnscrypt home-lab, and holds CCNP Enterprise. Threat intel and
network security are first-hand skills, not a hired-out commodity.

## Monetization

| Tier | Price | Features |
|------|-------|----------|
| Starter | $29/mo | 5 users, basic alerts |
| Professional | $99/mo | 25 users, advanced analytics, API |
| Enterprise | Custom | Unlimited, SIEM integrations, compliance reporting |

## Tech Stack

| Layer | Choice |
|-------|--------|
| Backend | Python 3.11 + FastAPI |
| Extension | Chrome Manifest V3 |
| Threat Intel | AbuseIPDB, URLhaus, OpenPhish, MISP |
| Database | SQLite (MVP) → PostgreSQL (scale) |
| Auth | JWT + OAuth2 |

## Build Plan

See [`project.yaml`](project.yaml) for the full phase/task breakdown.

```
research → design → implementation → testing → enterprise → improvement
```

| Phase | Deliverable | Success criteria |
|-------|-------------|------------------|
| research | market + intel-source reports | ≥5 competitors, ≥3 feeds |
| design | architecture + privacy/threat model | pipeline + STRIDE complete |
| implementation | engine, API, extension, dashboard | blocks a known-bad test URL |
| testing | test suite | all pass, >80% core coverage |
| enterprise | RBAC, SIEM, compliance | events land in mock SIEM |
| improvement | security review | no critical findings |

## Quick Start (once MVP lands)

```bash
cd src && python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn api.main:app --reload      # API on :8000
# Load extension/: chrome://extensions → Developer mode → Load unpacked
```

## Repository Layout

```
cyber-health-check/
├── project.yaml      # phases, tasks, success criteria
├── agents.yaml       # agent roles for orchestration
├── tasks.yaml        # task queue with dependencies
├── src/              # backend (engine + API + auth + integrations)
├── public/           # team dashboard
├── extension/        # Chrome MV3 extension
├── tests/            # test suite
├── docs/             # architecture, privacy/threat model
├── results/          # agent outputs (reports)
├── audit/            # decisions + change log
└── workspace/        # shared scratch for agents
```
