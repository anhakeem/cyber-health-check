# Cyber Health Check

Browser extension offering real-time cybersecurity threat alerts for corporate teams. Proactively monitors and prevents potential cyber threats.

**Source:** [Loot Drop Startup Graveyard](https://www.loot-drop.io/ideas.html) — 29 upvotes

## Quick Start

```bash
# Backend
cd src && python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python main.py

# Extension
# Load unpacked from extension/ directory in Chrome
```

## Project Plan

### Phase 1: MVP (1-3 Months)

| Component | Tech | Status |
|-----------|------|--------|
| Threat Engine | Python + threat intel feeds | Pending |
| Browser Extension | Chrome Extension MV3 | Pending |
| Team Dashboard | FastAPI + SQLite | Pending |

### Phase 2: Enterprise

| Feature | Description | Status |
|---------|-------------|--------|
| Team Management | RBAC, multi-tenant | Pending |
| SIEM Integrations | Splunk, ELK, Splunk | Pending |
| Compliance Reporting | Audit trails, reports | Pending |

## Monetization

| Tier | Price | Features |
|------|-------|----------|
| Starter | $29/mo | 5 users, basic alerts |
| Professional | $99/mo | 25 users, advanced analytics, API |
| Enterprise | Custom | Unlimited, SIEM integrations, compliance |

## Tech Stack

- **Backend:** Python + FastAPI
- **Extension:** Chrome Extension Manifest V3
- **Threat Intel:** MISP, AbuseIPDB, CHDB
- **Database:** SQLite (MVP) → PostgreSQL (scale)
- **Auth:** JWT + OAuth2

## License

MIT
