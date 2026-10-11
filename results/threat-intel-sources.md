# Threat Intelligence Feeds: Evaluation for Commercial Use

**Project:** Cyber Health Check — corporate browser security product
**Date:** 2026-10-11
**Scope:** Free and paid threat-intel feeds, their rate limits, and commercial-use/redistribution licensing terms.

> ⚠️ **CRITICAL NOTICE:** This document evaluates feeds for use in a **commercial product**. Many "free" feeds explicitly prohibit commercial use. Using a non-commercial feed in a paid product may result in account termination, legal action, or both. Verify all terms directly with each provider before integration.

---

## 1. AbuseIPDB

**Website:** https://www.abuseipdb.com
**API Docs:** https://www.abuseipdb.com/api.html

### What It Provides
- IP reputation database with abuse confidence scores, country, ISP, and usage type
- Community-driven reporting of abusive IP addresses
- Blacklist downloads (CSV), bulk reporter, API for individual checks

### Rate Limits (Free)
| Plan | Checks/Day | Block Checks/Day | Blacklist Size |
|------|-----------|-----------------|----------------|
| Free (Individual) | 1,000 | 100 | 10,000 IPs |
| Basic | 10,000 | 1,000 | 100,000 IPs |
| Premium | 50,000 | 5,000 | 500,000 IPs |

- Free tier: 1,000 IP checks & reports/day (24h sliding window, APIv1; resets at 00:00 UTC for APIv2)
- Rate limiter enforced per account; exceeding limit returns HTTP 429
- Each IP can be reported only once per 15 minutes
- Source: https://www.abuseipdb.com/faq.html

### Commercial Use Terms
- **Free plans explicitly prohibit commercial use.** Per AbuseIPDB Legal Terms §7:
  > "You may not use Free plans for commercial purposes, and a single user or organization may not register multiple Free user accounts. For commercial use or use by multiple user accounts related to a single user or organization, you must subscribe to a Basic or higher Paid Plan."
  > — Source: https://www.abuseipdb.com/legal
- **Paid plans:** Basic $25/mo ($228/yr), Premium $99/mo ($1,068/yr), Enterprise custom pricing
- Source: https://www.abuseipdb.com/pricing

### Verdict: ⚠️ RESTRICTED (Free) / ✅ ALLOWED (Paid)
- Free tier is **non-commercial only**
- Commercial use requires paid plan ($25+/mo)
- Reasonable pricing for SMBs

---

## 2. URLhaus (abuse.ch)

**Website:** https://urlhaus.abuse.ch
**API Docs:** https://urlhaus.abuse.ch/api

### What It Provides
- Malware distribution URLs with metadata (payload, tags, threat type)
- Daily CSV database dump, MISP events, DNS RPZ, Snort/Suricata rulesets, hostfiles, ClamAV signatures
- API for automated queries (requires free Auth-Key)

### Rate Limits
- Free community API available under "fair use principles"
- No hard published numeric rate limit for community API
- abuse.ch terms describe volume limits as "volumes reasonably expected for non-commercial or non-profit purposes"
- Source: https://urlhaus.abuse.ch/api

### Commercial Use Terms
- **Community API is free of charge under fair-use principles, BUT:**
  > "Use of the API by companies, networks, or individuals with commercial or for-profit needs may require a paid subscription for the enhanced abuse.ch commercial API."
  > — Source: https://urlhaus.abuse.ch/api
- Commercial API is managed through Spamhaus (abuse.ch's commercial sister company)
- URLhaus data also available via Spamhaus Intelligence API (SIA) — commercial license required
- Developer License (free for 6 months) available for testing, but commercial use requires paid license
- Contributor route: commercial users who consistently contribute data for 6 months may qualify for free use (subject to review)
- Source: https://www.spamhaus.com/resource-center/utilize-abusech-data-exposing-malicious-urls-with-spamhaus-intelligence-api

### Verdict: ⚠️ RESTRICTED for commercial use without subscription
- Free community API is fair-use only
- Commercial use requires paid subscription via Spamhaus/Abuse.ch
- High-quality malware URL data but licensing complexity

---

## 3. OpenPhish

**Website:** https://openphish.com
**Terms:** https://openphish.com/terms.html

### What It Provides
- Phishing URL feeds with metadata (targeted brand, IP/ASN, GeoIP, SSL metadata, page language)
- Intelligence Pack with enhanced metadata
- SQLite database with Python API for offline queries
- REST API integration

### Rate Limits
| Feed Tier | Update Frequency | Format | Commercial Use |
|-----------|-----------------|--------|----------------|
| Community (Free) | 12 hours | Text file | ❌ No |
| Premium | 5 minutes | CSV, JSON | ✅ Yes (licensed) |
| Platinum | 5 minutes | CSV, JSON | ✅ Yes (licensed) |

- Source: https://openphish.com/phishing_feeds.html

### Commercial Use Terms
- **Community Feed is STRICTLY NON-COMMERCIAL.** Per OpenPhish Terms of Use:
  > "You may use the Services and the information obtained through them for academic, independent, or personal research, provided that such research does not support your organization's business operations. You agree not to use any part of the Services for any commercial purposes, including, but not limited to, security operations, threat intelligence, detection, enrichment, product development, automation, customer protection, or other."
  > — Source: https://openphish.com/terms.html
- Premium and Platinum feeds are licensed for commercial use (pricing via email inquiry)
- Database tiers: Light (60 days, 15-min refresh), Extended (120 days, 15-min refresh), Pro (180 days, daily refresh)
- Pricing not publicly disclosed — requires email from organization domain
- Source: https://openphish.com/phishing_database.html

### Verdict: ⚠️ RESTRICTED (Free) / ✅ ALLOWED (Paid, but pricing opaque)
- Community feed cannot be used in any commercial product
- Premium licensing available but pricing is not transparent
- Strong phishing-specific data

---

## 4. PhishTank (Cisco Talos)

**Website:** https://phishtank.net
**Terms:** https://phishtank.net/terms.php
**API Info:** https://www.phishtank.net/api_info.php

### What It Provides
- Community-verified phishing website database
- Downloadable database files (updated hourly) in multiple formats
- REST API for URL submissions and lookups
- ETag-based caching to minimize requests

### Rate Limits
- API key required for programmatic access
- Rate limits enforced; exact numbers not publicly published but communicated via response headers (`X-Request-Limit`, `X-Request-Limit-Interval`)
- HTTP HEAD requests for ETag checking are **unlimited** and don't count against rate limit
- Downloadable database files are the recommended approach for high-volume lookups
- Going over limit returns HTTP 509
- Source: https://www.phishtank.net/api_info.php

### Commercial Use Terms
- **Data (API) is explicitly available for commercial use WITHOUT charge.** Per PhishTank Terms of Use:
  > "However, the 'Data' (as defined below) from the Site and the Service are available for commercial use without charge. The data is not warrantied in any way for accuracy."
  > — Source: https://phishtank.net/terms.php
- FAQ confirms:
  > "Is it OK to use the API for both commercial and non-commercial uses? Yes, it is OK."
  > — Source: https://www.phishtank.net/faq.php
- Content (website design, text) is CC BY-SA 2.5 and non-commercial, but the **Data** (API/feed) is commercial-friendly
- Note: Data is provided "as is" without accuracy warranty

### Verdict: ✅ COMMERCIALLY SAFE (Data/API)
- Free API data can be used commercially without restriction
- Use downloadable databases for high-volume scenarios to avoid rate limiting
- Data quality depends on community verification (median verification time ~15 hours per 2013 stats; current times may vary)

---

## 5. MISP (Malware Information Sharing Platform)

**Website:** https://www.misp-project.org
**License:** https://www.misp-project.org/license

### What It Provides
- Open-source threat intelligence platform for storing, correlating, and sharing IOCs
- Structured STIX/TAXII format support
- Galaxy clusters, taxonomies, warning-lists, decaying models
- Community feeds and sharing via MISP federation
- REST API, PyMISP Python library

### Rate Limits
- Self-hosted: No rate limits (your own infrastructure)
- Public MISP instances: Depends on instance operator; generally fair-use
- No built-in API rate limiting in the software itself

### Commercial Use Terms
- **MISP Core Software:** Licensed under **AGPL-3.0-or-later**
  - AGPL requires source code disclosure if you modify the core software
  - "This requirement only applies if the MISP core software has been modified, meaning that you are free to bundle MISP with any software under different licenses"
  - "AGPL only applies to the MISP core software and not to any other software using the API of MISP"
  - Source: https://www.misp-project.org/license
- **MISP Galaxies:** Dual-licensed CC0 1.0 or BSD 2-Clause
- **MISP Warning-lists:** Dual-licensed CC0 1.0 or BSD 2-Clause
- **MISP Taxonomies:** Dual-licensed CC0 1.0 or BSD 2-Clause
- **MISP Objects:** Dual-licensed CC0 1.0 or BSD 2-Clause (software: AGPL-3.0)

### Verdict: ✅ COMMERCIALLY SAFE (with caveats)
- Open-source platform, free for commercial use
- AGPL applies only to modified core software — using MISP as-is via API does not trigger AGPL
- Data licensing varies by feed; check individual feed terms
- Requires self-hosting or access to a community instance

---

## 6. Google Safe Browsing API

**Website:** https://developers.google.com/safe-browsing
**Usage Limits:** https://developers.google.com/safe-browsing/v4/usage-limits

### What It Provides
- URL reputation checks against Google's safe browsing lists (malware, phishing, unwanted software)
- Batch URL checks (up to 500 URLs per POST request)
- Threat list updates via API

### Rate Limits
- Default usage quota allocated per project (viewable in Google Cloud Console)
- Up to 10,000 clients per 24-hour period per API key
- Up to 500 URLs per POST request
- Additional quota available upon request
- Source: https://stackoverflow.com/questions/10855601/google-safe-browsing-api-limits
- Source: https://developers.google.com/safe-browsing/v4/usage-limits

### Commercial Use Terms
- **Safe Browsing API is FOR NON-COMMERCIAL USE ONLY.** Per Google's usage restrictions:
  > "The Safe Browsing API is for non-commercial use only (meaning 'not for sale or revenue generating purposes'). If you need a solution for commercial purposes, please refer to Web Risk."
  > — Source: https://developers.google.com/safe-browsing/v4/usage-limits
- **Commercial alternative:** Google Web Risk API (paid, commercial)
  - Provides similar functionality with commercial licensing
  - Pricing not publicly listed; requires Google Cloud billing

### Verdict: ❌ RESTRICTED (Free API) / ✅ ALLOWED (Web Risk, paid)
- Free Safe Browsing API cannot be used in commercial products
- Must use Google Web Risk API for commercial use
- Web Risk pricing is not transparent (contact Google sales)

---

## 7. VirusTotal

**Website:** https://www.virustotal.com
**API Overview:** https://docs.virustotal.com/docs/api-overview

### What It Provides
- File scanning and reputation (multi-engine antivirus)
- URL scanning and reputation
- Domain/IP reputation
- File upload and download, metadata analysis
- Community comments and votes

### Rate Limits (Public/Free API)
- **4 requests per minute**
- **500 requests per day**
- File uploads capped at 650 MB
- Premium API: No hard rate limits; governed by SLA
- Source: https://docs.virustotal.com/docs/api-overview
- Source: https://docs.virustotal.com/reference/public-vs-premium-api

### Commercial Use Terms
- **Public API is STRICTLY NON-COMMERCIAL.** Per VirusTotal API Overview:
  > "The public API is a free service, available for any website or application that is free to consumers. The API must not be used in commercial products or services, it can not be used as a substitute for antivirus products and it can not be integrated in any project that may harm the antivirus industry directly or indirectly. Noncompliance of these terms will result in immediate permanent ban of the infractor individual or organization."
  > — Source: https://docs.virustotal.com/docs/api-overview
- Per Public vs Premium API docs:
  > "The Public API must not be used in commercial products or services. The Public API must not be used in business workflows that do not contribute new files."
  > — Source: https://docs.virustotal.com/reference/public-vs-premium-api
- **Creating multiple accounts to overcome limits is explicitly prohibited**
- Premium/GTI Enterprise: Custom pricing, requires contacting sales
- Independent estimates suggest $1,500–$4,000+/month for premium (inference — not verified from official pricing)

### Verdict: ❌ RESTRICTED (Free API) / ✅ ALLOWED (Premium, expensive)
- Public API cannot be used in commercial products under any circumstances
- Premium API is expensive and requires custom enterprise agreement
- Not recommended for commercial browser security product at SMB price point

---

## 8. Spamhaus

**Website:** https://www.spamhaus.org
**Free DNSBL:** https://www.spamhaus.org/blocklists/dnsbl-fair-use-policy
**DQS (paid):** https://www.spamhaus.com/terms-of-use-fair-use-policy-for-free-data-query-service

### What It Provides
- **SBL** (Spamhaus Blocklist): IP addresses involved in spam
- **XBL** (Exploits Blocklist): IP addresses with malware/botnet activity
- **PBL** (Policy Blocklist): IP ranges that should not send email directly
- **DBL** (Domain Blocklist): Domains with poor reputation, spam, or phishing
- **ZEN**: Combined SBL+XBL+PBL
- **HBL** (Hash Blocklist): Malware hashes

### Rate Limits
- Free DNS query service: No hard published numeric limit, but fair-use policy applies
- Commercial DQS (Data Query Service): Paid subscription, limits depend on plan
- Source: https://www.spamhaus.org/blocklists/dnsbl-fair-use-policy

### Commercial Use Terms
- **Free DNSBL service is free of charge for low-volume, non-commercial users.**
  > "Use of the Spamhaus DNSBLs is free of charge for low-volume, non-commercial users. If you're unsure, please check our DNSBL usage criteria."
  > — Source: https://www.spamhaus.org/blocklists/policy-blocklist
- **Commercial use requires Spamhaus Technology (DQS) paid subscription**
  > "An expanded set of data is available in the DQS offering of our commercial sister company, Spamhaus Technologies, Ltd"
  > — Source: https://www.spamhaus.org/faqs/dnsbl-usage
- Fair Use Policy limits queries to "volumes reasonably expected for non-commercial or non-profit purposes" (inference)
- Source: https://www.spamhaus.com/terms-of-use-fair-use-policy-for-free-data-query-service

### Verdict: ⚠️ RESTRICTED (Free) / ✅ ALLOWED (DQS, paid)
- Free DNSBLs are for non-commercial, low-volume use
- Commercial products need DQS subscription (pricing via Spamhaus Technology)
- Strong reputation data but requires commercial licensing for product integration

---

## Summary Recommendation Table

| Feed | Free Tier | Commercial Use | Rate Limit (Free) | Pricing (Paid) | Recommendation |
|------|-----------|----------------|-------------------|----------------|----------------|
| **AbuseIPDB** | ✅ Yes | ❌ No (free tier) | 1,000 checks/day | $25–$99/mo | ⚠️ Use paid tier for IP reputation |
| **URLhaus** | ✅ Yes | ⚠️ Fair-use only | Unpublished | Via Spamhaus | ⚠️ Contact for commercial license |
| **OpenPhish** | ✅ Yes | ❌ No (community) | N/A | Email inquiry | ⚠️ License required; pricing opaque |
| **PhishTank** | ✅ Yes | ✅ **Yes, free** | Header-based (unlimited HEAD) | Free | ✅ **Best free phishing feed for commercial use** |
| **MISP** | ✅ Yes (OSS) | ✅ Yes (AGPL) | N/A | Free (self-hosted) | ✅ **Excellent for IOC management; AGPL caveat** |
| **Google Safe Browsing** | ✅ Yes | ❌ No | ~10,000 clients/24h | Web Risk (paid) | ❌ Free tier not usable commercially |
| **VirusTotal** | ✅ Yes | ❌ No | 4 req/min, 500 req/day | Enterprise ($1.5K+/mo est.) | ❌ Too expensive/limited for SMB |
| **Spamhaus** | ✅ Yes | ❌ No (free tier) | Fair-use | DQS (paid) | ⚠️ Requires paid DQS for commercial use |

---

## Key Findings

### Feeds Safe for Commercial Use (Free of Charge)
1. **PhishTank** — API data explicitly commercial-friendly; use downloadable databases for volume
2. **MISP** — Open-source platform; AGPL only applies to modified core; use as-is via API

### Feeds Requiring Paid Licensing
3. **AbuseIPDB** — $25/mo Basic plan is affordable entry point for IP reputation
4. **Spamhaus DQS** — Commercial DNSBL for IP/domain reputation; contact for pricing
5. **URLhaus/abuse.ch Commercial API** — Malware URL data via Spamhaus partnership
6. **OpenPhish Premium** — Phishing feed; pricing requires email inquiry
7. **Google Web Risk** — Commercial alternative to Safe Browsing API

### Feeds NOT Suitable for Commercial Use
8. **VirusTotal Public API** — Explicitly non-commercial; premium too expensive for most SMBs
9. **Google Safe Browsing API** — Non-commercial only; must use Web Risk for commercial products

---

## Recommended Stack for Cyber Health Check

For a commercial browser security product targeting corporate clients:

1. **Phishing Detection:** PhishTank (free, commercial-safe) + OpenPhish Premium (if budget allows)
2. **IP Reputation:** AbuseIPDB Basic ($25/mo) — affordable and reliable
3. **Malware URL Detection:** URLhaus community API (if fair-use volume suffices) or abuse.ch commercial API
4. **IOC Management:** MISP (self-hosted, free, open-source) for aggregation and correlation
5. **Safe Browsing:** Google Web Risk API (paid) for Google-grade URL safety

### Total Estimated Monthly Cost (Minimal Viable):
- PhishTank: $0
- AbuseIPDB Basic: $25/mo
- MISP: $0 (self-hosted)
- Google Web Risk: Variable (contact Google)
- URLhaus: $0–variable (contact Spamhaus)

**Estimated base cost: $25/mo + Google Web Risk fees**

---

## Sources

1. AbuseIPDB API Documentation — https://www.abuseipdb.com/api.html
2. AbuseIPDB Legal Information — https://www.abuseipdb.com/legal
3. AbuseIPDB FAQ — https://www.abuseipdb.com/faq.html
4. AbuseIPDB Pricing — https://www.abuseipdb.com/pricing
5. URLhaus Community API — https://urlhaus.abuse.ch/api
6. Spamhaus/URLhaus Partnership — https://www.spamhaus.com/resource-center/utilize-abusech-data-exposing-malicious-urls-with-spamhaus-intelligence-api
7. OpenPhish Terms of Use — https://openphish.com/terms.html
8. OpenPhish Phishing Feeds — https://openphish.com/phishing_feeds.html
9. OpenPhish Database — https://openphish.com/phishing_database.html
10. OpenPhish Knowledge Base — https://openphish.com/kb.html
11. PhishTank Terms of Use — https://phishtank.net/terms.php
12. PhishTank API Information — https://www.phishtank.net/api_info.php
13. PhishTank FAQ — https://www.phishtank.net/faq.php
14. MISP Project License — https://www.misp-project.org/license
15. MISP Wikipedia — https://en.wikipedia.org/wiki/MISP_Threat_Sharing
16. Google Safe Browsing Usage Limits — https://developers.google.com/safe-browsing/v4/usage-limits
17. Google Safe Browsing Appropriate Usage — https://developers.google.com/safe-browsing/reference/Appropriate.Usage
18. VirusTotal API Overview — https://docs.virustotal.com/docs/api-overview
19. VirusTotal Public vs Premium API — https://docs.virustotal.com/reference/public-vs-premium-api
20. Spamhaus DNSBL Fair Use Policy — https://www.spamhaus.org/blocklists/dnsbl-fair-use-policy
21. Spamhaus DQS Fair Use Policy — https://www.spamhaus.com/terms-of-use-fair-use-policy-for-free-data-query-service
22. Spamhaus DNSBL Usage FAQ — https://www.spamhaus.org/faqs/dnsbl-usage
23. Spamhaus PBL — https://www.spamhaus.org/blocklists/policy-blocklist

---

*This document is for informational purposes only. All terms are subject to change by respective providers. Verify directly with each provider before making integration decisions. License interpretations in this document are informational and not legal advice.*
