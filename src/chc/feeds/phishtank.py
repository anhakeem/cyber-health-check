"""PhishTank feed adapter (commercial-safe, free).

API: POST http://checkurl.phishtank.com/checkurl/
Response JSON: {"results": {"in_database": bool, "verified": bool, "valid": bool, ...}}
Source: https://www.phishtank.net/api_info.php
"""
from __future__ import annotations

import httpx

from chc.feeds.base import FeedVerdict, IndicatorKind


class PhishTankFeed:
    def __init__(self, api_key: str, client: httpx.Client | None = None):
        self.id = "phishtank"
        self.commercial_ok = True
        self.api_key = api_key
        self._client = client or httpx.Client()
        self.kinds = frozenset({"url", "domain"})

    def lookup(self, indicator: str, kind: IndicatorKind) -> FeedVerdict | None:
        url = "http://checkurl.phishtank.com/checkurl/"
        payload = {
            "url": indicator,
            "format": "json",
            "app_key": self.api_key,
        }
        resp = httpx.post(url, data=payload, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        results = data.get("results", {})
        in_database = results.get("in_database", False)
        valid = results.get("valid", False)
        if in_database and valid:
            return FeedVerdict(verdict="malicious", category="phishing", confidence=0.9, source=self.id)
        return FeedVerdict(verdict="clean", category=None, confidence=0.0, source=self.id)

    def health(self) -> bool:
        try:
            resp = httpx.get("http://checkurl.phishtank.com/checkurl/", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False
