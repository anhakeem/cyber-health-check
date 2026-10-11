"""PhishTank feed adapter (commercial-safe, free)."""
from __future__ import annotations

import httpx

from chc.feeds.base import FeedVerdict, IndicatorKind


class PhishTankFeed:
    def __init__(self, api_key: str, client: httpx.Client | None = None):
        self.id = "phishtank"
        self.commercial_ok = True
        self.api_key = api_key
        self._client = client or httpx.Client()

    def lookup(self, indicator: str, kind: IndicatorKind) -> FeedVerdict | None:
        url = "https://www.phishtank.com/api/1.0/check/"
        resp = httpx.get(url, params={"url": indicator, "api_key": self.api_key}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        results = data.get("results", {})
        if results.get("in_db") and results.get("verified"):
            return FeedVerdict(verdict="malicious", category="phishing", confidence=0.9, source=self.id)
        return FeedVerdict(verdict="clean", category=None, confidence=0.0, source=self.id)

    def health(self) -> bool:
        try:
            resp = httpx.get("https://www.phishtank.com/api/1.0/status/", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False
