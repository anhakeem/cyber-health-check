"""AbuseIPDB feed adapter (commercial-safe with paid plan, requires API key)."""
from __future__ import annotations

import httpx

from chc.feeds.base import FeedVerdict, IndicatorKind


class AbuseIPDBFeed:
    def __init__(self, api_key: str | None, client: httpx.Client | None = None):
        if not api_key:
            raise ValueError("AbuseIPDB requires an API key (paid plan)")
        self.id = "abuseipdb"
        self.commercial_ok = True
        self.api_key = api_key
        self._client = client or httpx.Client()

    def lookup(self, indicator: str, kind: IndicatorKind) -> FeedVerdict | None:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.api_key, "Accept": "application/json"}
        resp = httpx.get(url, headers=headers, params={"ipAddress": indicator}, timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        if score >= 75:
            return FeedVerdict(verdict="malicious", category="abuse", confidence=score / 100, source=self.id)
        if score >= 25:
            return FeedVerdict(verdict="suspicious", category="abuse", confidence=score / 100, source=self.id)
        return FeedVerdict(verdict="clean", category=None, confidence=0.0, source=self.id)

    def health(self) -> bool:
        try:
            resp = httpx.get("https://api.abuseipdb.com/api/v2/blacklist", headers={"Key": self.api_key}, timeout=5)
            return resp.status_code == 200
        except Exception:
            return False
