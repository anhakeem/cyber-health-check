"""MISP feed adapter (commercial-safe, AGPL use-as-is)."""
from __future__ import annotations

import httpx

from chc.feeds.base import FeedVerdict, IndicatorKind


class MISPFeed:
    def __init__(self, url: str, api_key: str, client: httpx.Client | None = None):
        self.id = "misp"
        self.commercial_ok = True
        self.url = url.rstrip("/")
        self.api_key = api_key
        self._client = client or httpx.Client()

    def lookup(self, indicator: str, kind: IndicatorKind) -> FeedVerdict | None:
        url = f"{self.url}/attributes/restSearch"
        headers = {"Authorization": self.api_key, "Accept": "application/json"}
        payload = {"value": indicator, "type": "domain" if kind == "domain" else "url"}
        resp = httpx.get(url, headers=headers, params=payload, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        response = data.get("response", [])
        if response:
            return FeedVerdict(verdict="malicious", category="c2", confidence=0.8, source=self.id)
        return None

    def health(self) -> bool:
        try:
            resp = httpx.get(f"{self.url}/servers/getVersion", headers={"Authorization": self.api_key}, timeout=5)
            return resp.status_code == 200
        except Exception:
            return False
