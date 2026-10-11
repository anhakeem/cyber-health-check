"""MISP feed adapter (commercial-safe, AGPL use-as-is).

API: POST /attributes/restSearch with JSON body.
Response JSON: {"response": {"Attribute": [...]}}
Source: https://www.circl.lu/doc/misp/automation
"""
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
        self.kinds = frozenset({"url", "domain", "ip"})

    def lookup(self, indicator: str, kind: IndicatorKind) -> FeedVerdict | None:
        url = f"{self.url}/attributes/restSearch"
        headers = {"Authorization": self.api_key, "Accept": "application/json"}
        payload = {"value": indicator}
        resp = httpx.post(url, headers=headers, json=payload, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        response = data.get("response", {})
        # response is a dict with an "Attribute" key containing a list
        if isinstance(response, dict):
            attributes = response.get("Attribute", [])
        elif isinstance(response, list):
            attributes = response
        else:
            attributes = []
        if attributes:
            return FeedVerdict(verdict="malicious", category="c2", confidence=0.8, source=self.id)
        return None

    def health(self) -> bool:
        try:
            resp = httpx.get(f"{self.url}/servers/getVersion", headers={"Authorization": self.api_key}, timeout=5)
            return resp.status_code == 200
        except Exception:
            return False
