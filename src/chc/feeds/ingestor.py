"""FeedIngestor: registers feeds and enforces commercial_ok gating."""
from __future__ import annotations

from typing import Iterable

from chc.feeds.base import ThreatFeed


class FeedIngestor:
    def __init__(self, tier: str = "production"):
        self.tier = tier
        self._feeds: dict[str, ThreatFeed] = {}
        self._enabled: dict[str, ThreatFeed] = {}

    def register(self, feed: ThreatFeed) -> None:
        self._feeds[feed.id] = feed

    def enable(self, feed_id: str) -> None:
        feed = self._feeds[feed_id]
        if feed.commercial_ok is not True and self.tier != "dev":
            raise PermissionError(
                f"feed {feed_id!r} is commercial_ok=False; "
                f"only tier 'dev' may enable it"
            )
        self._enabled[feed_id] = feed

    @property
    def enabled_feeds(self) -> list[str]:
        return sorted(self._enabled)

    def enabled(self) -> Iterable[ThreatFeed]:
        return list(self._enabled.values())
