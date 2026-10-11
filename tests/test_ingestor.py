"""TDD: commercial_ok gating — RED phase.

FeedIngestor must refuse to enable a feed whose commercial_ok is False
unless tier == 'dev'. Enforces the licensing research:
non-commercial feeds are dev-only.
"""
import pytest

from chc.feeds.base import FeedVerdict, ThreatFeed
from chc.feeds.ingestor import FeedIngestor


class _DummyFeed:
    """Test double implementing the ThreatFeed protocol (no network)."""

    def __init__(self, feed_id: str, commercial_ok: bool):
        self.id = feed_id
        self.commercial_ok = commercial_ok
        self.kinds = frozenset({"url", "domain", "ip"})
        self.lookup_calls = []

    def lookup(self, indicator, kind) -> FeedVerdict | None:
        self.lookup_calls.append((indicator, kind))
        return None

    def health(self) -> bool:
        return True


def test_commercial_ok_false_feed_refused_when_tier_not_dev():
    ingestor = FeedIngestor(tier="production")
    feed = _DummyFeed("vt-public", commercial_ok=False)
    ingestor.register(feed)

    with pytest.raises(PermissionError):
        ingestor.enable("vt-public")

    assert "vt-public" not in ingestor.enabled_feeds


def test_commercial_ok_false_feed_allowed_in_dev_tier():
    ingestor = FeedIngestor(tier="dev")
    feed = _DummyFeed("vt-public", commercial_ok=False)
    ingestor.register(feed)

    ingestor.enable("vt-public")

    assert "vt-public" in ingestor.enabled_feeds


def test_commercial_ok_true_feed_allowed_in_production():
    ingestor = FeedIngestor(tier="production")
    feed = _DummyFeed("phishtank", commercial_ok=True)
    ingestor.register(feed)

    ingestor.enable("phishtank")

    assert "phishtank" in ingestor.enabled_feeds


def test_feed_not_registered_cannot_be_enabled():
    ingestor = FeedIngestor(tier="production")

    with pytest.raises(KeyError):
        ingestor.enable("never-registered")


def test_protocol_is_runtime_checkable():
    assert isinstance(_DummyFeed("x", True), ThreatFeed)
