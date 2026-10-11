"""TDD: ReputationService — worst-wins merge + cache TTL. RED phase."""
import time

import pytest

from chc.feeds.base import FeedVerdict
from chc.reputation import ReputationService


class _StubFeed:
    """Test double: returns a programmed verdict, records lookups."""

    def __init__(self, feed_id, verdict=None, commercial_ok=True):
        self.id = feed_id
        self.commercial_ok = commercial_ok
        self._verdict = verdict
        self.lookups = []

    def lookup(self, indicator, kind):
        self.lookups.append((indicator, kind))
        return self._verdict

    def health(self):
        return True


# --- worst-wins merge -------------------------------------------------------

def test_worst_wins_malicious_beats_suspicious():
    svc = ReputationService(
        feeds=[
            _StubFeed("a", FeedVerdict("suspicious", "phishing", 0.6, "a")),
            _StubFeed("b", FeedVerdict("malicious", "phishing", 0.9, "b")),
        ],
        ttl=3600,
    )
    r = svc.check("https://bad.example/login", "url")
    assert r.verdict == "malicious"
    assert r.confidence == 0.9
    assert set(r.sources) == {"a", "b"}


def test_worst_wins_suspicious_beats_unknown():
    svc = ReputationService(
        feeds=[
            _StubFeed("a", FeedVerdict("unknown", None, 0.0, "a")),
            _StubFeed("b", FeedVerdict("suspicious", "malware", 0.5, "b")),
        ],
        ttl=3600,
    )
    r = svc.check("https://x.example/", "url")
    assert r.verdict == "suspicious"


def test_worst_wins_unknown_beats_clean():
    svc = ReputationService(
        feeds=[
            _StubFeed("a", FeedVerdict("clean", None, 0.1, "a")),
            _StubFeed("b", FeedVerdict("unknown", None, 0.0, "b")),
        ],
        ttl=3600,
    )
    r = svc.check("https://x.example/", "url")
    assert r.verdict == "unknown"


def test_all_clean_returns_clean():
    svc = ReputationService(
        feeds=[
            _StubFeed("a", FeedVerdict("clean", None, 0.1, "a")),
            _StubFeed("b", FeedVerdict("clean", None, 0.2, "b")),
        ],
        ttl=3600,
    )
    r = svc.check("https://x.example/", "url")
    assert r.verdict == "clean"


def test_no_feeds_returns_unknown():
    svc = ReputationService(feeds=[], ttl=3600)
    r = svc.check("https://x.example/", "url")
    assert r.verdict == "unknown"
    assert r.sources == []


def test_feed_returning_none_is_skipped():
    svc = ReputationService(
        feeds=[
            _StubFeed("a", None),
            _StubFeed("b", FeedVerdict("malicious", "c2", 0.8, "b")),
        ],
        ttl=3600,
    )
    r = svc.check("https://x.example/", "url")
    assert r.verdict == "malicious"
    assert r.sources == ["b"]


# --- cache TTL ---------------------------------------------------------------

def test_cache_hit_within_ttl_does_not_requery():
    feed = _StubFeed("a", FeedVerdict("malicious", "phishing", 0.9, "a"))
    svc = ReputationService(feeds=[feed], ttl=3600)
    r1 = svc.check("https://bad.example/", "url")
    assert r1.cached is False
    r2 = svc.check("https://bad.example/", "url")
    assert r2.cached is True
    assert r2.verdict == "malicious"
    # Only one actual feed lookup happened.
    assert len(feed.lookups) == 1


def test_cache_miss_after_ttl_requeries():
    feed = _StubFeed("a", FeedVerdict("malicious", "phishing", 0.9, "a"))
    now = [1000.0]
    svc = ReputationService(feeds=[feed], ttl=10, clock=lambda: now[0])
    r1 = svc.check("https://bad.example/", "url")
    assert r1.cached is False
    now[0] += 5  # within TTL
    r2 = svc.check("https://bad.example/", "url")
    assert r2.cached is True
    now[0] += 20  # past TTL
    r3 = svc.check("https://bad.example/", "url")
    assert r3.cached is False
    assert len(feed.lookups) == 2


def test_different_indicators_are_cached_separately():
    feed = _StubFeed("a", FeedVerdict("malicious", "phishing", 0.9, "a"))
    svc = ReputationService(feeds=[feed], ttl=3600)
    svc.check("https://a.example/", "url")
    svc.check("https://b.example/", "url")
    assert len(feed.lookups) == 2


# --- SSRF safety -------------------------------------------------------------

def test_check_never_fetches_target_url(monkeypatch):
    """The service must not issue any HTTP request to the checked URL."""
    import httpx

    called = []

    def fake_get(url, *a, **kw):
        called.append(url)
        raise AssertionError("must not fetch target URL")

    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.setattr(httpx, "post", fake_get)

    svc = ReputationService(
        feeds=[_StubFeed("a", FeedVerdict("malicious", "phishing", 0.9, "a"))],
        ttl=3600,
    )
    svc.check("https://internal.example/secret", "url")
    assert called == []


def test_check_url_normalizes_before_lookup():
    feed = _StubFeed("a", FeedVerdict("malicious", "phishing", 0.9, "a"))
    svc = ReputationService(feeds=[feed], ttl=3600)
    svc.check("https://user:pass@bad.example/x#frag", "url")
    assert feed.lookups[0][0] == "https://bad.example/x"
