"""TDD: feed adapters (PhishTank, MISP, AbuseIPDB) — RED phase.

All network calls go through an injectable httpx client so tests mock
them. PhishTank and MISP are commercial_ok=True (free). AbuseIPDB is
commercial_ok=True but requires an API key to be enabled.
"""
import httpx
import pytest

from chc.feeds.abuseipdb import AbuseIPDBFeed
from chc.feeds.base import FeedVerdict
from chc.feeds.misp import MISPFeed
from chc.feeds.phishtank import PhishTankFeed


def _json_response(payload, status=200):
    req = httpx.Request("GET", "https://example.com")
    return httpx.Response(status, json=payload, request=req)


# --- PhishTank ---------------------------------------------------------------

def test_phishtank_commercial_ok():
    feed = PhishTankFeed(api_key="k", client=httpx.Client())
    assert feed.commercial_ok is True
    assert feed.id == "phishtank"


def test_phishtank_lookup_malicious(monkeypatch):
    def fake_get(url, **kw):
        assert "phishtank" in url
        return _json_response({"results": {"in_db": True, "verified": True}})

    monkeypatch.setattr(httpx, "get", fake_get)
    feed = PhishTankFeed(api_key="k", client=httpx.Client())
    v = feed.lookup("https://bad.example/", "url")
    assert v is not None
    assert v.verdict == "malicious"
    assert v.source == "phishtank"


def test_phishtank_lookup_not_in_db(monkeypatch):
    monkeypatch.setattr(httpx, "get", lambda url, **kw: _json_response({"results": {"in_db": False}}))
    feed = PhishTankFeed(api_key="k", client=httpx.Client())
    v = feed.lookup("https://good.example/", "url")
    assert v is not None
    assert v.verdict == "clean"


def test_phishtank_health(monkeypatch):
    monkeypatch.setattr(httpx, "get", lambda url, **kw: _json_response({"status": "ok"}))
    feed = PhishTankFeed(api_key="k", client=httpx.Client())
    assert feed.health() is True


# --- MISP --------------------------------------------------------------------

def test_misp_commercial_ok():
    feed = MISPFeed(url="https://misp.example", api_key="k", client=httpx.Client())
    assert feed.commercial_ok is True
    assert feed.id == "misp"


def test_misp_lookup_malicious(monkeypatch):
    def fake_get(url, **kw):
        assert "misp" in url
        return _json_response({"response": [{"Attribute": [{"type": "domain", "to_ids": True}]}]})

    monkeypatch.setattr(httpx, "get", fake_get)
    feed = MISPFeed(url="https://misp.example", api_key="k", client=httpx.Client())
    v = feed.lookup("bad.example", "domain")
    assert v is not None
    assert v.verdict == "malicious"
    assert v.source == "misp"


def test_misp_lookup_no_match(monkeypatch):
    monkeypatch.setattr(httpx, "get", lambda url, **kw: _json_response({"response": []}))
    feed = MISPFeed(url="https://misp.example", api_key="k", client=httpx.Client())
    v = feed.lookup("good.example", "domain")
    assert v is None


def test_misp_health(monkeypatch):
    monkeypatch.setattr(httpx, "get", lambda url, **kw: _json_response({"status": "ok"}))
    feed = MISPFeed(url="https://misp.example", api_key="k", client=httpx.Client())
    assert feed.health() is True


# --- AbuseIPDB ---------------------------------------------------------------

def test_abuseipdb_commercial_ok():
    feed = AbuseIPDBFeed(api_key="k", client=httpx.Client())
    assert feed.commercial_ok is True
    assert feed.id == "abuseipdb"


def test_abuseipdb_requires_api_key():
    with pytest.raises(ValueError):
        AbuseIPDBFeed(api_key=None, client=httpx.Client())


def test_abuseipdb_lookup_malicious(monkeypatch):
    def fake_get(url, **kw):
        assert "abuseipdb" in url
        return _json_response({"data": {"abuseConfidenceScore": 90}})

    monkeypatch.setattr(httpx, "get", fake_get)
    feed = AbuseIPDBFeed(api_key="k", client=httpx.Client())
    v = feed.lookup("1.2.3.4", "ip")
    assert v is not None
    assert v.verdict == "malicious"
    assert v.source == "abuseipdb"


def test_abuseipdb_lookup_clean(monkeypatch):
    monkeypatch.setattr(httpx, "get", lambda url, **kw: _json_response({"data": {"abuseConfidenceScore": 0}}))
    feed = AbuseIPDBFeed(api_key="k", client=httpx.Client())
    v = feed.lookup("1.2.3.4", "ip")
    assert v is not None
    assert v.verdict == "clean"


def test_abuseipdb_health(monkeypatch):
    monkeypatch.setattr(httpx, "get", lambda url, **kw: _json_response({"status": "ok"}))
    feed = AbuseIPDBFeed(api_key="k", client=httpx.Client())
    assert feed.health() is True
