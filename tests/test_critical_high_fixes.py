"""TDD: CRITICAL and HIGH findings from claude-review.md.

Each test is written to FAIL against the current code, then the code is
fixed to make it pass. Tests are grouped by finding number.
"""
import httpx
import pytest

from chc.feeds.abuseipdb import AbuseIPDBFeed
from chc.feeds.base import FeedVerdict
from chc.feeds.ingestor import FeedIngestor
from chc.feeds.misp import MISPFeed
from chc.feeds.phishtank import PhishTankFeed
from chc.reputation import ReputationService, normalize_domain, normalize_url


# ===========================================================================
# CRITICAL #1: commercial_ok gating bypass
# ===========================================================================

class _StubFeed:
    """Test double: returns a programmed verdict, records lookups."""

    def __init__(self, feed_id, verdict=None, commercial_ok=True, kinds=None):
        self.id = feed_id
        self.commercial_ok = commercial_ok
        self._verdict = verdict
        self._kinds = kinds or {"url", "domain", "ip"}
        self.lookups = []

    @property
    def kinds(self):
        return self._kinds

    def lookup(self, indicator, kind):
        self.lookups.append((indicator, kind))
        return self._verdict

    def health(self):
        return True


def test_critical_1_reputation_service_rejects_non_commercial_feed():
    """ReputationService must reject feeds with commercial_ok=False."""
    feed = _StubFeed("vt-public", commercial_ok=False)
    with pytest.raises(PermissionError):
        ReputationService(feeds=[feed])


def test_critical_1_reputation_service_rejects_non_bool_commercial_ok():
    """ReputationService must reject feeds with commercial_ok that is not True."""
    feed = _StubFeed("vt-public", commercial_ok="false")
    with pytest.raises(PermissionError):
        ReputationService(feeds=[feed])


def test_critical_1_reputation_service_accepts_commercial_feed():
    """ReputationService must accept feeds with commercial_ok=True."""
    feed = _StubFeed("phishtank", commercial_ok=True)
    svc = ReputationService(feeds=[feed])
    assert len(svc.feeds) == 1


def test_critical_1_reputation_service_with_ingestor():
    """ReputationService must work with a FeedIngestor."""
    ingestor = FeedIngestor(tier="production")
    feed = _StubFeed("phishtank", commercial_ok=True)
    ingestor.register(feed)
    ingestor.enable("phishtank")
    svc = ReputationService(feeds=ingestor)
    assert len(svc.feeds) == 1


def test_critical_1_reputation_service_with_ingestor_dev_tier():
    """ReputationService with FeedIngestor in dev tier allows non-commercial feeds."""
    ingestor = FeedIngestor(tier="dev")
    feed = _StubFeed("vt-public", commercial_ok=False)
    ingestor.register(feed)
    ingestor.enable("vt-public")
    svc = ReputationService(feeds=ingestor)
    assert len(svc.feeds) == 1


# ===========================================================================
# CRITICAL #2: One failing feed kills the whole check
# ===========================================================================

def test_critical_2_failing_feed_does_not_kill_check():
    """If one feed raises, the healthy feed's verdict must still be returned."""

    class _FailingFeed:
        id = "failing"
        commercial_ok = True
        kinds = {"url"}

        def lookup(self, indicator, kind):
            raise RuntimeError("feed is down")

        def health(self):
            return False

    healthy = _StubFeed("healthy", FeedVerdict("malicious", "phishing", 0.9, "healthy"))
    svc = ReputationService(feeds=[_FailingFeed(), healthy])
    r = svc.check("https://bad.example/", "url")
    assert r.verdict == "malicious"
    assert r.sources == ["healthy"]


def test_critical_2_all_failing_feeds_returns_unknown():
    """If all feeds fail, the result must be unknown, not an exception."""

    class _FailingFeed:
        id = "failing"
        commercial_ok = True
        kinds = {"url"}

        def lookup(self, indicator, kind):
            raise RuntimeError("feed is down")

        def health(self):
            return False

    svc = ReputationService(feeds=[_FailingFeed(), _FailingFeed()])
    r = svc.check("https://bad.example/", "url")
    assert r.verdict == "unknown"


# ===========================================================================
# CRITICAL #3: Feeds aren't routed by indicator kind
# ===========================================================================

def test_critical_3_feeds_have_kinds_capability():
    """Each feed must declare which indicator kinds it supports."""
    assert "ip" in AbuseIPDBFeed(api_key="k").kinds
    assert "url" in PhishTankFeed(api_key="k").kinds
    assert "domain" in PhishTankFeed(api_key="k").kinds
    assert "url" in MISPFeed(url="https://misp.example", api_key="k").kinds
    assert "domain" in MISPFeed(url="https://misp.example", api_key="k").kinds
    assert "ip" in MISPFeed(url="https://misp.example", api_key="k").kinds


def test_critical_3_abuseipdb_does_not_get_urls():
    """AbuseIPDB must not be queried for URL indicators."""
    feed = _StubFeed("abuseipdb", kinds={"ip"})
    svc = ReputationService(feeds=[feed])
    svc.check("https://bad.example/", "url")
    assert len(feed.lookups) == 0


def test_critical_3_phishtank_does_not_get_ips():
    """PhishTank must not be queried for IP indicators."""
    feed = _StubFeed("phishtank", kinds={"url", "domain"})
    svc = ReputationService(feeds=[feed])
    svc.check("1.2.3.4", "ip")
    assert len(feed.lookups) == 0


def test_critical_3_misp_gets_all_kinds():
    """MISP must be queried for all indicator kinds."""
    feed = _StubFeed("misp", kinds={"url", "domain", "ip"})
    svc = ReputationService(feeds=[feed])
    svc.check("https://bad.example/", "url")
    svc.check("bad.example", "domain")
    svc.check("1.2.3.4", "ip")
    assert len(feed.lookups) == 3


# ===========================================================================
# HIGH #4: MISP returns "malicious" for almost any response
# ===========================================================================

def _json_response(payload, status=200):
    req = httpx.Request("POST", "https://example.com")
    return httpx.Response(status, json=payload, request=req)


def test_high_4_misp_empty_attribute_list_returns_none():
    """MISP must return None when the Attribute list is empty."""
    def fake_post(url, **kw):
        return _json_response({"response": {"Attribute": []}})

    import chc.feeds.misp as misp_module
    original = misp_module.httpx.post
    misp_module.httpx.post = fake_post
    try:
        feed = MISPFeed(url="https://misp.example", api_key="k")
        v = feed.lookup("good.example", "domain")
        assert v is None
    finally:
        misp_module.httpx.post = original


def test_high_4_misp_nonempty_attribute_list_returns_malicious():
    """MISP must return malicious when the Attribute list is non-empty."""
    def fake_post(url, **kw):
        return _json_response({"response": {"Attribute": [{"type": "domain", "to_ids": True}]}})

    import chc.feeds.misp as misp_module
    original = misp_module.httpx.post
    misp_module.httpx.post = fake_post
    try:
        feed = MISPFeed(url="https://misp.example", api_key="k")
        v = feed.lookup("bad.example", "domain")
        assert v is not None
        assert v.verdict == "malicious"
    finally:
        misp_module.httpx.post = original


# ===========================================================================
# HIGH #5: MISP restSearch needs POST + JSON body
# ===========================================================================

def test_high_5_misp_uses_post_with_json_body():
    """MISP restSearch must use POST with a JSON body, not GET with params."""
    captured = {}

    def fake_post(url, **kw):
        captured["url"] = url
        captured["json"] = kw.get("json")
        return _json_response({"response": {"Attribute": []}})

    import chc.feeds.misp as misp_module
    original = misp_module.httpx.post
    misp_module.httpx.post = fake_post
    try:
        feed = MISPFeed(url="https://misp.example", api_key="k")
        feed.lookup("bad.example", "domain")
        assert captured["url"] == "https://misp.example/attributes/restSearch"
        assert captured["json"] is not None
        assert "value" in captured["json"]
    finally:
        misp_module.httpx.post = original


# ===========================================================================
# HIGH #6: PhishTank wrong response fields
# ===========================================================================

def test_high_6_phishtank_uses_in_database_and_valid():
    """PhishTank must use in_database and valid, not in_db and verified."""
    captured = {}

    def fake_post(url, **kw):
        captured["url"] = url
        return _json_response({
            "results": {
                "in_database": True,
                "valid": True,
                "verified": True,
            }
        })

    import chc.feeds.phishtank as pt_module
    original = pt_module.httpx.post
    pt_module.httpx.post = fake_post
    try:
        feed = PhishTankFeed(api_key="k")
        v = feed.lookup("https://bad.example/", "url")
        assert v is not None
        assert v.verdict == "malicious"
    finally:
        pt_module.httpx.post = original


def test_high_6_phishtank_in_db_but_not_valid_returns_clean():
    """PhishTank must return clean when in_database=True but valid=False."""
    def fake_post(url, **kw):
        return _json_response({
            "results": {
                "in_database": True,
                "valid": False,
                "verified": True,
            }
        })

    import chc.feeds.phishtank as pt_module
    original = pt_module.httpx.post
    pt_module.httpx.post = fake_post
    try:
        feed = PhishTankFeed(api_key="k")
        v = feed.lookup("https://bad.example/", "url")
        assert v is not None
        assert v.verdict == "clean"
    finally:
        pt_module.httpx.post = original


def test_high_6_phishtank_not_in_db_returns_clean():
    """PhishTank must return clean when in_database=False."""
    def fake_post(url, **kw):
        return _json_response({
            "results": {
                "in_database": False,
                "valid": False,
            }
        })

    import chc.feeds.phishtank as pt_module
    original = pt_module.httpx.post
    pt_module.httpx.post = fake_post
    try:
        feed = PhishTankFeed(api_key="k")
        v = feed.lookup("https://good.example/", "url")
        assert v is not None
        assert v.verdict == "clean"
    finally:
        pt_module.httpx.post = original


# ===========================================================================
# HIGH #7: Other IPv4 spellings bypass the guard
# ===========================================================================

@pytest.mark.parametrize("bad", [
    "http://2130706433/x",           # decimal
    "http://0x7f.0.0.1/x",           # hex
    "http://0177.0.0.1/x",           # octal
    "http://127.1/x",                # short form
])
def test_high_7_rejects_alternative_ipv4_spellings(bad):
    """Must reject decimal, hex, octal, and short-form IPv4 spellings."""
    with pytest.raises(ValueError):
        normalize_url(bad)


# ===========================================================================
# HIGH #8: IPv6-embedded IPv4 bypasses the guard
# ===========================================================================

@pytest.mark.parametrize("bad", [
    "http://[::ffff:127.0.0.1]/x",    # IPv4-mapped
    "http://[::ffff:a9fe:a9fe]/x",    # IPv4-mapped (metadata)
    "http://[::127.0.0.1]/x",        # IPv4-compatible
    "http://[64:ff9b::7f00:1]/x",     # NAT64
    "http://[2002:7f00:1::]/x",      # 6to4
    "http://[::]/x",                 # unspecified
])
def test_high_8_rejects_ipv6_embedded_ipv4(bad):
    """Must reject IPv6-embedded IPv4 and other non-global IPv6."""
    with pytest.raises(ValueError):
        normalize_url(bad)


# ===========================================================================
# HIGH #9: kind=None or 'ip' skips validation
# ===========================================================================

def test_high_9_kind_none_validates_url():
    """kind=None with a URL must be validated."""
    feed = _StubFeed("a", FeedVerdict("malicious", "phishing", 0.9, "a"))
    svc = ReputationService(feeds=[feed])
    with pytest.raises(ValueError):
        svc.check("http://169.254.169.254/", None)


def test_high_9_kind_none_validates_ip():
    """kind=None with a private IP must be rejected."""
    feed = _StubFeed("a", FeedVerdict("malicious", "phishing", 0.9, "a"))
    svc = ReputationService(feeds=[feed])
    with pytest.raises(ValueError):
        svc.check("10.0.0.1", None)


def test_high_9_kind_ip_validates():
    """kind='ip' must validate the IP."""
    feed = _StubFeed("a", FeedVerdict("malicious", "phishing", 0.9, "a"))
    svc = ReputationService(feeds=[feed])
    with pytest.raises(ValueError):
        svc.check("10.0.0.1", "ip")


def test_high_9_kind_ip_accepts_public():
    """kind='ip' must accept a public IP."""
    feed = _StubFeed("a", FeedVerdict("malicious", "phishing", 0.9, "a"))
    svc = ReputationService(feeds=[feed])
    r = svc.check("1.2.3.4", "ip")
    assert r.verdict == "malicious"


def test_high_9_kind_none_infers_url():
    """kind=None with a URL must infer kind='url'."""
    feed = _StubFeed("a", FeedVerdict("malicious", "phishing", 0.9, "a"))
    svc = ReputationService(feeds=[feed])
    r = svc.check("https://bad.example/", None)
    assert r.verdict == "malicious"
    assert feed.lookups[0][1] == "url"


def test_high_9_kind_none_infers_ip():
    """kind=None with an IP must infer kind='ip'."""
    feed = _StubFeed("a", FeedVerdict("malicious", "phishing", 0.9, "a"))
    svc = ReputationService(feeds=[feed])
    r = svc.check("1.2.3.4", None)
    assert r.verdict == "malicious"
    assert feed.lookups[0][1] == "ip"


def test_high_9_kind_none_infers_domain():
    """kind=None with a domain must infer kind='domain'."""
    feed = _StubFeed("a", FeedVerdict("malicious", "phishing", 0.9, "a"))
    svc = ReputationService(feeds=[feed])
    r = svc.check("bad.example", None)
    assert r.verdict == "malicious"
    assert feed.lookups[0][1] == "domain"


# ===========================================================================
# SSRF regression tests (#44)
# ===========================================================================

@pytest.mark.parametrize("bad", [
    # decimal/hex/octal/short IPv4
    "http://2130706433/",
    "http://0x7f.0.0.1/",
    "http://0177.0.0.1/",
    "http://127.1/",
    # mapped/NAT64/6to4/:: IPv6
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:a9fe:a9fe]/",
    "http://[::127.0.0.1]/",
    "http://[64:ff9b::7f00:1]/",
    "http://[2002:7f00:1::]/",
    "http://[::]/",
    # CGNAT
    "http://100.64.0.1/",
    "http://100.127.255.255/",
    # boundaries
    "http://172.16.0.1/",
    "http://172.31.255.255/",
    # multicast and broadcast
    "http://224.0.0.1/",
    "http://240.0.0.1/",
    "http://255.255.255.255/",
    # TEST-NETs
    "http://192.0.2.1/",
    "http://198.51.100.1/",
    "http://203.0.113.1/",
    # IPv6 reserved
    "http://[fe80::1]/",
    "http://[fc00::1]/",
    "http://[fd00::1]/",
    "http://[ff00::1]/",
    "http://[fec0::1]/",
    "http://[2001:db8::1]/",
    "http://[100::1]/",
    # ports on private IPs
    "http://127.0.0.1:8080/",
    "http://10.0.0.1:443/",
])
def test_ssrf_regression_rejects_private_targets(bad):
    """SSRF regression: all these must be rejected."""
    with pytest.raises(ValueError):
        normalize_url(bad)


@pytest.mark.parametrize("bad", [
    # domain cases
    "2130706433",
    "0x7f.0.0.1",
    "0177.0.0.1",
    "127.1",
    "a..b",
    "-example.com",
    "example-.com",
])
def test_ssrf_regression_rejects_bad_domains(bad):
    """SSRF regression: bad domain indicators must be rejected."""
    with pytest.raises(ValueError):
        normalize_domain(bad)


@pytest.mark.parametrize("good", [
    # public IPs
    "http://1.2.3.4/",
    "http://8.8.8.8/",
    "http://172.32.0.1/",
    "http://172.15.255.255/",
    # public IPv6
    "http://[2001:4860:4860::8888]/",
    "http://[2606:4700::1]/",
    # domains
    "https://example.com/",
    "https://sub.example.com/path",
])
def test_ssrf_regression_accepts_public_targets(good):
    """SSRF regression: public targets must be accepted."""
    result = normalize_url(good)
    assert result  # should not raise
