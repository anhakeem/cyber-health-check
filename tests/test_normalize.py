"""TDD: normalize_url / normalize_domain — RED phase.

SSRF-safe by construction: reject non-http(s) schemes, strip
credentials/fragments, reject private/loopback/link-local/metadata IPs.
"""
import pytest

from chc.reputation import normalize_domain, normalize_url


# --- scheme rejection -------------------------------------------------------

@pytest.mark.parametrize("bad", [
    "javascript:alert(1)",
    "file:///etc/passwd",
    "data:text/html,<script>1</script>",
    "ftp://example.com/x",
    "vbscript:msgbox(1)",
    "  javascript:alert(1)",
])
def test_normalize_url_rejects_non_http_schemes(bad):
    with pytest.raises(ValueError):
        normalize_url(bad)


def test_normalize_url_rejects_missing_scheme():
    with pytest.raises(ValueError):
        normalize_url("example.com/path")


# --- credential + fragment stripping ---------------------------------------

def test_normalize_url_strips_credentials():
    assert normalize_url("https://user:pass@example.com/x") == "https://example.com/x"


def test_normalize_url_strips_fragment():
    assert normalize_url("https://example.com/x#frag") == "https://example.com/x"


def test_normalize_url_strips_credentials_and_fragment():
    assert normalize_url("https://u:p@example.com/x?q=1#f") == "https://example.com/x?q=1"


def test_normalize_url_keeps_path_and_query():
    assert normalize_url("https://example.com/a/b?x=1&y=2") == "https://example.com/a/b?x=1&y=2"


def test_normalize_url_normalizes_host_case():
    assert normalize_url("HTTPS://EXAMPLE.com/Path") == "https://example.com/Path"


# --- private IP rejection ---------------------------------------------------

@pytest.mark.parametrize("bad", [
    "http://127.0.0.1/x",
    "http://10.0.0.5/x",
    "http://192.168.1.1/x",
    "http://172.16.0.1/x",
    "http://169.254.169.254/latest/meta-data",
    "http://0.0.0.0/x",
    "http://[::1]/x",
    "http://[fe80::1]/x",
])
def test_normalize_url_rejects_private_ips(bad):
    with pytest.raises(ValueError):
        normalize_url(bad)


# --- domain normalization ---------------------------------------------------

def test_normalize_domain_strips_scheme_and_path():
    assert normalize_domain("https://example.com/path?q=1") == "example.com"


def test_normalize_domain_strips_credentials():
    assert normalize_domain("https://user:pass@example.com/") == "example.com"


def test_normalize_domain_strips_leading_dot():
    assert normalize_domain(".example.com") == "example.com"


def test_normalize_domain_rejects_non_http_scheme():
    with pytest.raises(ValueError):
        normalize_domain("javascript:alert(1)")


def test_normalize_domain_rejects_private_ip():
    with pytest.raises(ValueError):
        normalize_domain("127.0.0.1")


def test_normalize_domain_rejects_empty():
    with pytest.raises(ValueError):
        normalize_domain("")
