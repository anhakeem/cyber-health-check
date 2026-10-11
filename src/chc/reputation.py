"""Reputation service: normalize indicators, SSRF-safe by construction.

This module NEVER fetches the target URL. Reputation is resolved from
feeds/cache only. The normalize helpers are the SSRF guard: they reject
non-http(s) schemes, strip credentials/fragments, and reject private,
loopback, link-local, CGNAT, and metadata IPs.
"""
from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass, field, replace
from urllib.parse import urlsplit

from chc.feeds.base import FeedVerdict, IndicatorKind, Verdict

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]

_METADATA_IPS = {"169.254.169.254"}


def _is_private_host(host: str) -> bool:
    host = host.strip("[]").lower()
    if host in _METADATA_IPS:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # DNS name, not an IP literal
    return any(ip in net for net in _PRIVATE_NETS)


def _check_scheme(raw: str) -> str:
    # Reject any scheme that isn't http/https, including whitespace tricks.
    m = re.match(r"^\s*([A-Za-z][A-Za-z0-9+.\-]*)://", raw)
    if not m:
        raise ValueError("indicator must be an absolute http(s) URL")
    scheme = m.group(1).lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"scheme {scheme!r} is not allowed; only http(s)")
    return scheme


def normalize_url(raw: str) -> str:
    """Normalize an absolute http(s) URL. Rejects non-http(s) schemes,
    strips credentials and fragments, rejects private-IP literals."""
    scheme = _check_scheme(raw)
    parts = urlsplit(raw.strip())
    host = parts.hostname or ""
    if not host:
        raise ValueError("indicator has no host")
    if _is_private_host(host):
        raise ValueError(f"host {host!r} is a private/reserved address")
    # Rebuild without credentials (username/password) and fragment.
    port = parts.port
    netloc = host
    if port is not None:
        netloc = f"{host}:{port}"
    return f"{scheme}://{netloc}{parts.path}" + (
        f"?{parts.query}" if parts.query else ""
    )


def normalize_domain(raw: str) -> str:
    """Normalize a domain indicator. Accepts a bare domain or an
    http(s) URL; rejects non-http(s) schemes and private-IP literals."""
    s = raw.strip()
    # If it looks like a URL, normalize as URL (which enforces scheme +
    # private-IP rules) and return the bare host.
    if re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*://", s):
        url = normalize_url(s)
        return urlsplit(url).hostname or ""
    # Bare domain: no scheme allowed to sneak in, no credentials.
    if "://" in s or "@" in s or ":" in s:
        raise ValueError("domain indicator must not contain scheme, port, or credentials")
    host = s.split("/")[0].split("?")[0].split("#")[0].lower().lstrip(".")
    if not host or not re.fullmatch(r"[a-z0-9.\-]+", host):
        raise ValueError(f"invalid domain indicator {raw!r}")
    if _is_private_host(host):
        raise ValueError(f"host {host!r} is a private/reserved address")
    return host


def kind_of(indicator: str) -> IndicatorKind:
    """Classify a normalized indicator as url | domain | ip."""
    if indicator.startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_address(indicator)
        return "ip"
    except ValueError:
        return "domain"


# Worst-wins ordering: malicious > suspicious > unknown > clean
_VERDICT_RANK = {"malicious": 3, "suspicious": 2, "unknown": 1, "clean": 0}


@dataclass
class MergedVerdict:
    verdict: Verdict
    category: str | None
    confidence: float
    sources: list[str]
    cached: bool = False


def merge_verdicts(verdicts: list[FeedVerdict]) -> MergedVerdict:
    """Merge feed verdicts worst-wins: malicious > suspicious > unknown > clean."""
    if not verdicts:
        return MergedVerdict(verdict="unknown", category=None, confidence=0.0, sources=[])
    worst = max(verdicts, key=lambda v: (_VERDICT_RANK[v.verdict], v.confidence))
    sources = sorted({v.source for v in verdicts if v.source})
    return MergedVerdict(
        verdict=worst.verdict,
        category=worst.category,
        confidence=worst.confidence,
        sources=sources,
    )


class ReputationService:
    """Resolve reputation from feeds + TTL cache. NEVER fetches the target
    URL — SSRF-safe by construction."""

    def __init__(self, feeds, ttl: float = 3600, clock=time.monotonic):
        self.feeds = list(feeds)
        self.ttl = ttl
        self._clock = clock
        self._cache: dict[tuple[str, str], tuple[MergedVerdict, float]] = {}

    def check(self, indicator: str, kind: IndicatorKind | None = None) -> MergedVerdict:
        if kind == "url":
            indicator = normalize_url(indicator)
        elif kind == "domain":
            indicator = normalize_domain(indicator)
        key = (kind or "unknown", indicator)
        now = self._clock()
        if key in self._cache:
            verdict, expires = self._cache[key]
            if now < expires:
                return replace(verdict, cached=True)
        feed_verdicts = [
            v for f in self.feeds if (v := f.lookup(indicator, kind or "unknown")) is not None
        ]
        merged = merge_verdicts(feed_verdicts)
        self._cache[key] = (merged, now + self.ttl)
        return merged
