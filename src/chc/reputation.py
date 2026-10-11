"""Reputation service: normalize indicators, SSRF-safe by construction.

This module NEVER fetches the target URL. Reputation is resolved from
feeds/cache only. The normalize helpers are the SSRF guard: they reject
non-http(s) schemes, strip credentials/fragments, and reject private,
loopback, link-local, CGNAT, and metadata IPs.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import struct
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
    ipaddress.ip_network("192.0.0.0/24"),   # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),   # TEST-NET-1
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),    # multicast
    ipaddress.ip_network("240.0.0.0/4"),    # reserved
    ipaddress.ip_network("255.255.255.255/32"),  # broadcast
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("fec0::/10"),
    ipaddress.ip_network("2001:db8::/32"),  # documentation
    ipaddress.ip_network("100::/64"),       # discard-only
]

_METADATA_IPS = {"169.254.169.254"}


def _parse_ipv4_alternative(host: str) -> ipaddress.IPv4Address | None:
    """Try to parse alternative IPv4 spellings (decimal, hex, octal, short).

    Returns the IPv4Address if the host is a valid alternative spelling,
    or None if it's not an IP literal at all.
    """
    # Strict dotted quad — already handled by ipaddress.ip_address
    try:
        ip = ipaddress.ip_address(host)
        if isinstance(ip, ipaddress.IPv4Address):
            return ip
    except ValueError:
        pass

    # Decimal integer: "2130706433"
    if re.fullmatch(r"\d+", host):
        try:
            return ipaddress.ip_address(int(host))
        except (ValueError, struct.error):
            pass

    # Mixed octets: "0x7f.0.0.1", "0177.0.0.1", "127.1", etc.
    # Each part can be decimal, hex (0x...), or octal (0...).
    if re.fullmatch(r"[0-9a-fA-Fx.]+", host) and "." in host:
        try:
            parts = host.split(".")
            if len(parts) > 4:
                return None
            octets = []
            for p in parts:
                if p.startswith("0x") or p.startswith("0X"):
                    val = int(p, 16)
                elif len(p) > 1 and p.startswith("0"):
                    val = int(p, 8)
                else:
                    val = int(p)
                if val < 0 or val > 255:
                    return None
                octets.append(val)
            # Pad short forms: "127.1" -> [127, 0, 0, 1]
            while len(octets) < 4:
                octets.insert(-1, 0)
            if len(octets) == 4:
                return ipaddress.IPv4Address(".".join(str(o) for o in octets))
        except (ValueError, struct.error):
            pass

    return None


def _is_private_host(host: str) -> bool:
    host = host.strip("[]").lower()
    if host in _METADATA_IPS:
        return True

    # Try strict IP parse first
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Try alternative IPv4 spellings
        alt_ip = _parse_ipv4_alternative(host)
        if alt_ip is not None:
            ip = alt_ip
        else:
            return False  # DNS name, not an IP literal

    # Unwrap IPv6-embedded IPv4
    if isinstance(ip, ipaddress.IPv6Address):
        # IPv4-mapped: ::ffff:a.b.c.d
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        # 6to4: 2002:aabb:ccdd::/48
        elif ip.sixtofour is not None:
            ip = ip.sixtofour
        # Teredo: 2001:0000:server:client
        elif ip.teredo is not None:
            server, client = ip.teredo
            if not server.is_global or not client.is_global:
                return True
        # NAT64: 64:ff9b::/96
        elif ip.packed[:12] == b"\x00\x64\xff\x9b" + b"\x00" * 8:
            embedded = ipaddress.ip_address(ip.packed[12:])
            if isinstance(embedded, ipaddress.IPv4Address) and not embedded.is_global:
                return True
        # IPv4-compatible: ::/96 (deprecated)
        elif ip.packed[:12] == b"\x00" * 12:
            embedded = ipaddress.ip_address(ip.packed[12:])
            if isinstance(embedded, ipaddress.IPv4Address) and not embedded.is_global:
                return True

    # Reject anything that isn't a global IP
    if not ip.is_global:
        return True

    # Also check against our explicit denylist
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
    # Validate each label
    labels = host.split(".")
    for label in labels:
        if not label or len(label) > 63:
            raise ValueError(f"invalid domain indicator {raw!r}")
        if label.startswith("-") or label.endswith("-"):
            raise ValueError(f"invalid domain indicator {raw!r}")
        if not re.fullmatch(r"[a-z0-9\-]+", label):
            raise ValueError(f"invalid domain indicator {raw!r}")
    # Reject alternative IPv4 spellings and private IPs
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
        # Accept either a FeedIngestor or an iterable of feeds
        if hasattr(feeds, "enabled"):
            # FeedIngestor has already enforced commercial_ok gating
            feed_list = list(feeds.enabled())
        else:
            feed_list = list(feeds)
            # Enforce commercial_ok gating: every feed must have commercial_ok is True
            for feed in feed_list:
                if feed.commercial_ok is not True:
                    raise PermissionError(
                        f"feed {feed.id!r} has commercial_ok={feed.commercial_ok!r}; "
                        f"only commercial_ok=True feeds are allowed"
                    )
        self.feeds = feed_list
        self.ttl = ttl
        self._clock = clock
        self._cache: dict[tuple[str, str], tuple[MergedVerdict, float]] = {}

    def check(self, indicator: str, kind: IndicatorKind | None = None) -> MergedVerdict:
        # Infer kind if not provided
        if kind is None:
            kind = kind_of(indicator)

        # Validate based on kind
        if kind == "url":
            indicator = normalize_url(indicator)
        elif kind == "domain":
            indicator = normalize_domain(indicator)
        elif kind == "ip":
            # Validate as IP — reject private/reserved
            try:
                ip = ipaddress.ip_address(indicator)
            except ValueError:
                raise ValueError(f"invalid IP indicator {indicator!r}")
            if not ip.is_global:
                raise ValueError(f"IP {indicator!r} is not a global address")
            # Also check against denylist
            if any(ip in net for net in _PRIVATE_NETS):
                raise ValueError(f"IP {indicator!r} is in a reserved range")
        else:
            raise ValueError(f"unknown indicator kind {kind!r}")

        key = (kind, indicator)
        now = self._clock()
        if key in self._cache:
            verdict, expires = self._cache[key]
            if now < expires:
                return replace(verdict, cached=True)

        # Query only feeds that support this kind, with failure isolation
        feed_verdicts = []
        for f in self.feeds:
            # Check if feed supports this kind
            feed_kinds = getattr(f, "kinds", None)
            if feed_kinds is not None and kind not in feed_kinds:
                continue
            try:
                v = f.lookup(indicator, kind)
                if v is not None:
                    feed_verdicts.append(v)
            except Exception:
                # Isolate feed failures — one bad feed must not kill the check
                continue

        merged = merge_verdicts(feed_verdicts)
        self._cache[key] = (merged, now + self.ttl)
        return merged
