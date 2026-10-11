"""Feed abstraction: ThreatFeed protocol + FeedVerdict dataclass."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

Verdict = Literal["malicious", "suspicious", "clean", "unknown"]
IndicatorKind = Literal["url", "domain", "ip"]


@dataclass(frozen=True)
class FeedVerdict:
    verdict: Verdict
    category: str | None = None
    confidence: float = 0.0
    source: str | None = None


@runtime_checkable
class ThreatFeed(Protocol):
    id: str
    commercial_ok: bool
    kinds: frozenset[IndicatorKind]

    def lookup(self, indicator: str, kind: IndicatorKind) -> FeedVerdict | None: ...

    def health(self) -> bool: ...
