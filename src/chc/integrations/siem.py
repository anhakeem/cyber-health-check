"""SIEM exporters — Splunk HEC and syslog/CEF (architecture §2, enterprise phase).

Each exporter takes a list of event dicts and returns the number sent. Network
I/O is injected (`post` / `send`) so the exporters are testable without a real
SIEM, and so the caller controls transport, retries, and auth.
"""
from __future__ import annotations

import logging
from typing import Callable

log = logging.getLogger(__name__)

_CEF_VENDOR = "CyberHealthCheck"
_CEF_PRODUCT = "BrowserSecurity"
_CEF_VERSION = "1.0"

_SEVERITY_TO_CEF = {"low": 3, "medium": 5, "high": 8, "critical": 10}


def _escape_cef(value: str) -> str:
    """CEF extension values must escape backslash, pipe, and equals."""
    return (str(value)
            .replace("\\", "\\\\")
            .replace("|", "\\|")
            .replace("=", "\\=")
            .replace("\n", " "))


def to_cef(event: dict) -> str:
    """Render an event as a CEF line (ArcSight Common Event Format)."""
    sev = _SEVERITY_TO_CEF.get(str(event.get("severity", "low")).lower(), 3)
    name = _escape_cef(event.get("action", "event"))
    ext = {
        "src": event.get("indicator", ""),
        "request": event.get("indicator", ""),
        "act": event.get("action", ""),
        "suser": event.get("actor", ""),
        "cs1Label": "verdict",
        "cs1": event.get("verdict", ""),
        "cs2Label": "category",
        "cs2": event.get("category", ""),
    }
    ext_str = " ".join(f"{k}={_escape_cef(v)}" for k, v in ext.items())
    return f"CEF:0|{_CEF_VENDOR}|{_CEF_PRODUCT}|{_CEF_VERSION}|{name}|{name}|{sev}|{ext_str}"


class SplunkHecExporter:
    """Sends events to a Splunk HTTP Event Collector endpoint."""

    def __init__(self, hec_url: str, token: str, post: Callable | None = None,
                 timeout: float = 10.0, source: str = "cyber-health-check") -> None:
        self._url = hec_url.rstrip("/") + "/services/collector/event"
        self._token = token
        self._source = source
        self._timeout = timeout
        if post is None:
            import httpx

            def post(url, json=None, headers=None, timeout=None):  # noqa: A002
                return httpx.post(url, json=json, headers=headers, timeout=timeout)

        self._post = post

    def export(self, events: list[dict]) -> int:
        sent = 0
        for ev in events:
            try:
                resp = self._post(
                    self._url,
                    json={"event": ev, "source": self._source},
                    headers={"Authorization": f"Splunk {self._token}"},
                    timeout=self._timeout,
                )
                resp.raise_for_status()
                sent += 1
            except Exception as exc:  # noqa: BLE001 — one bad event must not stop the batch
                log.warning("splunk export failed (%s)", type(exc).__name__)
        return sent


class SyslogExporter:
    """Formats events as CEF lines and hands them to a `send` callable.

    `send` is the transport seam — wire it to a syslog socket, a file, or a
    test list. Keeping transport out of this class keeps it dependency-free.
    """

    def __init__(self, send: Callable[[str], None]) -> None:
        self._send = send

    def export(self, events: list[dict]) -> int:
        sent = 0
        for ev in events:
            try:
                self._send(to_cef(ev))
                sent += 1
            except Exception as exc:  # noqa: BLE001
                log.warning("syslog export failed (%s)", type(exc).__name__)
        return sent
