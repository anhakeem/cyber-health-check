"""Real extension load test for Cyber Health Check (opt-in).

Launches Chromium with the unpacked MV3 extension, verifies the service worker
registers, and exercises the CHECK_URL flow against a live stub API.

Run: RUN_EXTENSION_TESTS=1 DISPLAY=:0 pytest tests/test_extension_load.py -q -s
"""
from __future__ import annotations

import http.server
import json
import os
import socketserver
import threading
from pathlib import Path

import pytest

pytest.importorskip("playwright")

if not os.environ.get("RUN_EXTENSION_TESTS"):
    pytest.skip(
        "extension load test is opt-in; set RUN_EXTENSION_TESTS=1 to run",
        allow_module_level=True,
    )

EXT_DIR = Path(__file__).resolve().parent.parent / "extension"


class _StubHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/api/v1/health"):
            self._json(200, {"status": "ok"})
        else:
            self._json(404, {"error": {"code": "NOT_FOUND", "message": "no"}})

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.end_headers()

    def do_POST(self):
        if self.path.startswith("/api/v1/check-url"):
            self._json(200, {
                "indicator": "https://bad.example/login", "verdict": "malicious",
                "category": "phishing", "confidence": 0.97,
                "sources": ["phishtank", "misp"], "cached": False,
            })
        else:
            self._json(404, {"error": {"code": "NOT_FOUND", "message": "no"}})


@pytest.fixture(scope="module")
def stub_api():
    class _Server(socketserver.TCPServer):
        allow_reuse_address = True

    with _Server(("127.0.0.1", 0), _StubHandler) as srv:
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        yield f"http://127.0.0.1:{port}"
        srv.shutdown()


def test_extension_loads_and_checks_url(stub_api):
    from playwright.sync_api import sync_playwright

    assert EXT_DIR.exists(), f"extension dir missing: {EXT_DIR}"
    user_data = "/home/hermes/.hermes/cache/scratch/pw-chc-profile"

    with sync_playwright() as p:
        ctx = p.chromium.launch_persistent_context(
            user_data, headless=False,
            args=[
                f"--disable-extensions-except={EXT_DIR}",
                f"--load-extension={EXT_DIR}",
                "--no-first-run",
            ],
        )
        try:
            sw = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event(
                "serviceworker", timeout=15000
            )
            ext_id = sw.url.split("/")[2]
            print(f"\n[ext] service worker registered: {sw.url}")

            popup = ctx.new_page()
            popup.goto(f"chrome-extension://{ext_id}/popup.html")
            popup.wait_for_load_state("domcontentloaded")
            assert popup.query_selector("#verdict") is not None

            result = popup.evaluate(
                """(api) => new Promise((resolve) => {
                    chrome.storage.local.set({ apiBase: api }, () => {
                        chrome.runtime.sendMessage(
                            { type: 'CHECK_URL', url: 'https://bad.example/login' },
                            (resp) => resolve(resp)
                        );
                    });
                })""",
                stub_api,
            )
            print(f"[ext] CHECK_URL response: {result}")
            assert result and result.get("ok"), f"check failed: {result}"
            assert result["data"]["verdict"] == "malicious"
        finally:
            ctx.close()
