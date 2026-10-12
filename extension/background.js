// Cyber Health Check — service worker / background script (MV3).
//
// Owns ALL network calls. Checks each navigated URL against our API's
// reputation service and raises an alert when a verdict is bad.
//
// PRIVACY: only the URL the browser is already navigating to is sent — never
// page content, cookies, or form data (see docs/privacy-threat-model.md).
// State lives in extension storage (the worker is terminated when idle).
//
// Cross-browser: uses the `ext.*` helpers from browser-compat.js. In Chrome the
// shim is imported below; in Firefox the manifest loads it before this file.

if (typeof importScripts === "function") {
  // Chrome service worker: load the compat shim (no-op in Firefox, which
  // already loaded browser-compat.js via the manifest's background.scripts).
  importScripts("browser-compat.js");
}

const DEFAULT_API = "http://localhost:8098";
const CACHE_TTL_MS = 5 * 60 * 1000; // local verdict cache, 5 min

async function getApiBase() {
  const { apiBase } = await ext.storageGet(["apiBase"]);
  return apiBase || DEFAULT_API;
}

function verdictRank(v) {
  return { malicious: 3, suspicious: 2, unknown: 1, clean: 0 }[v] ?? 0;
}

async function localCacheGet(url) {
  const { verdictCache = {} } = await ext.storageGet(["verdictCache"]);
  const entry = verdictCache[url];
  if (entry && Date.now() - entry.at < CACHE_TTL_MS) return entry;
  return null;
}

async function localCachePut(url, verdict) {
  const { verdictCache = {} } = await ext.storageGet(["verdictCache"]);
  verdictCache[url] = { ...verdict, at: Date.now() };
  // Bound the cache so it can't grow without limit.
  const keys = Object.keys(verdictCache);
  if (keys.length > 500) {
    keys.sort((a, b) => verdictCache[a].at - verdictCache[b].at);
    for (const k of keys.slice(0, keys.length - 500)) delete verdictCache[k];
  }
  await ext.storageSet({ verdictCache });
}

async function checkUrl(url) {
  const cached = await localCacheGet(url);
  if (cached) return cached;

  const api = await getApiBase();
  const resp = await fetch(`${api}/api/v1/check-url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data?.error?.message || `check failed (${resp.status})`);
  await localCachePut(url, data);
  return data;
}

async function recordAlert(data, tabId) {
  const { alerts = [] } = await ext.storageGet(["alerts"]);
  alerts.unshift({
    indicator: data.indicator,
    verdict: data.verdict,
    category: data.category || null,
    at: Date.now(),
    tabId,
  });
  await ext.storageSet({ alerts: alerts.slice(0, 200) });
}

function badgeFor(verdict) {
  if (verdict === "malicious") return { text: "!", color: "#fb7185" };
  if (verdict === "suspicious") return { text: "?", color: "#fbbf24" };
  return { text: "", color: "#34d399" };
}

// Listener registered at top level so it exists on service-worker cold start.
ext.onMessage((msg, sender, sendResponse) => {
  if (msg?.type === "CHECK_URL") {
    checkUrl(msg.url)
      .then(async (data) => {
        const tabId = sender.tab?.id;
        if (tabId != null && verdictRank(data.verdict) >= 2) {
          await recordAlert(data, tabId);
          const b = badgeFor(data.verdict);
          ext.setBadge(tabId, b.text, b.color);
        }
        sendResponse({ ok: true, data });
      })
      .catch((err) => sendResponse({ ok: false, error: String(err.message || err) }));
    return true; // async
  }

  if (msg?.type === "HEALTH") {
    getApiBase()
      .then((api) => fetch(`${api}/api/v1/health`))
      .then((r) => sendResponse({ ok: r.ok }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (msg?.type === "GET_ALERTS") {
    ext.storageGet(["alerts"]).then(({ alerts = [] }) =>
      sendResponse({ ok: true, alerts })
    );
    return true;
  }
  return false;
});
