// Cyber Health Check — popup controller.

const $ = (id) => document.getElementById(id);

// Firefox rejects when the background can't answer; Chrome resolves null.
// Normalise to null so the UI falls back to its error/offline states.
function send(msg) {
  return ext.sendMessage(msg).catch(() => null);
}

function timeAgo(ms) {
  const s = Math.floor((Date.now() - ms) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

async function currentTabUrl() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  return tab?.url || "";
}

async function renderVerdict() {
  const url = await currentTabUrl();
  $("url").textContent = url;
  if (!url.startsWith("http")) {
    $("verdict").innerHTML = '<div class="v">—</div><div class="u">Not a web page.</div>';
    return;
  }
  const resp = await send({ type: "CHECK_URL", url });
  const box = $("verdict");
  if (!resp?.ok) {
    box.className = "verdict";
    box.innerHTML = `<div class="v error">Error</div><div class="u">${resp?.error || "check failed"}</div>`;
    return;
  }
  const d = resp.data;
  box.className = `verdict ${d.verdict}`;
  box.innerHTML =
    `<div class="v">${d.verdict.toUpperCase()}</div>` +
    `<div class="u">${d.category ? d.category + " · " : ""}confidence ${(d.confidence * 100).toFixed(0)}%` +
    `${d.sources?.length ? " · " + d.sources.join(", ") : ""}</div>`;
}

async function renderAlerts() {
  const resp = await send({ type: "GET_ALERTS" });
  const alerts = resp?.alerts || [];
  const box = $("alerts");
  if (!alerts.length) {
    box.innerHTML = '<div class="empty">No alerts yet.</div>';
    return;
  }
  box.innerHTML = alerts
    .slice(0, 12)
    .map(
      (a) =>
        `<div class="alert ${a.verdict}"><div class="i">${a.indicator}</div>` +
        `<div class="t">${a.verdict}${a.category ? " · " + a.category : ""} · ${timeAgo(a.at)}</div></div>`
    )
    .join("");
}

async function checkHealth() {
  const resp = await send({ type: "HEALTH" });
  $("badge").textContent = resp?.ok ? "API online" : "API offline";
}

renderVerdict();
renderAlerts();
checkHealth();
