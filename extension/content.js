// Cyber Health Check — content script.
//
// Reports the URL the browser lands on to the service worker for a reputation
// check, and renders a warning banner if the verdict is bad. It NEVER reads
// page content, cookies, or form data — only location.href.

let bannerEl = null;

function showBanner(data) {
  if (bannerEl) bannerEl.remove();
  const malicious = data.verdict === "malicious";
  const color = malicious ? "#7f1d1d" : "#78350f";
  const accent = malicious ? "#fb7185" : "#fbbf24";
  bannerEl = document.createElement("div");
  bannerEl.setAttribute("data-chc-banner", "1");
  bannerEl.style.cssText = [
    "position:fixed", "top:0", "left:0", "right:0", "z-index:2147483647",
    `background:${color}`, "color:#fff", "font:600 13px/1.4 system-ui,sans-serif",
    "padding:10px 14px", "box-shadow:0 2px 10px rgba(0,0,0,.4)", "display:flex",
    "gap:12px", "align-items:center",
  ].join(";");
  const icon = document.createElement("span");
  icon.textContent = malicious ? "⛔" : "⚠️";
  const msg = document.createElement("span");
  msg.textContent = malicious
    ? `Cyber Health Check: this page looks malicious (${data.category || "threat"}). Do not enter credentials.`
    : `Cyber Health Check: this page looks suspicious. Proceed with care.`;
  const close = document.createElement("button");
  close.textContent = "✕";
  close.style.cssText = `margin-left:auto;background:transparent;border:1px solid ${accent};color:#fff;border-radius:6px;cursor:pointer;padding:2px 8px;font:inherit`;
  close.onclick = () => bannerEl && bannerEl.remove();
  bannerEl.append(icon, msg, close);
  document.documentElement.appendChild(bannerEl);
}

function report() {
  const url = location.href;
  if (!url.startsWith("http")) return;
  chrome.runtime.sendMessage({ type: "CHECK_URL", url }, (resp) => {
    if (chrome.runtime.lastError || !resp?.ok) return;
    const v = resp.data?.verdict;
    if (v === "malicious" || v === "suspicious") showBanner(resp.data);
  });
}

report();

// Re-check on SPA navigations (X, YouTube, etc.) without a page reload.
let lastUrl = location.href;
new MutationObserver(() => {
  if (location.href !== lastUrl) {
    lastUrl = location.href;
    report();
  }
}).observe(document, { subtree: true, childList: true });
