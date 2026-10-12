// Cyber Health Check — browser API compatibility shim.
//
// Chrome exposes `chrome.*` (callback style); Firefox exposes `browser.*`
// (promise style) and aliases `chrome`. This gives one promise-based helper
// that works in both. Loaded before the other scripts in the Firefox build.

const api = (typeof browser !== "undefined" && browser.runtime) ? browser : chrome;

const ext = {
  isFirefox: typeof browser !== "undefined" && !!browser.runtime,

  async storageGet(keys) {
    if (ext.isFirefox) return api.storage.local.get(keys);
    return new Promise((resolve) => api.storage.local.get(keys, resolve));
  },

  async storageSet(obj) {
    if (ext.isFirefox) return api.storage.local.set(obj);
    return new Promise((resolve) => api.storage.local.set(obj, resolve));
  },

  sendMessage(msg) {
    if (ext.isFirefox) return api.runtime.sendMessage(msg);
    return new Promise((resolve) => {
      api.runtime.sendMessage(msg, (resp) => {
        if (api.runtime.lastError) resolve(null);
        else resolve(resp);
      });
    });
  },

  sendToTab(tabId, msg) {
    if (ext.isFirefox) return api.tabs.sendMessage(tabId, msg);
    return new Promise((resolve) => {
      api.tabs.sendMessage(tabId, msg, (resp) => {
        if (api.runtime.lastError) resolve(null);
        else resolve(resp);
      });
    });
  },

  setBadge(tabId, text, color) {
    if (api.action && api.action.setBadgeText) {
      api.action.setBadgeText({ tabId, text });
      if (color) api.action.setBadgeBackgroundColor({ tabId, color });
    } else if (api.browserAction) {
      // Firefox MV2-style fallback
      api.browserAction.setBadgeText({ tabId, text });
      if (color) api.browserAction.setBadgeBackgroundColor({ tabId, color });
    }
  },

  // Register a message listener. The listener MUST return true for async
  // responses in both browsers; this is a straight passthrough.
  onMessage(handler) {
    api.runtime.onMessage.addListener(handler);
  },
};
