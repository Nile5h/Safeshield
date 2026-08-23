// ─────────────────────────────────────────────────────────────────────────────
// SafeShield Background Service Worker
// Handles: URL scan caching, auto-scan, redirect guard, badge management
// ─────────────────────────────────────────────────────────────────────────────

const ANALYZE_URL_API = 'http://127.0.0.1:8000/analyze/url';
const CACHE_TTL_MS    = 10 * 60 * 1000; // 10 minutes
const RISK_THRESHOLD  = 50;
const BLOCKED_PAGE    = chrome.runtime.getURL('blocked.html');

// Internal URL schemes that should never be scanned
const INTERNAL_SCHEMES = ['chrome://', 'chrome-extension://', 'about:', 'data:', 'devtools://'];

// ─── Helpers ─────────────────────────────────────────────────────────────────

function isInternalUrl(url) {
  if (!url) return true;
  return INTERNAL_SCHEMES.some((scheme) => url.startsWith(scheme));
}

function isBlockedPage(url) {
  return url && url.startsWith(BLOCKED_PAGE);
}

/**
 * Read the 10-minute scan cache from chrome.storage.session.
 * Returns the cached result for `url` if fresh, otherwise null.
 */
async function getCachedResult(url) {
  return new Promise((resolve) => {
    chrome.storage.session.get(['safeshieldScanCache'], (data) => {
      const cache = data.safeshieldScanCache || {};
      const entry = cache[url];
      if (entry && Date.now() - entry.timestamp < CACHE_TTL_MS) {
        resolve(entry.result);
      } else {
        resolve(null);
      }
    });
  });
}

/**
 * Write a scan result into the session cache.
 */
async function setCachedResult(url, result) {
  return new Promise((resolve) => {
    chrome.storage.session.get(['safeshieldScanCache'], (data) => {
      const cache = data.safeshieldScanCache || {};
      cache[url] = { timestamp: Date.now(), result };
      chrome.storage.session.set({ safeshieldScanCache: cache }, resolve);
    });
  });
}

/**
 * Check if the user has whitelisted this URL for this session.
 */
async function isWhitelisted(url) {
  return new Promise((resolve) => {
    chrome.storage.local.get(['safeshieldWhitelist'], (data) => {
      const list = data.safeshieldWhitelist || [];
      resolve(list.includes(url));
    });
  });
}

/**
 * Call the SafeShield backend to analyze a URL.
 * Returns the full response JSON or null on network error.
 */
async function fetchUrlAnalysis(url) {
  try {
    const response = await fetch(ANALYZE_URL_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) return null;
    return await response.json();
  } catch {
    // Backend offline or network error — fail open (don't block)
    return null;
  }
}

// ─── Badge helpers ────────────────────────────────────────────────────────────

function setBadgeDanger(tabId) {
  chrome.action.setBadgeText({ tabId, text: '!' });
  chrome.action.setBadgeBackgroundColor({ tabId, color: '#ef4444' });
}

function setBadgeSafe(tabId) {
  chrome.action.setBadgeText({ tabId, text: '✓' });
  chrome.action.setBadgeBackgroundColor({ tabId, color: '#34d399' });
}

function clearBadge(tabId) {
  chrome.action.setBadgeText({ tabId, text: '' });
}

// ─── Core scan + redirect logic ───────────────────────────────────────────────

/**
 * Analyze a URL for the given tab. If the verdict is dangerous,
 * redirect the tab to the blocked interstitial page.
 */
async function scanAndGuard(tabId, url) {
  if (isInternalUrl(url) || isBlockedPage(url)) {
    clearBadge(tabId);
    return;
  }

  // Don't re-block a URL the user has already whitelisted
  const whitelisted = await isWhitelisted(url);
  if (whitelisted) {
    setBadgeSafe(tabId);
    return;
  }

  // Check session cache first
  let result = await getCachedResult(url);

  if (!result) {
    result = await fetchUrlAnalysis(url);
    if (result) await setCachedResult(url, result);
  }

  if (!result) {
    // No result from backend — clear badge and move on
    clearBadge(tabId);
    return;
  }

  const { verdict, risk_score, reasons = [] } = result;
  const isDangerous = verdict === 'FRAUD' || Number(risk_score) >= RISK_THRESHOLD;

  if (isDangerous) {
    setBadgeDanger(tabId);

    const breakdown = result.scoring_breakdown || {};
    const params = new URLSearchParams({
      url,
      score: String(risk_score),
      reasons: reasons.join('||'),
      tier: breakdown.tier_label || (verdict === 'FRAUD' ? 'TIER 1: LIVE DYNAMIC' : 'TIER 2: STATIC FALLBACK'),
      summary: breakdown.summary || '',
    });

    chrome.tabs.update(tabId, {
      url: `${BLOCKED_PAGE}?${params.toString()}`,
    });
  } else {
    setBadgeSafe(tabId);
  }
}

// ─── webNavigation listeners ──────────────────────────────────────────────────

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  // Only handle top-level navigation (frameId 0)
  if (details.frameId !== 0) return;
  if (isInternalUrl(details.url) || isBlockedPage(details.url)) return;

  // Fire-and-forget: pre-warm the cache so it's ready when onCommitted fires
  fetchUrlAnalysis(details.url).then((result) => {
    if (result) setCachedResult(details.url, result);
  });
});

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  scanAndGuard(details.tabId, details.url);
});

// ─── Message handler (from popup or blocked.js) ───────────────────────────────

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'GET_SCAN_RESULT') {
    getCachedResult(message.url).then((result) => sendResponse({ result }));
    return true; // keep channel open for async response
  }

  if (message.type === 'WHITELIST_URL') {
    chrome.storage.local.get(['safeshieldWhitelist'], (data) => {
      const list = data.safeshieldWhitelist || [];
      if (!list.includes(message.url)) list.push(message.url);
      chrome.storage.local.set({ safeshieldWhitelist: list }, () => {
        sendResponse({ ok: true });
      });
    });
    return true;
  }
});
