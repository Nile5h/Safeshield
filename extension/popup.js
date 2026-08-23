// =============================================================================
// SafeShield Popup — popup.js
// Handles: backend health check, active-tab live scan, CYBER-9 cookie audit,
//          collapsible drawer, and all dynamic UI rendering.
// =============================================================================

'use strict';

const API_BASE    = 'http://127.0.0.1:8000';
const HEALTH_URL  = `${API_BASE}/health`;
const ANALYZE_URL = `${API_BASE}/analyze/url`;

// Score thresholds that match the backend verdict model
const VERDICT = {
  SAFE:       { max: 24,  label: 'SAFE',       cls: 'verdict-safe'       },
  SUSPICIOUS: { max: 49,  label: 'SUSPICIOUS',  cls: 'verdict-suspicious' },
  FRAUD:      { max: 100, label: 'FRAUD',       cls: 'verdict-fraud'      },
};

// Internal URL schemes — never scan these
const INTERNAL_SCHEMES = ['chrome://', 'chrome-extension://', 'about:', 'data:', 'devtools://'];

// Session-related cookie name patterns (CYBER-9 focus)
const SESSION_TOKEN_RE = /session|token|auth|jwt|\bid\b/i;

// Known tracker domains (subset)
const TRACKER_DOMAINS = [
  'google-analytics.com', 'doubleclick.net', 'facebook.com',
  'twitter.com', 'linkedin.com', 'hotjar.com', 'amplitude.com',
  'segment.com', 'mixpanel.com', 'adroll.com',
];

// =============================================================================
// Utilities
// =============================================================================

function isInternal(url) {
  return !url || INTERNAL_SCHEMES.some((s) => url.startsWith(s));
}

function getVerdict(score) {
  if (score <= VERDICT.SAFE.max)       return VERDICT.SAFE;
  if (score <= VERDICT.SUSPICIOUS.max) return VERDICT.SUSPICIOUS;
  return VERDICT.FRAUD;
}

/** Extract just the hostname (or full URL for data:/blob: URLs). */
function domainFromUrl(url) {
  try { return new URL(url).hostname || url; }
  catch { return url; }
}

/** Capitalise first letter of a SameSite string. */
function fmtSameSite(ss) {
  if (!ss || ss === 'unspecified') return '—';
  return ss.charAt(0).toUpperCase() + ss.slice(1);
}

/** Resolve the risk badge for a single cookie (CYBER-9 logic). */
function cookieRiskBadge(cookie) {
  const flags = [];
  if (!cookie.httpOnly) flags.push('XSS');
  if (!cookie.secure)   flags.push('MITM');
  if (!cookie.sameSite || cookie.sameSite === 'unspecified') flags.push('CSRF');

  if (flags.length === 0) return { label: 'OK',           cls: 'flag-ok'     };
  if (flags.length === 1) return { label: flags[0],       cls: 'flag-warn'   };
  return                         { label: flags.join('+'), cls: 'flag-danger' };
}

function isTracker(domain) {
  return TRACKER_DOMAINS.some((t) => domain.includes(t));
}

// =============================================================================
// Active-tab helpers
// =============================================================================

async function getActiveTab() {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => resolve(tabs[0] ?? null));
  });
}

// =============================================================================
// Backend health check
// =============================================================================

async function checkBackendHealth() {
  const pill     = document.getElementById('pill-backend');
  const pillText = document.getElementById('pill-backend-text');

  try {
    const res = await fetch(HEALTH_URL, { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      pill.className    = 'status-pill pill-online';
      pillText.textContent = 'BACKEND CONNECTED';
      return true;
    }
  } catch { /* fall through */ }

  pill.className    = 'status-pill pill-offline';
  pillText.textContent = 'BACKEND OFFLINE';
  return false;
}

// =============================================================================
// Active-tab scan — live backend or background cache fallback
// =============================================================================

/** Try to pull a cached result from the background service worker. */
async function getCachedResult(url) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: 'GET_SCAN_RESULT', url }, (resp) => {
      // Suppress "message channel closed" errors when SW is starting up
      if (chrome.runtime.lastError) { resolve(null); return; }
      resolve(resp?.result ?? null);
    });
  });
}

/** POST to backend, return parsed JSON or null. */
async function fetchLiveScan(url) {
  try {
    const res = await fetch(ANALYZE_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(12000),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

/**
 * Local heuristic fallback used when the backend is unreachable.
 * Checks for common structural risk signals in the URL itself.
 */
function localHeuristicScan(url) {
  let score = 0;
  const reasons = [];

  try {
    const u = new URL(url);
    const host = u.hostname.toLowerCase();

    // IP address instead of domain name
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      score += 30; reasons.push('IP address used instead of domain name');
    }
    // Excessive subdomains
    if (host.split('.').length > 4) {
      score += 15; reasons.push('Unusual number of subdomains');
    }
    // Lookalike TLDs / suspicious keywords
    const suspicious = ['login', 'secure', 'verify', 'account', 'update', 'banking', 'paypal', 'apple', 'google', 'microsoft'];
    suspicious.forEach((kw) => {
      if (host.includes(kw)) { score += 10; reasons.push(`Keyword "${kw}" in domain`); }
    });
    // No HTTPS
    if (u.protocol !== 'https:') {
      score += 20; reasons.push('Page served over HTTP (not HTTPS)');
    }
    // Very long URL
    if (url.length > 200) {
      score += 10; reasons.push('Unusually long URL');
    }
    // URL-encoded characters in host
    if (host.includes('%')) {
      score += 25; reasons.push('Encoded characters in hostname');
    }
  } catch {
    score = 0;
  }

  score = Math.min(score, 100);
  const verdict = getVerdict(score);

  return {
    risk_score: score,
    verdict:    verdict.label,
    category:   score > 0 ? 'Heuristic Pattern Match' : 'No Issues Detected',
    reasons:    reasons.length ? reasons : ['No structural risk signals detected locally.'],
    recommendation: score >= 50
      ? 'Proceed with caution. Start the SafeShield backend for a full AI-powered analysis.'
      : 'URL appears structurally normal. Start the backend for a definitive verdict.',
    _source: 'local',
  };
}

// =============================================================================
// UI renderers
// =============================================================================

function showLoading() {
  document.getElementById('scan-loading').hidden = false;
  document.getElementById('scan-error').hidden   = true;
  document.getElementById('scan-result').hidden  = true;
}

function showError(title, sub) {
  document.getElementById('scan-loading').hidden = true;
  document.getElementById('scan-error').hidden   = false;
  document.getElementById('scan-result').hidden  = true;
  document.getElementById('scan-error-title').textContent = title;
  document.getElementById('scan-error-sub').textContent   = sub;
}

function renderScanResult(result) {
  const score   = Number(result.risk_score ?? 0);
  const verdict = getVerdict(score);

  // ── Score ring
  const ring = document.getElementById('score-ring');
  ring.dataset.verdict = verdict.cls.replace('verdict-', '');
  document.getElementById('score-number').textContent = score;

  // ── Verdict badge
  const badge = document.getElementById('verdict-badge');
  // Use backend's own verdict string if available, else compute
  const rawVerdict = (result.verdict || verdict.label).toUpperCase();
  badge.textContent = rawVerdict;
  badge.className   = `verdict-badge ${verdict.cls}`;

  // ── Category
  document.getElementById('scan-category').textContent = result.category || result.risk_level || '—';

  // ── Scoring & Dynamic Weightage Breakdown
  const breakdown = result.scoring_breakdown || {};
  const tierBadge = document.getElementById('tier-badge');
  const dynVal    = document.getElementById('weight-dynamic-val');
  const dynBar    = document.getElementById('weight-dynamic-bar');
  const statVal   = document.getElementById('weight-static-val');
  const statBar   = document.getElementById('weight-static-bar');
  const mlVal     = document.getElementById('weight-ml-val');
  const mlBar     = document.getElementById('weight-ml-bar');
  const sumText   = document.getElementById('weightage-summary');

  if (result._source === 'local') {
    tierBadge.textContent = 'LOCAL HEURISTICS';
    tierBadge.className   = 'tier-badge tier-fallback';
    dynVal.textContent    = '0%';
    dynBar.style.width    = '0%';
    statVal.textContent   = '100%';
    statBar.style.width   = '100%';
    mlVal.textContent     = '0%';
    mlBar.style.width     = '0%';
    sumText.textContent   = 'Evaluated using local client-side structural heuristics (backend offline).';
  } else if (breakdown.evaluation_tier?.includes('Allowlist') || breakdown.allowlist_weight_pct > 0) {
    tierBadge.textContent = 'ALLOWLIST BYPASS';
    tierBadge.className   = 'tier-badge tier-allowlist';
    dynVal.textContent    = '0%';
    dynBar.style.width    = '0%';
    statVal.textContent   = '0%';
    statBar.style.width   = '0%';
    mlVal.textContent     = '0%';
    mlBar.style.width     = '0%';
    sumText.textContent   = '100% Trusted Organization Domain match (Instant 0 ms bypass).';
  } else if (breakdown.dynamic_heuristics_weight_pct === 100 || breakdown.evaluation_tier?.includes('Tier 1')) {
    tierBadge.textContent = 'TIER 1: LIVE DYNAMIC';
    tierBadge.className   = 'tier-badge tier-dynamic';
    dynVal.textContent    = '100%';
    dynBar.style.width    = '100%';
    statVal.textContent   = '0%';
    statBar.style.width   = '0%';
    mlVal.textContent     = '0%';
    mlBar.style.width     = '0%';
    sumText.textContent   = 'Dynamic Heuristic Verifications (DOM/Forms/Payloads) prioritized with 100% override.';
  } else {
    // Tier 2 Fallback
    const dynW  = Number(breakdown.dynamic_heuristics_weight_pct ?? 0);
    const statW = Number(breakdown.static_heuristics_weight_pct ?? 60);
    const mlW   = Number(breakdown.ml_model_weight_pct ?? 40);

    tierBadge.textContent = 'TIER 2: STATIC FALLBACK';
    tierBadge.className   = 'tier-badge tier-fallback';
    dynVal.textContent    = `${dynW}%`;
    dynBar.style.width    = `${dynW}%`;
    statVal.textContent   = `${statW}%`;
    statBar.style.width   = `${statW}%`;
    mlVal.textContent     = `${mlW}%`;
    mlBar.style.width     = `${mlW}%`;
    sumText.textContent   = breakdown.summary || `Static Heuristics (${statW}%) & ML Model (${mlW}%) fallback applied.`;
  }

  // ── 4 Dynamic Heuristic Verification Checks
  const dynChecks = breakdown.dynamic_verifications || result.live_inspection?.dynamic_verifications || {};

  function updateCheckRow(prefix, checkObj) {
    const icon  = document.getElementById(`icon-${prefix}`);
    const badge = document.getElementById(`badge-${prefix}`);
    if (!icon || !badge) return;

    const status = (checkObj?.status || 'PASS').toUpperCase();
    if (status === 'PASS') {
      icon.textContent  = '✓';
      icon.className    = 'check-icon pass';
      badge.textContent = 'PASS';
      badge.className   = 'check-badge pass';
    } else if (status === 'FAIL') {
      icon.textContent  = '✗';
      icon.className    = 'check-icon fail';
      badge.textContent = 'FAIL';
      badge.className   = 'check-badge fail';
    } else {
      icon.textContent  = '—';
      icon.className    = 'check-icon warn';
      badge.textContent = 'N/A';
      badge.className   = 'check-badge warn';
    }
  }

  updateCheckRow('pwd', dynChecks.password_form_origin || { status: 'PASS' });
  updateCheckRow('iframe', dynChecks.zero_size_iframes || { status: 'PASS' });
  updateCheckRow('brand', dynChecks.brand_domain_match || { status: 'PASS' });
  updateCheckRow('payload', dynChecks.drive_by_payloads || { status: 'PASS' });

  // ── Reasons
  const reasons = Array.isArray(result.reasons) && result.reasons.length
    ? result.reasons
    : ['No specific threat indicators returned by the backend.'];
  const reasonsEl = document.getElementById('scan-reasons');
  reasonsEl.innerHTML = reasons.map((r) => `<li>${r}</li>`).join('');
  document.getElementById('reasons-block').hidden = false;

  // ── Recommendation (if present)
  const recBlock = document.getElementById('recommendation-block');
  const recText  = result.recommendation || '';
  if (recText) {
    document.getElementById('scan-recommendation').textContent = recText;
    recBlock.hidden = false;
  } else {
    recBlock.hidden = true;
  }

  // ── Source tag
  const srcTag = document.getElementById('source-tag');
  if (result._source === 'local') {
    srcTag.textContent = '⚡ Local heuristic scan (backend offline)';
    srcTag.className   = 'source-tag source-local';
  } else if (result._source === 'cache') {
    srcTag.textContent = '📦 Cached result (< 10 min)';
    srcTag.className   = 'source-tag source-cache';
  } else {
    srcTag.textContent = '● Live backend scan';
    srcTag.className   = 'source-tag source-live';
  }

  // ── Show result area
  document.getElementById('scan-loading').hidden = true;
  document.getElementById('scan-error').hidden   = true;
  document.getElementById('scan-result').hidden  = false;
}

// =============================================================================
// Main scan runner
// =============================================================================

let _currentTabUrl = null;

async function runScan(forceRefresh = false) {
  const tab = await getActiveTab();
  const url  = tab?.url ?? null;
  _currentTabUrl = url;

  // Domain display
  const domainEl = document.getElementById('tab-domain');
  if (!url || isInternal(url)) {
    domainEl.textContent = isInternal(url) ? '(browser internal page)' : '(no active tab)';
    showError(
      'No Scannable Page',
      'SafeShield does not scan browser-internal pages (chrome://, about:, etc.).'
    );
    return;
  }
  domainEl.textContent = domainFromUrl(url);

  showLoading();

  // 1. Try background session cache first (unless forced refresh)
  if (!forceRefresh) {
    const cached = await getCachedResult(url);
    if (cached) {
      cached._source = 'cache';
      renderScanResult(cached);
      return;
    }
  }

  // 2. Try live backend
  const live = await fetchLiveScan(url);
  if (live) {
    live._source = 'live';
    renderScanResult(live);
    return;
  }

  // 3. Backend unreachable — run local heuristic
  const local = localHeuristicScan(url);
  renderScanResult(local);
}

// =============================================================================
// CYBER-9: Cookie & Session Inspector
// =============================================================================

async function getAllCookies(url) {
  return new Promise((resolve) => chrome.cookies.getAll({ url }, resolve));
}

async function runCookieAudit(url) {
  const cyber9Badge = document.getElementById('cyber9-badge');

  if (!url || isInternal(url)) {
    cyber9Badge.textContent = 'N/A';
    cyber9Badge.className   = 'cyber9-badge cyber9-na';
    document.getElementById('cookie-empty-msg').hidden = false;
    document.getElementById('cookie-table-wrap').style.display = 'none';
    setTally(0, 0, 0, 0);
    return;
  }

  let cookies = [];
  try {
    cookies = await getAllCookies(url);
  } catch {
    cyber9Badge.textContent = 'Error';
    cyber9Badge.className   = 'cyber9-badge cyber9-na';
    return;
  }

  // Tally totals
  let nSecure = 0, nHttpOnly = 0, nTrackers = 0;
  cookies.forEach((c) => {
    if (c.secure)            nSecure++;
    if (c.httpOnly)          nHttpOnly++;
    if (isTracker(c.domain)) nTrackers++;
  });
  setTally(cookies.length, nSecure, nHttpOnly, nTrackers);

  // Session-token detail rows
  const sessionCookies = cookies.filter((c) => SESSION_TOKEN_RE.test(c.name));
  const tbody    = document.getElementById('cookie-table-body');
  const emptyMsg = document.getElementById('cookie-empty-msg');
  const table    = document.getElementById('cookie-table');

  tbody.innerHTML = '';

  if (sessionCookies.length === 0) {
    emptyMsg.hidden = false;
    table.style.display = 'none';

    const allOk = cookies.length > 0 && cookies.every((c) => c.secure && c.httpOnly);
    cyber9Badge.textContent = cookies.length === 0
      ? 'No Cookies'
      : (allOk ? '✓ CYBER-9 PASS' : '⚠ Review');
    cyber9Badge.className = `cyber9-badge ${
      cookies.length === 0 ? 'cyber9-na' : (allOk ? 'cyber9-pass' : 'cyber9-fail')
    }`;
    return;
  }

  emptyMsg.hidden = true;
  table.style.display = '';

  let anyVulnerable = false;
  sessionCookies.forEach((c) => {
    const badge = cookieRiskBadge(c);
    if (badge.cls !== 'flag-ok') anyVulnerable = true;

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="cookie-name" title="${c.name}">${c.name}</td>
      <td class="${c.httpOnly ? 'flag-ok' : 'flag-warn'}">${c.httpOnly ? '✓' : '✗'}</td>
      <td class="${c.secure   ? 'flag-ok' : 'flag-warn'}">${c.secure   ? '✓' : '✗'}</td>
      <td>${fmtSameSite(c.sameSite)}</td>
      <td><span class="risk-chip ${badge.cls}">${badge.label}</span></td>
    `;
    tbody.appendChild(tr);
  });

  cyber9Badge.textContent = anyVulnerable ? '✗ CYBER-9 FAIL' : '✓ CYBER-9 PASS';
  cyber9Badge.className   = `cyber9-badge ${anyVulnerable ? 'cyber9-fail' : 'cyber9-pass'}`;
}

function setTally(total, secure, httponly, trackers) {
  document.getElementById('tally-total').textContent    = total;
  document.getElementById('tally-secure').textContent   = secure;
  document.getElementById('tally-httponly').textContent = httponly;
  document.getElementById('tally-trackers').textContent = trackers;
}

// =============================================================================
// Collapsible Quick-Actions drawer
// =============================================================================

function initDrawer() {
  const toggle = document.getElementById('drawer-toggle');
  const body   = document.getElementById('drawer-body');

  toggle.addEventListener('click', () => {
    const open = toggle.getAttribute('aria-expanded') === 'true';
    toggle.setAttribute('aria-expanded', String(!open));
    body.hidden = open;
    toggle.querySelector('.drawer-chevron').textContent = open ? '▾' : '▴';
  });

  // Drawer action buttons (stub — extend when manual analysis panels are built)
  body.querySelectorAll('.drawer-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const action = btn.dataset.action;
      // TODO: open full manual-analysis flow per action type
      btn.textContent = `${btn.querySelector('.drawer-icon')?.textContent ?? ''} Coming soon…`;
      btn.disabled = true;
      setTimeout(() => {
        btn.disabled = false;
        btn.innerHTML = btn.innerHTML; // reset — placeholder until panels are built
      }, 1500);
    });
  });
}

// =============================================================================
// Scan Again button
// =============================================================================

function initScanAgain() {
  document.getElementById('btn-scan-again').addEventListener('click', () => {
    runScan(true); // force-refresh, bypass cache
  });
}

// =============================================================================
// Bootstrap
// =============================================================================

document.addEventListener('DOMContentLoaded', async () => {
  // Kick off all three tasks concurrently
  const [backendOnline] = await Promise.all([
    checkBackendHealth(),
    (async () => {
      await runScan();
    })(),
    (async () => {
      const tab = await getActiveTab();
      await runCookieAudit(tab?.url ?? null);
    })(),
  ]);

  initDrawer();
  initScanAgain();
});
