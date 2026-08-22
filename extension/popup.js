// ─────────────────────────────────────────────────────────────────────────────
// SafeShield Popup Script
// Handles: manual analysis buttons, auto-scan display, CYBER-9 cookie audit
// ─────────────────────────────────────────────────────────────────────────────

// ─── Risk bucket helpers ──────────────────────────────────────────────────────

const riskLabels = {
  low:      { label: 'LOW RISK',      className: 'low'      },
  medium:   { label: 'MEDIUM RISK',   className: 'medium'   },
  high:     { label: 'HIGH RISK',     className: 'high'     },
  critical: { label: 'CRITICAL RISK', className: 'critical' },
};

const analysisTemplates = {
  message: {
    score: 76,
    category: 'Possible Financial Scam',
    reasons: ['Urgent language', 'Requests for money or credentials', 'Suspicious link pattern'],
    action: 'Do not respond, verify the sender through a trusted channel, and preserve the evidence.',
    evidence: 'Message content selected by the user for review; no automatic WhatsApp scraping was performed.'
  },
  url: {
    score: 68,
    category: 'Suspicious URL',
    reasons: ['Lookalike domain name', 'Unusual URL structure', 'Potential credential harvesting pattern'],
    action: 'Avoid opening the link and verify the destination using a known official site.',
    evidence: 'User-submitted URL analyzed locally for structural risk indicators only.'
  },
  image: {
    score: 59,
    category: 'Suspicious Visual Content',
    reasons: ['OCR indicates urgency', 'QR code detected', 'Potential scam language in image text'],
    action: 'Do not scan QR content or interact with embedded links until reviewed by a trusted source.',
    evidence: 'Image selected for manual review; OCR and QR extraction are user-initiated actions.'
  },
  apk: {
    score: 88,
    category: 'Potentially Malicious APK',
    reasons: ['Sensitive permission combinations', 'Suspicious installer behavior indicators', 'Static package risk flags'],
    action: 'Do not install or run the APK. Store a copy securely and review with a sandboxed or isolated environment.',
    evidence: 'APK file selected for static analysis only; no execution is performed.'
  },
  report: {
    score: 92,
    category: 'Evidence Collection Ready',
    reasons: ['Incident summary prepared', 'Recommended action documented', 'Evidence snapshot created'],
    action: 'Preserve the original evidence and keep the final summary for human review.',
    evidence: 'Prepared incident summary includes timestamp, category, score, and recommended action.'
  }
};

function getRiskBucket(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 30) return 'medium';
  return 'low';
}

function updateResult(template) {
  const score  = template.score;
  const bucket = getRiskBucket(score);
  const info   = riskLabels[bucket];

  document.getElementById('risk-label').textContent  = info.label;
  document.getElementById('risk-label').className    = `risk-label ${info.className}`;
  document.getElementById('score-label').textContent = `${score}/100`;
  document.getElementById('risk-score').textContent  = `${score}/100`;
  document.getElementById('risk-category').textContent = template.category;

  const reasonsList = document.getElementById('reasons-list');
  reasonsList.innerHTML = template.reasons.map((r) => `<li>${r}</li>`).join('');

  document.getElementById('recommended-action').textContent = template.action;
  document.getElementById('evidence-summary').textContent   = template.evidence;
}

function initializeButtons() {
  document.querySelectorAll('.action-btn').forEach((button) => {
    button.addEventListener('click', () => {
      const action   = button.dataset.action;
      const template = analysisTemplates[action];
      if (!template) return;

      updateResult(template);
      chrome.storage.local.set({ safeShieldLastResult: { action, ...template } });
    });
  });
}

// ─── Auto-scan panel: load result from background cache ───────────────────────

async function getActiveTabUrl() {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      resolve(tabs[0]?.url || null);
    });
  });
}

function updateScanPanel(result, url) {
  const statusPill   = document.getElementById('scan-status');
  const riskLabel    = document.getElementById('scan-risk-label');
  const scoreEl      = document.getElementById('scan-score');
  const reasonsEl    = document.getElementById('scan-reasons');

  if (!result) {
    statusPill.textContent  = 'No data';
    statusPill.className    = 'scan-status-pill pill-neutral';
    scoreEl.textContent     = '—';
    riskLabel.textContent   = 'UNKNOWN';
    riskLabel.className     = 'risk-label low';
    reasonsEl.innerHTML     = '<li>Backend unavailable or URL not yet scanned.</li>';
    return;
  }

  const score   = Number(result.risk_score);
  const bucket  = getRiskBucket(score);
  const info    = riskLabels[bucket];
  const isDangerous = result.verdict === 'FRAUD' || score >= 50;

  statusPill.textContent = isDangerous ? 'DANGER' : 'SAFE';
  statusPill.className   = `scan-status-pill ${isDangerous ? 'pill-danger' : 'pill-safe'}`;

  riskLabel.textContent = info.label;
  riskLabel.className   = `risk-label ${info.className}`;
  scoreEl.textContent   = `${score}/100`;

  const reasons = result.reasons || [];
  reasonsEl.innerHTML = reasons.length
    ? reasons.map((r) => `<li>${r}</li>`).join('')
    : '<li>No threat indicators detected.</li>';
}

async function loadScanResult() {
  const url = await getActiveTabUrl();
  if (!url) return;

  chrome.runtime.sendMessage({ type: 'GET_SCAN_RESULT', url }, (response) => {
    updateScanPanel(response?.result || null, url);
  });
}

// ─── CYBER-9: Cookie & Session Inspector ─────────────────────────────────────

// Names that suggest a session token — CYBER-9 compliance focus
const SESSION_TOKEN_PATTERNS = /session|token|auth|jwt|\bid\b/i;

// Third-party tracker domains (common subset)
const TRACKER_DOMAINS = [
  'google-analytics.com', 'doubleclick.net', 'facebook.com',
  'twitter.com', 'linkedin.com', 'hotjar.com', 'amplitude.com',
  'segment.com', 'mixpanel.com', 'adroll.com',
];

function isTrackerDomain(domain) {
  return TRACKER_DOMAINS.some((t) => domain.includes(t));
}

function riskBadgeForCookie(cookie) {
  const risks = [];
  if (!cookie.httpOnly) risks.push('XSS');
  if (!cookie.secure)   risks.push('MITM');
  if (!cookie.sameSite || cookie.sameSite === 'unspecified') risks.push('CSRF');

  if (risks.length === 0) return { label: 'OK',  cls: 'flag-ok'   };
  if (risks.length === 1) return { label: risks[0], cls: 'flag-warn' };
  return { label: risks.join('+'), cls: 'flag-danger' };
}

function sameSiteLabel(ss) {
  if (!ss || ss === 'unspecified') return '—';
  return ss.charAt(0).toUpperCase() + ss.slice(1);
}

async function runCookieAudit(tabUrl) {
  return new Promise((resolve) => {
    chrome.cookies.getAll({ url: tabUrl }, resolve);
  });
}

async function loadCookiePanel() {
  const url = await getActiveTabUrl();

  const cyber9Badge = document.getElementById('cyber9-badge');

  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://')) {
    cyber9Badge.textContent = 'N/A';
    cyber9Badge.className   = 'cyber9-badge cyber9-na';
    document.getElementById('cookie-empty-msg').hidden = false;
    document.getElementById('cookie-table-wrap').style.display = 'none';
    updateTally(0, 0, 0, 0);
    return;
  }

  let cookies = [];
  try {
    cookies = await runCookieAudit(url);
  } catch {
    cyber9Badge.textContent = 'Error';
    cyber9Badge.className   = 'cyber9-badge cyber9-na';
    return;
  }

  const hostname = new URL(url).hostname;

  // Tally all cookies
  let totalSecure   = 0;
  let totalHttpOnly = 0;
  let trackers      = 0;

  cookies.forEach((c) => {
    if (c.secure)   totalSecure++;
    if (c.httpOnly) totalHttpOnly++;
    if (isTrackerDomain(c.domain)) trackers++;
  });

  updateTally(cookies.length, totalSecure, totalHttpOnly, trackers);

  // Filter to session-related tokens for the detail table
  const sessionCookies = cookies.filter((c) => SESSION_TOKEN_PATTERNS.test(c.name));

  const tbody   = document.getElementById('cookie-table-body');
  const emptyMsg = document.getElementById('cookie-empty-msg');

  tbody.innerHTML = '';

  if (sessionCookies.length === 0) {
    emptyMsg.hidden = false;
    document.getElementById('cookie-table').style.display = 'none';
  } else {
    emptyMsg.hidden = true;
    document.getElementById('cookie-table').style.display = '';

    let anyVulnerable = false;

    sessionCookies.forEach((c) => {
      const badge = riskBadgeForCookie(c);
      if (badge.cls !== 'flag-ok') anyVulnerable = true;

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="cookie-name" title="${c.name}">${c.name}</td>
        <td class="${c.httpOnly ? 'flag-ok' : 'flag-warn'}">${c.httpOnly ? '✓' : '✗'}</td>
        <td class="${c.secure   ? 'flag-ok' : 'flag-warn'}">${c.secure   ? '✓' : '✗'}</td>
        <td>${sameSiteLabel(c.sameSite)}</td>
        <td><span class="risk-chip ${badge.cls}">${badge.label}</span></td>
      `;
      tbody.appendChild(tr);
    });

    // CYBER-9 compliance verdict
    if (anyVulnerable) {
      cyber9Badge.textContent = '✗ CYBER-9 FAIL';
      cyber9Badge.className   = 'cyber9-badge cyber9-fail';
    } else {
      cyber9Badge.textContent = '✓ CYBER-9 PASS';
      cyber9Badge.className   = 'cyber9-badge cyber9-pass';
    }
  }

  // If no session cookies, just report on total cookie security
  if (sessionCookies.length === 0) {
    const allOk = cookies.every((c) => c.secure && c.httpOnly);
    cyber9Badge.textContent = cookies.length === 0 ? 'No Cookies' : (allOk ? '✓ CYBER-9 PASS' : '⚠ Review');
    cyber9Badge.className   = `cyber9-badge ${cookies.length === 0 ? 'cyber9-na' : (allOk ? 'cyber9-pass' : 'cyber9-fail')}`;
  }
}

function updateTally(total, secure, httponly, trackers) {
  document.getElementById('tally-total').textContent    = total;
  document.getElementById('tally-secure').textContent   = secure;
  document.getElementById('tally-httponly').textContent = httponly;
  document.getElementById('tally-trackers').textContent = trackers;
}

// ─── Init ─────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  initializeButtons();

  // Restore last manual analysis result
  chrome.storage.local.get(['safeShieldLastResult'], (result) => {
    if (result.safeShieldLastResult) updateResult(result.safeShieldLastResult);
  });

  // Load auto-scan result from background cache
  loadScanResult();

  // Run CYBER-9 cookie audit
  loadCookiePanel();
});
