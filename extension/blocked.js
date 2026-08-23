// ─────────────────────────────────────────────────────────────────────────────
// SafeShield blocked.js — Warning interstitial controller
// ─────────────────────────────────────────────────────────────────────────────

(function () {
  'use strict';

  const params  = new URLSearchParams(window.location.search);
  const rawUrl  = params.get('url')     || '';
  const score   = parseInt(params.get('score') || '0', 10);
  const reasons = (params.get('reasons') || '').split('||').filter(Boolean);

  // ── Populate URL ────────────────────────────────────────────────────────────
  const urlEl = document.getElementById('blocked-url');
  if (urlEl) urlEl.textContent = rawUrl || '(unknown URL)';

  // ── Populate score and tier badges ──────────────────────────────────────────
  const tier = params.get('tier') || '';
  const tierBadge = document.getElementById('tier-badge');
  if (tierBadge && tier) {
    tierBadge.textContent = tier;
    tierBadge.style.display = 'inline-block';
  }

  const scoreBadge = document.getElementById('score-badge');
  if (scoreBadge) {
    scoreBadge.textContent = `Risk Score: ${score}/100`;
    // Downgrade color if just medium-risk (50–69)
    if (score < 70) scoreBadge.classList.add('medium');
  }

  // ── Populate reasons list ───────────────────────────────────────────────────
  const reasonsList = document.getElementById('reasons-list');
  if (reasonsList) {
    if (reasons.length > 0) {
      reasonsList.innerHTML = reasons.map((r) => `<li>${r}</li>`).join('');
    } else {
      reasonsList.innerHTML = '<li>Threat pattern detected by SafeShield risk engine.</li>';
    }
  }

  // ── Back to Safety button ───────────────────────────────────────────────────
  document.getElementById('btn-back')?.addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.go(-2); // go back past blocked.html to the previous safe page
    } else {
      // No prior history — close the tab if possible
      chrome.tabs.getCurrent((tab) => {
        if (tab?.id != null) chrome.tabs.remove(tab.id);
      });
    }
  });

  // ── Bypass & Proceed button ─────────────────────────────────────────────────
  document.getElementById('btn-bypass')?.addEventListener('click', () => {
    if (!rawUrl) return;

    // Ask background to whitelist this URL so it won't be blocked again this session
    chrome.runtime.sendMessage({ type: 'WHITELIST_URL', url: rawUrl }, () => {
      window.location.href = rawUrl;
    });
  });
})();
