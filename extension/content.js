// SafeShield content.js — minimal content script
// Listens for messages from the background service worker.
// No automatic data collection; respects user privacy.

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'GET_PAGE_URL') {
    sendResponse({ url: window.location.href });
  }
});
