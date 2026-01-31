// Soul Password Manager - Background Script (Service Worker)
// Handles communication between content script, popup, and PWA

console.log('[Soul AutoFill] Background service worker started');

const PWA_URL = 'https://noimzip.github.io/soul-password-manager-with-vibe-coding/';
const LOCAL_PWA_URL = 'http://localhost:5173/';

// Store current tab and detected URL
let currentTabId = null;
let currentUrl = null;

// Listen for form detection from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('[Soul AutoFill] Message received:', message);

  if (message.action === 'formDetected') {
    // Store the tab ID and URL when a form is detected
    currentTabId = sender.tab?.id;
    currentUrl = message.url;
    
    // Update badge to show Soul is available
    if (currentTabId) {
      chrome.action.setBadgeText({ text: '●', tabId: currentTabId });
      chrome.action.setBadgeBackgroundColor({ color: '#6750a4', tabId: currentTabId });
    }
    
    sendResponse({ received: true });
  } else if (message.action === 'requestPassword') {
    // User clicked the Soul icon in a form
    currentUrl = message.url;
    
    // Open popup or communicate with PWA
    sendResponse({ received: true });
  } else if (message.action === 'fillPassword') {
    // Received password from popup, fill it in the page
    if (message.tabId && message.credentials) {
      chrome.tabs.sendMessage(message.tabId, {
        action: 'fillCredentials',
        username: message.credentials.username,
        password: message.credentials.password
      }).catch(err => {
        console.error('[Soul AutoFill] Failed to fill credentials:', err);
      });
    }
    sendResponse({ success: true });
  } else if (message.action === 'getDetectedUrl') {
    // Popup requests the current URL
    sendResponse({ url: currentUrl, tabId: currentTabId });
  }

  return true;
});

// Clear badge when tab changes
chrome.tabs.onActivated.addListener((activeInfo) => {
  currentTabId = activeInfo.tabId;
  currentUrl = null;
});

// Clear badge when URL changes
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tabId === currentTabId) {
    currentUrl = null;
    chrome.action.setBadgeText({ text: '', tabId: tabId });
  }
});

// Handle external messages from PWA (if configured)
chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
  console.log('[Soul AutoFill] External message from:', sender.origin, message);

  if (message.action === 'providePassword' && message.credentials) {
    // PWA is sending password data
    if (currentTabId) {
      chrome.tabs.sendMessage(currentTabId, {
        action: 'fillCredentials',
        username: message.credentials.username,
        password: message.credentials.password
      }).then(() => {
        sendResponse({ success: true });
      }).catch(err => {
        console.error('[Soul AutoFill] Failed to fill:', err);
        sendResponse({ success: false, error: err.message });
      });
    } else {
      sendResponse({ success: false, error: 'No active tab' });
    }
  } else if (message.action === 'getDetectedUrl') {
    sendResponse({ url: currentUrl, tabId: currentTabId });
  }

  return true;
});

// Context menu (right-click) option
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'soul-fill-password',
    title: 'Fill with Soul Password Manager',
    contexts: ['editable']
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'soul-fill-password') {
    // Open popup or communicate with PWA
    chrome.action.openPopup();
  }
});

console.log('[Soul AutoFill] Background script ready');
