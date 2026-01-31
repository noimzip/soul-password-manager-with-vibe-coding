// Soul Password Manager - Popup Script
console.log('[Soul AutoFill] Popup opened');

const PWA_URL = 'https://noimzip.github.io/soul-password-manager-with-vibe-coding/';
const LOCAL_PWA_URL = 'http://localhost:5173/';

let currentTabId = null;
let currentUrl = null;
let passwords = [];

// DOM Elements
const loadingState = document.getElementById('loadingState');
const errorState = document.getElementById('errorState');
const errorMessage = document.getElementById('errorMessage');
const passwordList = document.getElementById('passwordList');
const passwordItems = document.getElementById('passwordItems');
const searchInput = document.getElementById('searchInput');
const noResults = document.getElementById('noResults');
const currentUrlEl = document.getElementById('currentUrl');
const openPwaBtn = document.getElementById('openPwaBtn');
const refreshBtn = document.getElementById('refreshBtn');
const settingsBtn = document.getElementById('settingsBtn');

// Show specific state
function showState(state) {
  loadingState.classList.add('hidden');
  errorState.classList.add('hidden');
  passwordList.classList.add('hidden');

  if (state === 'loading') {
    loadingState.classList.remove('hidden');
  } else if (state === 'error') {
    errorState.classList.remove('hidden');
  } else if (state === 'list') {
    passwordList.classList.remove('hidden');
  }
}

// Get detected URL from background script
async function getDetectedUrl() {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ action: 'getDetectedUrl' }, (response) => {
      if (response && response.url) {
        currentUrl = response.url;
        currentTabId = response.tabId;
        currentUrlEl.textContent = currentUrl;
      } else {
        // Fallback: get current tab
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (tabs[0]) {
            const url = new URL(tabs[0].url);
            currentUrl = url.hostname;
            currentTabId = tabs[0].id;
            currentUrlEl.textContent = currentUrl;
          }
          resolve();
        });
        return;
      }
      resolve();
    });
  });
}

// Load passwords from storage (cached from PWA)
async function loadPasswordsFromStorage() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['soul_cached_passwords'], (result) => {
      if (result.soul_cached_passwords) {
        try {
          passwords = JSON.parse(result.soul_cached_passwords);
          console.log('[Soul AutoFill] Loaded', passwords.length, 'cached passwords');
        } catch (e) {
          console.error('[Soul AutoFill] Failed to parse cached passwords:', e);
          passwords = [];
        }
      }
      resolve();
    });
  });
}

// Try to communicate with PWA
async function connectToPWA() {
  try {
    console.log('[Soul AutoFill] Attempting to connect to PWA...');
    
    // Find Soul PWA tab
    const tabs = await chrome.tabs.query({});
    console.log('[Soul AutoFill] Total tabs found:', tabs.length);
    
    const pwaTab = tabs.find(tab => 
      tab.url && (
        tab.url.includes('noimzip.github.io/soul-password-manager') ||
        tab.url.includes('localhost:5173') ||
        tab.url.includes('localhost:4173')
      )
    );
    
    if (!pwaTab) {
      console.log('[Soul AutoFill] PWA tab not found. Looking for URLs containing:');
      console.log('  - noimzip.github.io/soul-password-manager');
      console.log('  - localhost:5173');
      console.log('  - localhost:4173');
      console.log('[Soul AutoFill] Available tabs:', tabs.map(t => t.url));
      return false;
    }
    
    console.log('[Soul AutoFill] Found PWA tab:', pwaTab.id, pwaTab.url);
    
    // Send message to PWA page
    return new Promise((resolve) => {
      console.log('[Soul AutoFill] Sending message to PWA tab...');
      chrome.tabs.sendMessage(pwaTab.id, {
        action: 'soul-get-passwords',
        source: 'extension'
      }, (response) => {
        if (chrome.runtime.lastError) {
          console.error('[Soul AutoFill] Message error:', chrome.runtime.lastError);
          resolve(false);
          return;
        }
        
        console.log('[Soul AutoFill] Received response:', response);
        
        if (response && response.passwords) {
          passwords = response.passwords;
          
          // Cache passwords
          chrome.storage.local.set({
            soul_cached_passwords: JSON.stringify(passwords)
          });
          
          console.log('[Soul AutoFill] Connected to PWA, loaded', passwords.length, 'passwords');
          resolve(true);
        } else if (response && response.error) {
          console.error('[Soul AutoFill] PWA returned error:', response.error);
          resolve(false);
        } else {
          console.log('[Soul AutoFill] No password data received. Response:', response);
          resolve(false);
        }
      });
    });
  } catch (e) {
    console.error('[Soul AutoFill] Failed to connect to PWA:', e);
    return false;
  }
}

// Filter passwords by current URL
function filterPasswordsByUrl(url) {
  if (!url) return passwords;
  
  const urlLower = url.toLowerCase();
  
  return passwords.filter(pwd => {
    if (!pwd.url) return false;
    
    const pwdUrl = pwd.url.toLowerCase();
    
    // Exact match
    if (pwdUrl.includes(urlLower)) return true;
    
    // Domain match
    try {
      const pwdDomain = new URL(pwdUrl.startsWith('http') ? pwdUrl : `https://${pwdUrl}`).hostname;
      if (pwdDomain.includes(urlLower) || urlLower.includes(pwdDomain)) {
        return true;
      }
    } catch (e) {
      // Invalid URL, check string contains
      if (pwdUrl.includes(urlLower)) return true;
    }
    
    return false;
  });
}

// Render password list
function renderPasswords(searchQuery = '') {
  const filtered = currentUrl ? filterPasswordsByUrl(currentUrl) : passwords;
  
  // Apply search filter
  const searchFiltered = searchQuery
    ? filtered.filter(pwd => {
        const query = searchQuery.toLowerCase();
        return (pwd.title && pwd.title.toLowerCase().includes(query)) ||
               (pwd.username && pwd.username.toLowerCase().includes(query)) ||
               (pwd.url && pwd.url.toLowerCase().includes(query));
      })
    : filtered;

  passwordItems.innerHTML = '';
  
  if (searchFiltered.length === 0) {
    noResults.classList.remove('hidden');
    return;
  }
  
  noResults.classList.add('hidden');
  
  searchFiltered.forEach(pwd => {
    const item = document.createElement('div');
    item.className = 'password-item';
    
    const icon = pwd.icon || '🔐';
    const title = pwd.title || 'Untitled';
    const username = pwd.username || 'No username';
    
    item.innerHTML = `
      <div class="password-icon">${icon}</div>
      <div class="password-info">
        <div class="password-title">${escapeHtml(title)}</div>
        <div class="password-username">${escapeHtml(username)}</div>
      </div>
    `;
    
    item.addEventListener('click', () => {
      fillPassword(pwd);
    });
    
    passwordItems.appendChild(item);
  });
}

// Fill password in the page
async function fillPassword(pwd) {
  if (!currentTabId) {
    showError('No active tab found');
    return;
  }

  try {
    // If password is not in cached data, get it from PWA
    let password = pwd.password;
    
    if (!password) {
      // Find PWA tab
      const tabs = await chrome.tabs.query({});
      const pwaTab = tabs.find(tab => 
        tab.url && (
          tab.url.includes('noimzip.github.io/soul-password-manager') ||
          tab.url.includes('localhost:5173') ||
          tab.url.includes('localhost:4173')
        )
      );
      
      if (pwaTab) {
        // Request full password data from PWA
        const response = await new Promise((resolve) => {
          chrome.tabs.sendMessage(pwaTab.id, {
            action: 'soul-get-password-by-id',
            id: pwd.id,
            source: 'extension'
          }, (response) => {
            if (chrome.runtime.lastError) {
              console.error('[Soul AutoFill] Error getting password:', chrome.runtime.lastError);
              resolve(null);
            } else {
              resolve(response);
            }
          });
        });
        
        if (response && response.password) {
          password = response.password;
        }
      }
    }
    
    if (!password) {
      showError('Could not retrieve password. Please open Soul PWA.');
      return;
    }

    chrome.runtime.sendMessage({
      action: 'fillPassword',
      tabId: currentTabId,
      credentials: {
        username: pwd.username || '',
        password: password
      }
    }, (response) => {
      if (response && response.success) {
        // Close popup after successful fill
        window.close();
      } else {
        showError('Failed to fill password');
      }
    });
  } catch (error) {
    console.error('[Soul AutoFill] Error filling password:', error);
    showError('Failed to fill password: ' + error.message);
  }
}

// Show error state
function showError(message) {
  errorMessage.textContent = message;
  showState('error');
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Initialize popup
async function initialize() {
  showState('loading');
  
  // Get detected URL
  await getDetectedUrl();
  
  // Try to connect to PWA
  const connected = await connectToPWA();
  
  if (!connected) {
    // Fallback: load from cache
    await loadPasswordsFromStorage();
  }
  
  if (passwords.length === 0) {
    showError('No passwords found. Please open Soul Password Manager first.');
    return;
  }
  
  // Show password list
  showState('list');
  renderPasswords();
}

// Event listeners
searchInput.addEventListener('input', (e) => {
  renderPasswords(e.target.value);
});

openPwaBtn.addEventListener('click', () => {
  chrome.tabs.create({ url: PWA_URL });
});

refreshBtn.addEventListener('click', () => {
  initialize();
});

settingsBtn.addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
});

// Start
initialize();
