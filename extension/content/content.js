// Soul Password Manager - Content Script
// Detects login forms and enables auto-fill functionality

console.log('[Soul AutoFill] Content script loaded');

let detectedFields = {
  username: null,
  password: null
};

// Check if extension context is valid
function isExtensionContextValid() {
  try {
    return chrome.runtime && chrome.runtime.id;
  } catch (e) {
    return false;
  }
}

// Safe message sending with error handling
async function sendMessageSafely(message) {
  if (!isExtensionContextValid()) {
    console.warn('[Soul AutoFill] Extension context invalidated. Please reload the page.');
    showReloadNotification();
    return null;
  }
  
  try {
    return await chrome.runtime.sendMessage(message);
  } catch (error) {
    if (error.message.includes('Extension context invalidated')) {
      console.warn('[Soul AutoFill] Extension was reloaded. Please refresh this page.');
      showReloadNotification();
    } else {
      console.error('[Soul AutoFill] Message error:', error);
    }
    return null;
  }
}

// Detect login forms on the page
function detectLoginForm() {
  const passwordFields = document.querySelectorAll('input[type="password"]');
  
  if (passwordFields.length === 0) {
    return null;
  }

  // Find the first password field and associated username field
  const passwordField = passwordFields[0];
  let usernameField = null;

  // Look for username field (email or text input before password)
  const form = passwordField.closest('form');
  if (form) {
    const inputs = form.querySelectorAll('input[type="text"], input[type="email"], input[type="tel"]');
    for (const input of inputs) {
      // Check if this input comes before the password field
      if (input.compareDocumentPosition(passwordField) & Node.DOCUMENT_POSITION_FOLLOWING) {
        usernameField = input;
        break;
      }
    }
  } else {
    // If not in a form, look for nearby inputs
    const allInputs = document.querySelectorAll('input[type="text"], input[type="email"], input[type="tel"]');
    for (const input of allInputs) {
      if (input.compareDocumentPosition(passwordField) & Node.DOCUMENT_POSITION_FOLLOWING) {
        usernameField = input;
        break;
      }
    }
  }

  return {
    username: usernameField,
    password: passwordField,
    url: window.location.hostname
  };
}

// Create and show Soul icon on password fields
function addSoulIcon(passwordField) {
  // Check if icon already exists
  if (passwordField.dataset.soulIconAdded) {
    return;
  }

  const icon = document.createElement('div');
  icon.className = 'soul-autofill-icon';
  icon.innerHTML = '🔑';
  icon.title = 'Fill with Soul Password Manager';
  
  // Style the icon
  Object.assign(icon.style, {
    position: 'absolute',
    right: '8px',
    top: '50%',
    transform: 'translateY(-50%)',
    width: '24px',
    height: '24px',
    cursor: 'pointer',
    fontSize: '16px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#6750a4',
    borderRadius: '4px',
    zIndex: '10000',
    userSelect: 'none'
  });

  // Make password field's parent relative if needed
  const parent = passwordField.parentElement;
  if (window.getComputedStyle(parent).position === 'static') {
    parent.style.position = 'relative';
  }

  // Add click handler
  icon.addEventListener('click', async (e) => {
    e.preventDefault();
    e.stopPropagation();
    
    const fields = detectLoginForm();
    if (fields) {
      // Send message to background script to show popup
      await sendMessageSafely({
        action: 'requestPassword',
        url: fields.url
      });
    }
  });

  parent.appendChild(icon);
  passwordField.dataset.soulIconAdded = 'true';
}

// Auto-fill credentials
function fillCredentials(username, password) {
  const fields = detectLoginForm();
  
  if (!fields) {
    console.log('[Soul AutoFill] No login form detected');
    return false;
  }

  if (fields.username && username) {
    fields.username.value = username;
    // Trigger input events for frameworks like React
    fields.username.dispatchEvent(new Event('input', { bubbles: true }));
    fields.username.dispatchEvent(new Event('change', { bubbles: true }));
  }

  if (fields.password && password) {
    fields.password.value = password;
    fields.password.dispatchEvent(new Event('input', { bubbles: true }));
    fields.password.dispatchEvent(new Event('change', { bubbles: true }));
  }

  // Visual feedback
  showFillNotification();
  
  return true;
}

// Show notification after auto-fill
function showFillNotification() {
  const notification = document.createElement('div');
  notification.textContent = '✓ Filled by Soul Password Manager';
  
  Object.assign(notification.style, {
    position: 'fixed',
    top: '20px',
    right: '20px',
    backgroundColor: '#6750a4',
    color: 'white',
    padding: '12px 20px',
    borderRadius: '8px',
    fontSize: '14px',
    fontFamily: 'system-ui, -apple-system, sans-serif',
    zIndex: '999999',
    boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
    animation: 'soulFadeIn 0.3s ease-out'
  });

  // Add animation
  const style = document.createElement('style');
  style.textContent = `
    @keyframes soulFadeIn {
      from { opacity: 0; transform: translateY(-10px); }
      to { opacity: 1; transform: translateY(0); }
    }
  `;
  document.head.appendChild(style);
  
  document.body.appendChild(notification);
  
  setTimeout(() => {
    notification.style.opacity = '0';
    notification.style.transition = 'opacity 0.3s';
    setTimeout(() => notification.remove(), 300);
  }, 2000);
}

// Show reload notification when extension context is invalidated
function showReloadNotification() {
  // Check if notification already exists
  if (document.getElementById('soul-reload-notification')) {
    return;
  }

  const notification = document.createElement('div');
  notification.id = 'soul-reload-notification';
  notification.innerHTML = `
    <div style="display: flex; align-items: center; gap: 12px;">
      <span>⚠️</span>
      <div style="flex: 1;">
        <strong>Soul Password Manager updated</strong><br>
        <span style="font-size: 12px; opacity: 0.9;">Please reload this page to continue</span>
      </div>
      <button id="soul-reload-btn" style="
        background: white;
        color: #6750a4;
        border: none;
        padding: 6px 12px;
        border-radius: 4px;
        cursor: pointer;
        font-weight: 600;
      ">Reload</button>
    </div>
  `;
  
  Object.assign(notification.style, {
    position: 'fixed',
    top: '20px',
    right: '20px',
    backgroundColor: '#6750a4',
    color: 'white',
    padding: '16px',
    borderRadius: '8px',
    fontSize: '14px',
    fontFamily: 'system-ui, -apple-system, sans-serif',
    zIndex: '999999',
    boxShadow: '0 4px 16px rgba(0,0,0,0.3)',
    maxWidth: '320px',
    animation: 'soulFadeIn 0.3s ease-out'
  });

  document.body.appendChild(notification);

  // Add reload button handler
  document.getElementById('soul-reload-btn')?.addEventListener('click', () => {
    window.location.reload();
  });
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!isExtensionContextValid()) {
    console.warn('[Soul AutoFill] Cannot receive messages - extension context invalidated');
    return false;
  }

  if (message.action === 'fillCredentials') {
    const success = fillCredentials(message.username, message.password);
    sendResponse({ success });
  } else if (message.action === 'detectForm') {
    const fields = detectLoginForm();
    sendResponse({ 
      found: !!fields,
      url: fields ? fields.url : null
    });
  }
  return true;
});

// Initialize: detect forms and add icons
function initialize() {
  if (!isExtensionContextValid()) {
    console.warn('[Soul AutoFill] Extension context not valid, skipping initialization');
    return;
  }

  const fields = detectLoginForm();
  if (fields && fields.password) {
    addSoulIcon(fields.password);
    detectedFields = fields;
    
    // Notify background that a form was detected
    sendMessageSafely({
      action: 'formDetected',
      url: fields.url
    });
  }
}

// Run on page load
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initialize);
} else {
  initialize();
}

// Re-run when DOM changes (for SPAs)
const observer = new MutationObserver((mutations) => {
  if (!isExtensionContextValid()) {
    observer.disconnect();
    console.warn('[Soul AutoFill] Stopping observer - extension context invalidated');
    return;
  }

  for (const mutation of mutations) {
    if (mutation.addedNodes.length > 0) {
      // Check if any password fields were added
      const hasPasswordField = Array.from(mutation.addedNodes).some(node => {
        if (node.nodeType === Node.ELEMENT_NODE) {
          return node.matches('input[type="password"]') || 
                 node.querySelector('input[type="password"]');
        }
        return false;
      });
      
      if (hasPasswordField) {
        setTimeout(initialize, 100);
        break;
      }
    }
  }
});

observer.observe(document.body, {
  childList: true,
  subtree: true
});

console.log('[Soul AutoFill] Monitoring for login forms');
