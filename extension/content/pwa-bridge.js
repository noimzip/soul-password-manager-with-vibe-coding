// Soul Password Manager - PWA Bridge Script
// This script runs in the PWA page context and bridges communication
// between the extension and the PWA

console.log('[Soul PWA Bridge] Bridge script loaded');

// Listen for messages from extension (popup or background)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('[Soul PWA Bridge] Received from extension:', message);
  
  if (message.action === 'soul-get-passwords' || message.action === 'soul-get-password-by-id') {
    // Forward message to PWA page context
    window.postMessage({
      type: 'soul-extension-request',
      action: message.action,
      id: message.id,
      source: 'extension'
    }, '*');
    
    // Wait for response from PWA
    const responseHandler = (event) => {
      if (event.data && event.data.type === 'soul-extension-response') {
        console.log('[Soul PWA Bridge] Received response from PWA:', event.data);
        window.removeEventListener('message', responseHandler);
        sendResponse(event.data.data);
      }
    };
    
    window.addEventListener('message', responseHandler);
    
    // Timeout after 5 seconds
    setTimeout(() => {
      window.removeEventListener('message', responseHandler);
      sendResponse({ error: 'Timeout waiting for PWA response' });
    }, 5000);
    
    // Return true to indicate async response
    return true;
  }
  
  return false;
});

console.log('[Soul PWA Bridge] Bridge ready');
