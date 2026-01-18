// Import Firebase SDKs
import { initializeApp } from "https://www.gstatic.com/firebasejs/12.8.0/firebase-app.js";
import { getAnalytics } from "https://www.gstatic.com/firebasejs/12.8.0/firebase-analytics.js";
import { getAuth, signInWithPopup, GoogleAuthProvider, signOut, onAuthStateChanged } from "https://www.gstatic.com/firebasejs/12.8.0/firebase-auth.js";
import { getFirestore, collection, addDoc, query, where, onSnapshot, doc, updateDoc, deleteDoc } from "https://www.gstatic.com/firebasejs/12.8.0/firebase-firestore.js";

// --- Firebase Configuration ---
const firebaseConfig = {
    apiKey: "AIzaSyCPDXCeqKrGk4IKuVe-VWoBPJCtL9C7Q7g",
    authDomain: "soul-password-manager.firebaseapp.com",
    projectId: "soul-password-manager",
    storageBucket: "soul-password-manager.firebasestorage.app",
    messagingSenderId: "445102232725",
    appId: "1:445102232725:web:3fed84a3f3e0fbd3f1b79c",
    measurementId: "G-VM2MLDRE6P"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const analytics = getAnalytics(app);
const auth = getAuth(app);
const db = getFirestore(app);

// --- Constants & State ---
const CONSTANTS = {
    STORAGE: {
        PASSWORDS: 'soul_passwords',
        MASTER_AUTH: 'soul_master_auth',
        AUTO_LOGOUT: 'soul_auto_logout_minutes',
        DEFAULT_USER: 'soul_default_username',
        THEME: 'soul_theme',
        GENERATOR_HISTORY: 'soul_generator_history'
    }
};

const CRYPTO_CONFIG = {
    PBKDF2_ITERATIONS: 100000,
    SALT_LENGTH: 16,
    IV_LENGTH: 12
};

let appKey = null; // Session key for Local Mode
let savedPasswords = []; // In-memory list of decrypted passwords
let currentDetailIndex = -1; // Index of currently opened item
let currentUser = null; // Firebase User
let dragSrcEl = null; // For Drag and Drop
let historyDebounceTimer = null; // Timer for debouncing history saves
let autoLogoutTimer = null; // Timer for auto logout

// --- Crypto Utilities (Local Mode - High Security) ---

function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes;
}

async function generateSalt() {
    return window.crypto.getRandomValues(new Uint8Array(CRYPTO_CONFIG.SALT_LENGTH));
}

async function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey", "deriveBits"]
    );
    
    const saltBuffer = typeof salt === 'string' ? base64ToArrayBuffer(salt) : salt;
    
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: saltBuffer,
            iterations: CRYPTO_CONFIG.PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

async function hashPassword(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]
    );
    const saltBuffer = typeof salt === 'string' ? base64ToArrayBuffer(salt) : salt;
    
    const derivedBits = await window.crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: saltBuffer,
            iterations: CRYPTO_CONFIG.PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },
        keyMaterial,
        256
    );
    return arrayBufferToBase64(derivedBits);
}

async function encryptLocal(data, key) {
    const enc = new TextEncoder();
    const encoded = enc.encode(JSON.stringify(data));
    const iv = window.crypto.getRandomValues(new Uint8Array(CRYPTO_CONFIG.IV_LENGTH));
    
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encoded
    );
    
    return JSON.stringify({
        iv: arrayBufferToBase64(iv),
        data: arrayBufferToBase64(encrypted)
    });
}

async function decryptLocal(encryptedJson, key) {
    try {
        const raw = JSON.parse(encryptedJson);
        if (!raw.iv || !raw.data) throw new Error("Invalid encrypted data format");
        
        const iv = base64ToArrayBuffer(raw.iv);
        const data = base64ToArrayBuffer(raw.data);
        
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            data
        );
        
        const dec = new TextDecoder();
        return JSON.parse(dec.decode(decrypted));
    } catch (e) {
        console.error("Decryption failed", e);
        throw e;
    }
}

// --- Crypto Utilities (Cloud Mode - Demo/Fixed Key) ---
// Uses a fixed salt/key to allow multi-device sync without complex key exchange in this demo.
async function getCloudCryptoKey() {
    const rawKey = new TextEncoder().encode("SoulPasswordManagerDemoKey"); 
    const keyHash = await window.crypto.subtle.digest('SHA-256', rawKey);
    return window.crypto.subtle.importKey(
      "raw",
      keyHash,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
}

async function encryptCloud(plaintext) {
    if (!plaintext) return "";
    try {
      const key = await getCloudCryptoKey();
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(plaintext);
      const ciphertext = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encoded
      );
      const combined = new Uint8Array(iv.length + ciphertext.byteLength);
      combined.set(iv);
      combined.set(new Uint8Array(ciphertext), iv.length);
      return arrayBufferToBase64(combined);
    } catch (e) {
      console.error("Cloud Encryption failed:", e);
      return plaintext;
    }
}

async function decryptCloud(encryptedBase64) {
    if (!encryptedBase64) return "";
    try {
      const key = await getCloudCryptoKey();
      const binaryString = window.atob(encryptedBase64);
      const combined = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        combined[i] = binaryString.charCodeAt(i);
      }
      const iv = combined.slice(0, 12);
      const ciphertext = combined.slice(12);
      const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        ciphertext
      );
      return new TextDecoder().decode(decrypted);
    } catch (e) {
      console.warn("Cloud Decryption failed, returning original:", e);
      return encryptedBase64;
    }
}

// --- Data Persistence ---

async function savePasswordsData() {
    if (currentUser) {
        // Cloud Mode: Saving is handled per-item via Firestore calls, 
        // but we might want to sync local state if needed.
        // In this implementation, Firestore is the source of truth when logged in.
        return;
    }
    // Local Mode
    if (!appKey) return;
    const encrypted = await encryptLocal(savedPasswords, appKey);
    localStorage.setItem(CONSTANTS.STORAGE.PASSWORDS, encrypted);
}

// --- Password Generation ---

function generatePasswordString(length, useUpper, useNumbers, useSymbols) {
    const letters = 'abcdefghijklmnopqrstuvwxyz';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    let pool = letters;
    if (useUpper) pool += letters.toUpperCase();
    if (useNumbers) pool += numbers;
    if (useSymbols) pool += symbols;

    let password = '';
    const randomValues = new Uint32Array(length);
    window.crypto.getRandomValues(randomValues);
    
    for (let i = 0; i < length; i++) {
        password += pool.charAt(randomValues[i] % pool.length);
    }
    return password;
}

// --- UI Helpers ---

function copyToClipboard(text, message) {
    if (!text) return;
    navigator.clipboard.writeText(text).then(function() {
        showSnackbar(message);
    }).catch(function(err) {
        console.error('Copy failed', err);
        showSnackbar('コピーに失敗しました');
    });
}

function showDialog(message, isConfirm) {
    return new Promise(function(resolve) {
        const dialog = document.createElement('m3e-dialog');
        
        const content = document.createElement('div');
        content.textContent = message;
        content.style.padding = '10px 0';
        dialog.appendChild(content);

        const btnContainer = document.createElement('div');
        btnContainer.style.display = 'flex';
        btnContainer.style.justifyContent = 'flex-end';
        btnContainer.style.marginTop = '10px';
        btnContainer.style.gap = '8px';

        const createBtn = function(text) {
            const btn = document.createElement('button');
            btn.textContent = text;
            btn.style.cssText = 'border:none; background:transparent; color:#2196f3; font-weight:bold; cursor:pointer; padding:8px 16px; font-size:14px;';
            return btn;
        };

        if (isConfirm) {
            const cancelBtn = createBtn('いいえ');
            cancelBtn.addEventListener('click', function() {
                dialog.open = false;
                resolve(false);
                setTimeout(function() { if(dialog.parentNode) dialog.parentNode.removeChild(dialog); }, 500);
            });
            btnContainer.appendChild(cancelBtn);
        }

        const okBtn = createBtn(isConfirm ? 'はい' : 'OK');
        okBtn.addEventListener('click', function() {
            dialog.open = false;
            resolve(true);
            setTimeout(function() { if(dialog.parentNode) dialog.parentNode.removeChild(dialog); }, 500);
        });
        btnContainer.appendChild(okBtn);
        dialog.appendChild(btnContainer);

        document.body.appendChild(dialog);
        requestAnimationFrame(function() {
            dialog.open = true;
        });
    });
}

function showAlertDialog(message) {
    return showDialog(message, false);
}

function showConfirmDialog(message) {
    return showDialog(message, true);
}

function showSnackbar(message) {
    const el = document.createElement('div');
    el.textContent = message;
    el.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background-color:#323232;color:white;padding:14px 24px;border-radius:4px;z-index:10000;box-shadow:0 2px 5px rgba(0,0,0,0.2);opacity:0;transition:opacity 0.3s;font-family:sans-serif;pointer-events:none;';
    document.body.appendChild(el);
    requestAnimationFrame(function() { el.style.opacity = '1'; });
    setTimeout(function() {
        el.style.opacity = '0';
        setTimeout(function() { if(el.parentNode) el.parentNode.removeChild(el); }, 300);
    }, 3000);
}

// --- Password Strength & TOTP ---

function calculatePasswordStrength(password) {
    let strength = 0;
    if (!password) return 0;

    if (password.length >= 8) strength += 1;
    if (password.length >= 12) strength += 1;
    if (password.length >= 16) strength += 1;

    let typeCount = 0;
    if (/[a-z]/.test(password)) typeCount++;
    if (/[A-Z]/.test(password)) typeCount++;
    if (/[0-9]/.test(password)) typeCount++;
    if (/[^A-Za-z0-9]/.test(password)) typeCount++;
    strength += typeCount;

    if (password.length < 8 || typeCount <= 1) return Math.min(strength, 1);
    if (typeCount === 2) return Math.min(strength, 3);

    return strength;
}

function calculateCrackTime(password) {
    let poolSize = 0;
    if (/[a-z]/.test(password)) poolSize += 26;
    if (/[A-Z]/.test(password)) poolSize += 26;
    if (/[0-9]/.test(password)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) poolSize += 33;

    if (poolSize === 0) return '';

    const combinations = Math.pow(poolSize, password.length);
    const seconds = combinations / 1000000000; 

    let timeString = '一瞬';
    if (seconds >= 31536000 * 100) timeString = '数世紀以上';
    else if (seconds >= 31536000) timeString = Math.floor(seconds / 31536000) + '年';
    else if (seconds >= 86400) timeString = Math.floor(seconds / 86400) + '日';
    else if (seconds >= 3600) timeString = Math.floor(seconds / 3600) + '時間';
    else if (seconds >= 60) timeString = Math.floor(seconds / 60) + '分';
    else if (seconds >= 1) timeString = Math.floor(seconds) + '秒';

    return '解読にかかる推定時間: ' + timeString;
}

// Base32 decode helper
function base32ToBuf(str) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let length = str.length;
    let bits = 0;
    let value = 0;
    let index = 0;
    const output = new Uint8Array((length * 5 / 8) | 0);
    
    for (let i = 0; i < length; i++) {
        const char = str.charAt(i).toUpperCase();
        const val = alphabet.indexOf(char);
        if (val === -1) continue;
        
        value = (value << 5) | val;
        bits += 5;
        
        if (bits >= 8) {
            output[index++] = (value >>> (bits - 8)) & 255;
            bits -= 8;
        }
    }
    return output.slice(0, index);
}

async function generateTOTP(secret) {
    if (!secret) return null;
    try {
        secret = secret.replace(/\s/g, '');
        const keyData = base32ToBuf(secret);
        if (keyData.length === 0) return null;

        const key = await window.crypto.subtle.importKey(
            "raw", keyData, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
        );

        const epoch = Math.floor(Date.now() / 1000);
        const timeStep = 30;
        const counter = Math.floor(epoch / timeStep);
        
        const counterBuf = new ArrayBuffer(8);
        const counterView = new DataView(counterBuf);
        counterView.setUint32(4, counter, false);

        const signature = await window.crypto.subtle.sign("HMAC", key, counterBuf);
        const hmac = new Uint8Array(signature);
        
        const offset = hmac[hmac.length - 1] & 0xf;
        const code = ((hmac[offset] & 0x7f) << 24) |
                     ((hmac[offset + 1] & 0xff) << 16) |
                     ((hmac[offset + 2] & 0xff) << 8) |
                     (hmac[offset + 3] & 0xff);
                     
        const strCode = (code % 1000000).toString().padStart(6, '0');
        return { code: strCode, remaining: timeStep - (epoch % timeStep) };
    } catch (e) {
        console.error("TOTP generation failed", e);
        return null;
    }
}

let totpInterval = null;

function startTOTPUpdate(secret) {
    if (totpInterval) clearInterval(totpInterval);
    
    const displayArea = document.getElementById('totp_display_area');
    const codeEl = document.getElementById('totp_code');
    const timerEl = document.getElementById('totp_timer');
    const progressBar = document.getElementById('totp_progress_bar');
    
    if (!secret) {
        displayArea.style.display = 'none';
        return;
    }
    
    displayArea.style.display = 'block';
    
    const update = async function() {
        const result = await generateTOTP(secret);
        if (result) {
            codeEl.textContent = result.code;
            timerEl.textContent = '更新まで: ' + result.remaining + '秒';
            if (progressBar) {
                progressBar.style.width = ((result.remaining / 30) * 100) + '%';
            }
        } else {
            codeEl.textContent = 'Invalid Secret';
            timerEl.textContent = '';
            if (progressBar) progressBar.style.width = '0%';
        }
    };
    
    update();
    totpInterval = setInterval(update, 1000);
}

function stopTOTPUpdate() {
    if (totpInterval) clearInterval(totpInterval);
    totpInterval = null;
}

function resetAutoLogoutTimer() {
    if (autoLogoutTimer) clearTimeout(autoLogoutTimer);
    
    const minutes = parseInt(localStorage.getItem(CONSTANTS.STORAGE.AUTO_LOGOUT) || '0');
    if (minutes > 0) {
        autoLogoutTimer = setTimeout(() => {
            if (currentUser) {
                signOut(auth).then(() => location.reload());
            } else {
                location.reload();
            }
        }, minutes * 60 * 1000);
    }
}

// --- Main App Logic ---

function generatePassword() {
    let len = 16;
    const lengthInput = document.getElementById('password_length');
    if (lengthInput) len = parseInt(lengthInput.value);
    
    const useUpper = document.getElementById('include_uppercase') ? document.getElementById('include_uppercase').checked : true;
    const useNumbers = document.getElementById('include_numbers') ? document.getElementById('include_numbers').checked : true;
    const useSymbols = document.getElementById('include_symbols') ? document.getElementById('include_symbols').checked : false;

    const password = generatePasswordString(len, useUpper, useNumbers, useSymbols);

    const autoMakeEl = document.getElementById('auto_make_password');
    if (autoMakeEl) autoMakeEl.textContent = password;

    const strength = calculatePasswordStrength(password);
    const resultElement = document.getElementById('maker_pass_strength');
    const crackTimeElement = document.getElementById('maker_pass_crack_time');

    if (resultElement) {
        if (strength < 2) {
            resultElement.textContent = '弱いパスワード';
            resultElement.style.color = '#d32f2f';
        } else if (strength < 4) {
            resultElement.textContent = '中程度のパスワード';
            resultElement.style.color = '#f57c00';
        } else {
            resultElement.textContent = '強いパスワード';
            resultElement.style.color = '#388e3c';
        }
    }

    if (crackTimeElement) {
        crackTimeElement.textContent = calculateCrackTime(password);
    }

    // Debounce history save to prevent spamming while dragging slider
    if (historyDebounceTimer) clearTimeout(historyDebounceTimer);
    historyDebounceTimer = setTimeout(() => {
        addToGeneratorHistory(password);
    }, 500);
}

function updateDetailStrength(password) {
    const strength = calculatePasswordStrength(password);
    const resultElement = document.getElementById('detail_pass_strength');
    const crackTimeElement = document.getElementById('detail_pass_crack_time');
    
    if (!password) {
            resultElement.textContent = '';
            if (crackTimeElement) crackTimeElement.textContent = '';
            return;
    }

    if (strength < 2) {
        resultElement.textContent = '弱いパスワード';
        resultElement.style.color = '#d32f2f';
    } else if (strength < 4) {
        resultElement.textContent = '中程度のパスワード';
        resultElement.style.color = '#f57c00';
    } else {
        resultElement.textContent = '強いパスワード';
        resultElement.style.color = '#388e3c';
    }

    if (crackTimeElement) {
        crackTimeElement.textContent = calculateCrackTime(password);
    }
}

function addToGeneratorHistory(password) {
    const key = CONSTANTS.STORAGE.GENERATOR_HISTORY;
    let history = JSON.parse(localStorage.getItem(key) || '[]');
    
    // Don't add if same as last one (top of list)
    if (history.length > 0 && history[0] === password) return;

    history.unshift(password);
    if (history.length > 20) history = history.slice(0, 20);
    
    localStorage.setItem(key, JSON.stringify(history));
    renderGeneratorHistory();
}

function renderGeneratorHistory() {
    const list = document.getElementById('maker_history_list');
    if (!list) return;
    
    const history = JSON.parse(localStorage.getItem(CONSTANTS.STORAGE.GENERATOR_HISTORY) || '[]');
    list.innerHTML = '';
    
    if (history.length === 0) {
        list.textContent = '履歴はありません';
        return;
    }

    history.forEach(pass => {
        const item = document.createElement('div');
        item.className = 'history-item';
        item.style.cursor = 'pointer';
        item.title = 'クリックしてコピー';
        
        const text = document.createElement('span');
        text.textContent = pass;
        text.style.fontFamily = 'monospace';
        text.style.overflow = 'hidden';
        text.style.textOverflow = 'ellipsis';
        text.style.whiteSpace = 'nowrap';
        text.style.flex = '1';
        text.style.marginRight = '8px';

        const copyIcon = document.createElement('m3e-icon');
        copyIcon.name = 'content_copy';
        copyIcon.style.fontSize = '16px';

        item.appendChild(text);
        item.appendChild(copyIcon);
        
        item.addEventListener('click', () => {
            copyToClipboard(pass, 'パスワードをコピーしました');
        });
        
        list.appendChild(item);
    });
}

// --- Drag and Drop Handlers ---

function handleDragStart(e) {
    this.style.opacity = '0.4';
    dragSrcEl = this;
    e.dataTransfer.effectAllowed = 'move';
}

function handleDragOver(e) {
    if (e.preventDefault) {
        e.preventDefault();
    }
    e.dataTransfer.dropEffect = 'move';
    this.classList.add('over');
    return false;
}

function handleDragLeave(e) {
    this.classList.remove('over');
}

async function handleDrop(e) {
    if (e.stopPropagation) {
        e.stopPropagation();
    }
    if (dragSrcEl !== this) {
        const srcIndex = parseInt(dragSrcEl.dataset.index);
        const targetIndex = parseInt(this.dataset.index);
        
        if (!isNaN(srcIndex) && !isNaN(targetIndex) && srcIndex !== targetIndex) {
             const item = savedPasswords[srcIndex];
             savedPasswords.splice(srcIndex, 1);
             savedPasswords.splice(targetIndex, 0, item);
             
             if (!currentUser) await savePasswordsData();
             renderPasswordList(document.getElementById('fld').value);
        }
    }
    return false;
}

function handleDragEnd(e) {
    this.style.opacity = '1';
    document.querySelectorAll('m3e-nav-menu-item').forEach(item => item.classList.remove('over'));
}

function renderPasswordList(filterText) {
    const navMenu = document.querySelector('m3e-nav-menu');
    const favList = document.getElementById('favorite_list');
    const passwordList = document.getElementById('password_list');

    // Clear lists
    favList.querySelectorAll('m3e-nav-menu-item').forEach(item => item.remove());
    
    // Remove dynamic groups
    const groups = navMenu.querySelectorAll('m3e-nav-menu-item-group:not(#favorite_list)');
    groups.forEach(g => g.remove());

    const categories = {};
    const categoryNames = new Set();

    savedPasswords.forEach((item, index) => {
        if (filterText && !item.title.toLowerCase().includes(filterText.toLowerCase()) && 
            !(item.website || '').toLowerCase().includes(filterText.toLowerCase())) {
            return;
        }

        if (item.favorite) {
            addPasswordToUI(item, index, favList);
        } else {
            const cat = item.category || 'Passwords';
            if (!categories[cat]) {
                categories[cat] = [];
            }
            categories[cat].push({item: item, index: index});
        }
        if (item.category) categoryNames.add(item.category);
    });

    // Create groups
    Object.keys(categories).sort().forEach(catName => {
        const group = document.createElement('m3e-nav-menu-item-group');
        const heading = document.createElement('m3e-heading');
        heading.slot = 'label';
        heading.variant = 'label';
        heading.size = 'large';
        heading.textContent = catName;
        group.appendChild(heading);
        
        categories[catName].forEach(data => {
            addPasswordToUI(data.item, data.index, group);
        });
        
        navMenu.appendChild(group);
    });

    // Update Datalist
    const dataList = document.getElementById('category_list');
    if (dataList) {
        dataList.innerHTML = '';
        categoryNames.forEach(cat => {
            const opt = document.createElement('option');
            opt.value = cat;
            dataList.appendChild(opt);
        });
    }
}

function addPasswordToUI(item, index, listGroup) {
    const newItem = document.createElement('m3e-nav-menu-item');
    newItem.style.position = 'relative';
    
    // Drag and Drop logic (simplified for module)
    newItem.draggable = true;
    newItem.dataset.index = index;
    newItem.addEventListener('dragstart', handleDragStart);
    newItem.addEventListener('dragover', handleDragOver);
    newItem.addEventListener('dragleave', handleDragLeave);
    newItem.addEventListener('drop', handleDrop);
    newItem.addEventListener('dragend', handleDragEnd);
    
    let icon;
    if (item.website) {
        try {
            const domain = new URL(item.website).hostname;
            icon = document.createElement('img');
            icon.src = 'https://www.google.com/s2/favicons?domain=' + domain + '&sz=64';
            icon.style.width = '24px';
            icon.style.height = '24px';
            icon.style.objectFit = 'contain';
        } catch (e) {
            icon = document.createElement('m3e-icon');
            icon.name = 'public';
        }
    } else {
        icon = document.createElement('m3e-icon');
        icon.name = 'key';
    }
    
    icon.slot = 'icon';

    const strength = calculatePasswordStrength(item.password);
    let strengthColor = '#388e3c'; // Green
    if (strength < 2) {
        strengthColor = '#d32f2f'; // Red
    } else if (strength < 4) {
        strengthColor = '#f57c00'; // Orange
    }

    if (icon.tagName.toLowerCase() === 'm3e-icon' && icon.name === 'key') {
        icon.style.color = strengthColor;
    }

    const label = document.createElement('span');
    label.slot = 'label';
    label.textContent = item.title;
    label.style.color = strengthColor;

    newItem.appendChild(icon);
    newItem.appendChild(label);

    // Favorite Button
    const favBtn = document.createElement('m3e-icon-button');
    favBtn.style.position = 'absolute';
    favBtn.style.right = '8px';
    favBtn.style.top = '50%';
    favBtn.style.transform = 'translateY(-50%)';
    favBtn.style.zIndex = '2';
    const favIcon = document.createElement('m3e-icon');
    favIcon.name = item.favorite ? 'star' : 'star_border';
    if (item.favorite) favIcon.style.color = '#fbc02d';
    favBtn.appendChild(favIcon);

    favBtn.addEventListener('click', async function(e) {
        e.stopPropagation();
        item.favorite = !item.favorite;
        await saveOrUpdateItem(item, index);
    });
    newItem.appendChild(favBtn);

    // Click to open detail
    newItem.addEventListener('click', function() {
        currentDetailIndex = index;
        const dialog = document.getElementById('detail_password_dialog');
        
        document.getElementById('detail_pass_title').value = item.title || '';
        document.getElementById('detail_pass_category').value = item.category || '';
        document.getElementById('detail_pass_website').value = item.website || '';
        document.getElementById('detail_pass_username').value = item.username || '';
        document.getElementById('detail_pass_value').value = item.password || '';
        document.getElementById('detail_pass_secret').value = item.secret || '';
        
        // Store docId for cloud updates
        dialog.dataset.docId = item.id;
        
        const dFavIcon = document.getElementById('detail_pass_favorite_btn').querySelector('m3e-icon');
        dFavIcon.name = item.favorite ? 'star' : 'star_border';
        dFavIcon.style.color = item.favorite ? '#fbc02d' : '';
        
        const lastMod = item.lastModified ? new Date(item.lastModified).toLocaleString() : '-';
        document.getElementById('detail_last_modified').textContent = lastMod;

        const history = item.history || [];
        document.getElementById('detail_revision_count').textContent = history.length;

        const historyList = document.getElementById('detail_history_list');
        historyList.innerHTML = '';
        if (history.length === 0) {
            historyList.textContent = '変更履歴はありません。';
        } else {
            history.slice().reverse().forEach(h => {
                const div = document.createElement('div');
                div.className = 'history-item';

                const infoDiv = document.createElement('div');
                infoDiv.style.flex = '1';
                const dateStr = new Date(h.date).toLocaleString();
                infoDiv.innerHTML = `<div class="font-bold text-small">${dateStr}</div>` +
                                `<div class="text-small" style="opacity: 0.8;">Title: ${h.title || '-'}</div>` +
                                `<div class="text-small" style="opacity: 0.8;">User: ${h.username || '-'}</div>`;
                
                const restoreBtn = document.createElement('button');
                restoreBtn.textContent = '復元';
                restoreBtn.type = 'button';
                restoreBtn.style.marginLeft = '8px';
                restoreBtn.className = 'cursor-pointer';
                
                restoreBtn.addEventListener('click', function() {
                    showConfirmDialog('この履歴の内容を入力フォームに反映しますか？').then(res => {
                        if (res) {
                            document.getElementById('detail_pass_title').value = h.title || '';
                            document.getElementById('detail_pass_category').value = h.category || '';
                            document.getElementById('detail_pass_website').value = h.website || '';
                            document.getElementById('detail_pass_username').value = h.username || '';
                            document.getElementById('detail_pass_value').value = h.password || '';
                            document.getElementById('detail_pass_secret').value = h.secret || '';
                            
                            updateDetailStrength(h.password || '');
                            startTOTPUpdate(h.secret || '');
                        }
                    });
                });

                div.appendChild(infoDiv);
                div.appendChild(restoreBtn);
                historyList.appendChild(div);
            });
        }

        updateDetailStrength(item.password || '');
        startTOTPUpdate(item.secret);
        dialog.open = true;
    });

    listGroup.appendChild(newItem);
}

// --- Storage Operations (Unified) ---

async function saveOrUpdateItem(item, index) {
    if (currentUser) {
        // Cloud Mode
        try {
            const encryptedPassword = await encryptCloud(item.password);
            const dataToSave = {
                uid: currentUser.uid,
                title: item.title,
                category: item.category,
                website: item.website,
                username: item.username,
                password: encryptedPassword,
                secret: item.secret,
                favorite: item.favorite,
                lastModified: item.lastModified,
                history: item.history || []
            };

            if (item.id) {
                await updateDoc(doc(db, "passwords", item.id), dataToSave);
            } else {
                await addDoc(collection(db, "passwords"), dataToSave);
            }
            // Note: onSnapshot will handle the UI update
        } catch (e) {
            console.error("Error saving to cloud:", e);
            showSnackbar("保存に失敗しました: " + e.message);
        }
    } else {
        // Local Mode
        if (index !== undefined && index !== -1) {
            savedPasswords[index] = item;
        } else {
            item.id = crypto.randomUUID();
            savedPasswords.push(item);
        }
        await savePasswordsData();
        renderPasswordList(document.getElementById('fld').value);
    }
}

async function deleteItem(index) {
    if (currentUser) {
        const item = savedPasswords[index];
        if (item && item.id) {
            try {
                await deleteDoc(doc(db, "passwords", item.id));
                // onSnapshot updates UI
            } catch (e) {
                console.error("Error deleting from cloud:", e);
                showSnackbar("削除に失敗しました");
            }
        }
    } else {
        savedPasswords.splice(index, 1);
        await savePasswordsData();
        renderPasswordList(document.getElementById('fld').value);
    }
}

// --- Initialization & Auth ---

function initFirestoreSync(user) {
    console.log("Sync initialized for user:", user.uid);
    const q = query(collection(db, "passwords"), where("uid", "==", user.uid));
    
    onSnapshot(q, async (querySnapshot) => {
        const newPasswords = [];
        for (const doc of querySnapshot.docs) {
            const data = doc.data();
            const decryptedPassword = await decryptCloud(data.password);
            newPasswords.push({
                id: doc.id,
                ...data,
                password: decryptedPassword
            });
        }
        savedPasswords = newPasswords;
        renderPasswordList(document.getElementById('fld').value);
    });
}

async function initLocalApp() {
    const encrypted = localStorage.getItem(CONSTANTS.STORAGE.PASSWORDS);
    if (encrypted && appKey) {
        try {
            savedPasswords = await decryptLocal(encrypted, appKey);
        } catch (e) {
            console.error(e);
            savedPasswords = [];
        }
    } else {
        savedPasswords = [];
    }
    renderPasswordList();
    document.getElementById('warning_dialog').open = true;
}

// Auth State Listener
onAuthStateChanged(auth, (user) => {
    if (user) {
        console.log("User logged in:", user.email);
        currentUser = user;
        const loginDialog = document.getElementById('login_dialog');
        if (loginDialog) loginDialog.open = false;
        initFirestoreSync(user);
    } else {
        currentUser = null;
        // Check for local master auth
        const masterAuth = JSON.parse(localStorage.getItem(CONSTANTS.STORAGE.MASTER_AUTH));
        if (!masterAuth) {
            document.getElementById('setup_dialog').open = true;
        } else {
            document.getElementById('login_dialog').open = true;
        }
    }
});

// --- Event Listeners ---

document.addEventListener('DOMContentLoaded', () => {
    // Password Checker
    const passCheckInput = document.getElementById('pass_check_form');
    if (passCheckInput) {
        passCheckInput.addEventListener('input', (e) => {
            const password = e.target.value;
            const strength = calculatePasswordStrength(password);
            const resultElement = document.getElementById('pass_check_result');
            const crackTimeElement = document.getElementById('pass_crack_time');

            if (resultElement) {
                if (!password) {
                    resultElement.textContent = '';
                } else if (strength < 2) {
                    resultElement.textContent = '弱いパスワード';
                    resultElement.style.color = '#d32f2f';
                } else if (strength < 4) {
                    resultElement.textContent = '中程度のパスワード';
                    resultElement.style.color = '#f57c00';
                } else {
                    resultElement.textContent = '強いパスワード';
                    resultElement.style.color = '#388e3c';
                }
            }

            if (crackTimeElement) {
                crackTimeElement.textContent = password ? calculateCrackTime(password) : '';
            }
        });
    }

    // Setup Dialog
    document.getElementById('setup_btn')?.addEventListener('click', async () => {
        const user = document.getElementById('setup_username').value;
        const pass = document.getElementById('setup_password').value;
        const conf = document.getElementById('setup_password_confirm').value;

        if (user && pass && pass === conf) {
            const salt = await generateSalt();
            const saltB64 = arrayBufferToBase64(salt);
            const hash = await hashPassword(pass, salt);
            
            appKey = await deriveKey(pass, salt);
            
            localStorage.setItem(CONSTANTS.STORAGE.MASTER_AUTH, JSON.stringify({ 
                username: user, 
                hash: hash,
                salt: saltB64
            }));
            
            savedPasswords = [];
            await savePasswordsData();
            
            document.getElementById('setup_dialog').open = false;
            initLocalApp();
        } else {
            showAlertDialog('入力内容を確認してください。');
        }
    });

    // Login Dialog
    document.getElementById('login_btn')?.addEventListener('click', async () => {
        const user = document.getElementById('login_username').value;
        const pass = document.getElementById('login_password').value;
        const masterAuth = JSON.parse(localStorage.getItem(CONSTANTS.STORAGE.MASTER_AUTH));

        if (!masterAuth) return;

        if (user !== masterAuth.username) {
             showAlertDialog('ユーザー名またはパスワードが間違っています。');
             return;
        }

        if (masterAuth.hash && masterAuth.salt) {
            const hash = await hashPassword(pass, masterAuth.salt);
            if (hash === masterAuth.hash) {
                appKey = await deriveKey(pass, masterAuth.salt);
                document.getElementById('login_dialog').open = false;
                initLocalApp();
                return;
            }
        }
        showAlertDialog('ユーザー名またはパスワードが間違っています。');
    });

    // Google Login
    document.getElementById('google_login_btn')?.addEventListener('click', () => {
        const provider = new GoogleAuthProvider();
        signInWithPopup(auth, provider)
            .catch((error) => {
                console.error("Login failed:", error);
                showAlertDialog("Googleログインに失敗しました: " + error.message);
            });
    });

    // Logout
    document.getElementById('logout_btn')?.addEventListener('click', () => {
        showConfirmDialog("ログアウトしますか？").then(res => {
            if (res) {
                if (currentUser) {
                    signOut(auth).then(() => location.reload());
                } else {
                    location.reload();
                }
            }
        });
    });

    // Save New Password
    document.getElementById('save_new_password_btn')?.addEventListener('click', async () => {
        const title = document.getElementById('new_pass_title').value;
        if (title) {
            const newItem = {
                title: title,
                category: document.getElementById('new_pass_category').value,
                website: document.getElementById('new_pass_website').value,
                username: document.getElementById('new_pass_username').value,
                password: document.getElementById('new_pass_value').value,
                secret: document.getElementById('new_pass_secret').value,
                favorite: false,
                lastModified: Date.now(),
                history: []
            };
            
            await saveOrUpdateItem(newItem);
            
            // Clear inputs
            document.getElementById('new_pass_title').value = '';
            document.getElementById('new_pass_category').value = '';
            document.getElementById('new_pass_website').value = '';
            document.getElementById('new_pass_username').value = '';
            document.getElementById('new_pass_value').value = '';
            document.getElementById('new_pass_secret').value = '';
            showSnackbar('新しいパスワードを作成しました');
        }
    });

    // Update Password
    document.getElementById('update_password_btn')?.addEventListener('click', async () => {
        if (currentDetailIndex > -1) {
            const title = document.getElementById('detail_pass_title').value;
            if (title) {
                const oldItem = savedPasswords[currentDetailIndex];
                const newItem = {
                    ...oldItem,
                    title: title,
                    category: document.getElementById('detail_pass_category').value,
                    website: document.getElementById('detail_pass_website').value,
                    username: document.getElementById('detail_pass_username').value,
                    password: document.getElementById('detail_pass_value').value,
                    secret: document.getElementById('detail_pass_secret').value,
                    favorite: document.getElementById('detail_pass_favorite_btn').querySelector('m3e-icon').name === 'star'
                };

                // Check changes for history
                const hasChanged = (oldItem.title !== newItem.title) ||
                                   (oldItem.password !== newItem.password) ||
                                   (oldItem.username !== newItem.username);
                
                if (hasChanged) {
                    const history = oldItem.history || [];
                    history.push({
                        date: Date.now(),
                        title: oldItem.title,
                        category: oldItem.category,
                        website: oldItem.website,
                        username: oldItem.username,
                        password: oldItem.password,
                        secret: oldItem.secret
                    });
                    newItem.history = history;
                    newItem.lastModified = Date.now();
                }

                await saveOrUpdateItem(newItem, currentDetailIndex);
                document.getElementById('detail_password_dialog').open = false;
                showSnackbar('パスワードを更新しました');
            }
        }
    });

    // Delete Password
    document.getElementById('delete_password_btn')?.addEventListener('click', () => {
        if (currentDetailIndex > -1) {
            showConfirmDialog("このパスワードを削除してもよろしいですか？").then(async res => {
                if (res) {
                    await deleteItem(currentDetailIndex);
                    document.getElementById('detail_password_dialog').open = false;
                    showSnackbar('パスワードを削除しました');
                }
            });
        }
    });

    // Generators
    document.getElementById('generate_new_pass_btn')?.addEventListener('click', () => {
        const password = generatePasswordString(16, true, true, true);
        document.getElementById('new_pass_value').value = password;
    });

    document.getElementById('generate_detail_pass_btn')?.addEventListener('click', () => {
        const password = generatePasswordString(16, true, true, true);
        document.getElementById('detail_pass_value').value = password;
        updateDetailStrength(password);
    });

    document.getElementById('regenerate_password_btn')?.addEventListener('click', generatePassword);
    document.getElementById('password_length')?.addEventListener('input', generatePassword);
    document.getElementById('include_uppercase')?.addEventListener('change', generatePassword);
    document.getElementById('include_numbers')?.addEventListener('change', generatePassword);
    document.getElementById('include_symbols')?.addEventListener('change', generatePassword);
    document.getElementById('copy_password_btn')?.addEventListener('click', () => {
        copyToClipboard(document.getElementById('auto_make_password').textContent, "パスワードをコピーしました");
    });

    // Search
    document.getElementById('fld')?.addEventListener('input', (e) => {
        renderPasswordList(e.target.value);
    });

    // Detail Dialog Events
    document.getElementById('detail_password_dialog')?.addEventListener('closed', stopTOTPUpdate);
    document.getElementById('detail_pass_value')?.addEventListener('input', (e) => updateDetailStrength(e.target.value));
    document.getElementById('open_website_btn')?.addEventListener('click', () => {
        let url = document.getElementById('detail_pass_website').value;
        if (url) {
            if (!/^https?:\/\//i.test(url)) url = 'http://' + url;
            window.open(url, '_blank');
        }
    });

    document.getElementById('copy_detail_pass_btn')?.addEventListener('click', () => {
        const password = document.getElementById('detail_pass_value').value;
        copyToClipboard(password, "パスワードをコピーしました");
    });

    document.getElementById('copy_detail_username_btn')?.addEventListener('click', () => {
        const username = document.getElementById('detail_pass_username').value;
        copyToClipboard(username, "ユーザー名をコピーしました");
    });

    document.getElementById('clear_history_btn')?.addEventListener('click', () => {
        if (currentDetailIndex > -1) {
            showConfirmDialog("このパスワードの変更履歴をすべて削除しますか？").then(async res => {
                if (res) {
                    const item = savedPasswords[currentDetailIndex];
                    item.history = [];
                    await saveOrUpdateItem(item, currentDetailIndex);
                    document.getElementById('detail_revision_count').textContent = '0';
                    document.getElementById('detail_history_list').innerHTML = '変更履歴はありません。';
                    showSnackbar('変更履歴をクリアしました');
                }
            });
        }
    });

    document.getElementById('clear_maker_history_btn')?.addEventListener('click', () => {
        showConfirmDialog("生成履歴をすべて削除しますか？").then(res => {
            if (res) {
                localStorage.removeItem(CONSTANTS.STORAGE.GENERATOR_HISTORY);
                renderGeneratorHistory();
                showSnackbar('生成履歴をクリアしました');
            }
        });
    });

    document.getElementById('totp_code')?.addEventListener('click', function() {
        const code = this.textContent;
        if (code && code !== 'Invalid Secret') {
            copyToClipboard(code, '2FAコードをコピーしました');
        }
    });

    document.getElementById('detail_pass_favorite_btn')?.addEventListener('click', function() {
        const icon = this.querySelector('m3e-icon');
        if (icon.name === 'star') {
            icon.name = 'star_border';
            icon.style.color = '';
        } else {
            icon.name = 'star';
            icon.style.color = '#fbc02d';
        }
    });

    // Initial Generator Run
    generatePassword();
    renderGeneratorHistory();

    // Theme Toggle
    const themeToggleBtn = document.getElementById('theme_toggle_btn');
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', () => {
            const isDark = document.body.classList.toggle('dark-theme');
            const icon = themeToggleBtn.querySelector('m3e-icon');
            icon.name = isDark ? 'light_mode' : 'dark_mode';
            localStorage.setItem(CONSTANTS.STORAGE.THEME, isDark ? 'dark' : 'light');
        });
        
        const savedTheme = localStorage.getItem(CONSTANTS.STORAGE.THEME);
        if (savedTheme === 'dark') {
            document.body.classList.add('dark-theme');
            themeToggleBtn.querySelector('m3e-icon').name = 'light_mode';
        }
    }

    // --- Default Username Features ---
    
    // Load saved default username into settings input
    const savedDefaultUser = localStorage.getItem(CONSTANTS.STORAGE.DEFAULT_USER);
    if (savedDefaultUser) {
        const settingInput = document.getElementById('setting_default_username');
        if (settingInput) settingInput.value = savedDefaultUser;
    }

    // Load saved auto logout
    const savedAutoLogout = localStorage.getItem(CONSTANTS.STORAGE.AUTO_LOGOUT);
    if (savedAutoLogout) {
        const settingInput = document.getElementById('setting_auto_logout');
        if (settingInput) settingInput.value = savedAutoLogout;
    }

    // Save general settings
    document.getElementById('save_general_settings_btn')?.addEventListener('click', () => {
        const defaultUser = document.getElementById('setting_default_username').value;
        const autoLogout = document.getElementById('setting_auto_logout').value;
        localStorage.setItem(CONSTANTS.STORAGE.DEFAULT_USER, defaultUser);
        localStorage.setItem(CONSTANTS.STORAGE.AUTO_LOGOUT, autoLogout);
        showSnackbar('設定を保存しました');
        document.getElementById('settings_dialog').open = false;
        resetAutoLogoutTimer();
    });

    // Fill default username in "Add Password" dialog
    document.getElementById('fill_new_pass_default_username_btn')?.addEventListener('click', () => {
        const val = localStorage.getItem(CONSTANTS.STORAGE.DEFAULT_USER);
        if (val) {
            document.getElementById('new_pass_username').value = val;
            showSnackbar('デフォルトユーザー名を入力しました');
        } else {
            showSnackbar('デフォルトユーザー名が設定されていません');
        }
    });

    // Fill default username in "Detail" dialog
    document.getElementById('fill_default_username_btn')?.addEventListener('click', () => {
        const val = localStorage.getItem(CONSTANTS.STORAGE.DEFAULT_USER);
        if (val) {
            document.getElementById('detail_pass_username').value = val;
            showSnackbar('デフォルトユーザー名を入力しました');
        } else {
            showSnackbar('デフォルトユーザー名が設定されていません');
        }
    });

    // Setup Password Toggles
    const passwordIds = [
        'new_pass_value', 'detail_pass_value', 'setup_password', 'setup_password_confirm',
        'login_password', 'setting_current_pass', 'setting_new_pass', 'setting_new_pass_confirm',
        'new_pass_secret', 'detail_pass_secret'
    ];
    passwordIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.type = 'password';
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.style.cssText = 'background:transparent; border:none; cursor:pointer; padding:0; margin-left:4px;';
            const icon = document.createElement('m3e-icon');
            icon.name = 'visibility';
            btn.appendChild(icon);
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                if (el.type === 'password') {
                    el.type = 'text';
                    icon.name = 'visibility_off';
                } else {
                    el.type = 'password';
                    icon.name = 'visibility';
                }
            });
            if (el.parentNode) el.parentNode.insertBefore(btn, el.nextSibling);
        }
    });
    
    // Sort Feature
    const searchField = document.getElementById('search_passwords');
    if (searchField && searchField.parentNode) {
        const sortContainer = document.createElement('div');
        sortContainer.className = 'sort-container';
        
        const sortSelect = document.createElement('select');
        sortSelect.className = 'sort-select';
        
        const options = [
            { value: '', text: '並び替え...' },
            { value: 'title_asc', text: '名前 (A-Z)' },
            { value: 'title_desc', text: '名前 (Z-A)' },
            { value: 'strength_asc', text: '強度 (弱い順)' },
            { value: 'strength_desc', text: '強度 (強い順)' },
            { value: 'updated_desc', text: '更新日 (新しい順)' },
            { value: 'updated_asc', text: '更新日 (古い順)' }
        ];
        
        options.forEach(opt => {
            const o = document.createElement('option');
            o.value = opt.value;
            o.textContent = opt.text;
            sortSelect.appendChild(o);
        });
        
        sortSelect.addEventListener('change', async function() {
            const val = this.value;
            if (!val) return;
            
            if (savedPasswords.length > 0) {
                savedPasswords.sort((a, b) => {
                    switch (val) {
                        case 'title_asc': return (a.title || '').localeCompare(b.title || '');
                        case 'title_desc': return (b.title || '').localeCompare(a.title || '');
                        case 'strength_asc': return calculatePasswordStrength(a.password) - calculatePasswordStrength(b.password);
                        case 'strength_desc': return calculatePasswordStrength(b.password) - calculatePasswordStrength(a.password);
                        case 'updated_desc': return (b.lastModified || 0) - (a.lastModified || 0);
                        case 'updated_asc': return (a.lastModified || 0) - (b.lastModified || 0);
                        default: return 0;
                    }
                });
                
                // If local, save order. If cloud, just re-render (order not persisted in this simple impl)
                if (!currentUser) await savePasswordsData();
                renderPasswordList(document.getElementById('fld').value);
                showSnackbar('リストを並び替えました');
            }
            this.value = '';
        });
        
        sortContainer.appendChild(sortSelect);
        searchField.parentNode.insertBefore(sortContainer, searchField.nextSibling);
    }

    // Import/Export Logic (Simplified for brevity, similar to original script.js)
    const deleteAllBtn = document.getElementById('delete_all_data_btn');
    if (deleteAllBtn && deleteAllBtn.parentNode) {
        const container = document.createElement('div');
        container.className = 'data-management-container';

        const title = document.createElement('h4');
        title.textContent = 'データ管理';
        title.className = 'mt-2 mb-2';
        container.appendChild(title);

        const btnContainer = document.createElement('div');
        btnContainer.className = 'flex-row-center-gap';

        const exportBtn = document.createElement('button');
        exportBtn.textContent = 'エクスポート (JSON)';
        exportBtn.type = 'button';
        exportBtn.className = 'cursor-pointer';
        exportBtn.style.padding = '8px 16px';
        
        exportBtn.addEventListener('click', () => {
            const data = JSON.stringify(savedPasswords, null, 2);
            const blob = new Blob([data], {type: 'application/json'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'soul_passwords.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        });

        const importBtn = document.createElement('button');
        importBtn.textContent = 'インポート (JSON)';
        importBtn.type = 'button';
        importBtn.className = 'cursor-pointer';
        importBtn.style.padding = '8px 16px';

        const fileInput = document.createElement('input');
        fileInput.type = 'file';
        fileInput.accept = '.json';
        fileInput.style.display = 'none';

        importBtn.addEventListener('click', () => fileInput.click());

        fileInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (e) => {
                try {
                    const importedData = JSON.parse(e.target.result);
                    if (Array.isArray(importedData)) {
                        showConfirmDialog(`現在のリストに ${importedData.length} 件のデータを追加しますか？`).then(async res => {
                            if (res) {
                                importedData.forEach(item => {
                                    if (!item.lastModified) item.lastModified = Date.now();
                                    // If cloud mode, we should probably add them one by one, but for now just local array
                                    if (currentUser) {
                                        saveOrUpdateItem(item); // Will trigger async saves
                                    } else {
                                        savedPasswords.push(item);
                                    }
                                });
                                if (!currentUser) {
                                    await savePasswordsData();
                                    renderPasswordList();
                                }
                                showAlertDialog('インポートが完了しました。');
                            }
                        });
                    }
                } catch (error) {
                    console.error(error);
                    showAlertDialog('ファイルの読み込みに失敗しました。');
                }
                e.target.value = '';
            };
            reader.readAsText(file);
        });

        btnContainer.appendChild(exportBtn);
        btnContainer.appendChild(importBtn);
        container.appendChild(btnContainer);
        container.appendChild(fileInput);

        deleteAllBtn.parentNode.insertBefore(container, deleteAllBtn);
    }

    // Initialize Auto Logout
    resetAutoLogoutTimer();
    ['mousedown', 'keydown', 'touchstart', 'scroll'].forEach(evt => {
        document.addEventListener(evt, resetAutoLogoutTimer, { passive: true });
    });
    document.body.classList.add('loaded');
});
