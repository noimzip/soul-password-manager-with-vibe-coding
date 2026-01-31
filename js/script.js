// Import Firebase SDKs
import { initializeApp } from "firebase/app";
import { getAuth, signInWithPopup, GoogleAuthProvider, signOut, onAuthStateChanged, reauthenticateWithPopup } from "firebase/auth";
import { getFirestore, collection, addDoc, query, where, onSnapshot, doc, updateDoc, deleteDoc, enableIndexedDbPersistence, setDoc, getDocs, getDoc } from "firebase/firestore";

// Import UI Components
import "@m3e/icon/dist/index.min.js";
import "@m3e/button/dist/index.min.js";
import "@m3e/fab/dist/index.min.js";
import "@m3e/fab-menu/dist/index.min.js";
import "@m3e/dialog/dist/index.min.js";
import "@m3e/icon-button/dist/index.min.js";
import "@m3e/slider/dist/index.min.js";
import "@m3e/form-field/dist/index.min.js";
import "@m3e/app-bar/dist/index.min.js";
import "@m3e/nav-menu/dist/index.min.js";
import "@m3e/divider/dist/index.min.js";
import "@m3e/heading/dist/index.min.js";
import "@m3e/loading-indicator/dist/index.min.js";
import "@m3e/checkbox/dist/index.min.js";
import "@m3e/select/dist/index.min.js";
import "@m3e/option/dist/index.min.js";
import "@m3e/chips/dist/index.min.js";

import { TRANSLATIONS } from './translations.js';
import DOMPurify from 'dompurify';

// --- Firebase Configuration ---
const firebaseConfig = {
    apiKey: import.meta.env.VITE_FIREBASE_APIKEY,
    authDomain: import.meta.env.VITE_FIREBASE_AUTHDOMAIN,
    projectId: import.meta.env.VITE_FIREBASE_PROJECTID,
    storageBucket: import.meta.env.VITE_FIREBASE_STORAGEBUCKET,
    messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGINGSENDERID,
    appId: import.meta.env.VITE_FIREBASE_APPID
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

// --- Log Capture ---
const appLogs = [];
const MAX_LOGS = 100;

function captureLog(level, args) {
    try {
        const msg = args.map(a => {
            if (a instanceof Error) return a.toString() + '\n' + a.stack;
            if (typeof a === 'object') return JSON.stringify(a);
            return String(a);
        }).join(' ');
        appLogs.push(`[${new Date().toISOString()}] [${level}] ${msg}`);
        if (appLogs.length > MAX_LOGS) appLogs.shift();
    } catch (e) {
        // Ignore errors during logging
    }
}

if (import.meta.env.DEV) {
    const originalLog = console.log; console.log = (...args) => { captureLog('INFO', args); originalLog.apply(console, args); };
    const originalWarn = console.warn; console.warn = (...args) => { captureLog('WARN', args); originalWarn.apply(console, args); };
    const originalError = console.error; console.error = (...args) => { captureLog('ERROR', args); originalError.apply(console, args); };
    window.addEventListener('error', (e) => captureLog('UNCAUGHT', [e.message, e.filename, e.lineno]));
}

// Enable Offline Persistence
enableIndexedDbPersistence(db).catch((err) => {
    if (err.code == 'failed-precondition' || err.code == 'unimplemented') {
        console.warn("Firestore persistence could not be enabled:", err.code);
    }
});

// --- Constants & State ---
const CONSTANTS = Object.freeze({
    APP_VERSION: '26.01.25 (Unstable)',
    STORAGE: {
        PASSWORDS: 'soul_passwords',
        MASTER_AUTH: 'soul_master_auth',
        AUTO_LOGOUT: 'soul_auto_logout_minutes',
        DEFAULT_USER: 'soul_default_username',
        THEME: 'soul_theme',
        GENERATOR_HISTORY: 'soul_generator_history',
        LANGUAGE: 'soul_language',
        SIDEBAR_WIDTH: 'soul_sidebar_width',
        THEME_COLOR: 'soul_theme_color',
        REQUIRE_SECOND_AUTH: 'soul_require_second_auth',
        CLOUD_KEY: 'soul_cloud_key',
        REQUIRE_AUTH_ON_DELETE: 'soul_require_auth_on_delete',
        REQUIRE_AUTH_ON_SHOW_COPY: 'soul_require_auth_on_show_copy',
        PASSKEY_FALLBACK: 'soul_passkey_fallback',
        LOGIN_ATTEMPTS_PREFIX: 'soul_login_attempts_',
        PASSKEY_NAMES: 'soul_passkey_names',
        PASSKEY_ENCRYPTED_DATA: 'soul_passkey_encrypted_data'
    }
});

const CRYPTO_CONFIG = Object.freeze({
    PBKDF2_ITERATIONS: 600000,
    SALT_LENGTH: 16,
    IV_LENGTH: 12
});

const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_MINUTES = 5;

const FIXED_ENCRYPTION_SECRET = import.meta.env.VITE_ENCRYPTION_SECRET;

const HYBRID_CONFIG = Object.freeze({
    RSA_ALGO: {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
    },
    AES_ALGO: {
        name: "AES-GCM",
        length: 256
    }
});

const DECRYPTION_ERROR_MARKER = '[[DECRYPTION_FAILED]]';

let appKey = null; // Session key for Local Mode
let cloudKey = null; // Session key for Cloud Mode
let hybridKeyPair = null; // RSA Key Pair for Hybrid Mode
let savedPasswords = []; // In-memory list of decrypted passwords
let currentDetailId = null; // ID of currently opened item
let currentUser = null; // Firebase User
let dragSrcEl = null; // For Drag and Drop
let historyDebounceTimer = null; // Timer for debouncing history saves
let autoLogoutTimer = null; // Timer for auto logout
let currentLang = 'ja'; // Default language
let securityHubLists = {
    weak: [],
    no2fa: [],
    reused: []
};
let isSelectionMode = false;
let selectedIds = new Set();
let deviceCheckUnsubscribe = null;
let newDeviceListenerUnsubscribe = null;
let isTwoPaneMode = false;
let isDetailEditMode = false;
let firestoreSyncUnsubscribe = null;
let contextMenuItem = null;
let searchDebounceTimer = null;
let currentSnackbar = null;
let selectedIconName = null;
let selectedIconImage = null;
let currentIconPickerTarget = null;
const PREDEFINED_ICONS = ['key', 'lock', 'public', 'account_circle', 'mail', 'shopping_cart', 'credit_card', 'account_balance', 'cloud', 'smartphone', 'computer', 'shield', 'vpn_key', 'passkey', 'fingerprint', 'face', 'description', 'notes', 'attachment', 'link', 'apps', 'more_horiz'];


function t(key, params = {}) {
    let str = TRANSLATIONS[currentLang][key] || key;
    for (const [k, v] of Object.entries(params)) {
        str = str.replace(`{${k}}`, v);
    }
    return str;
}

function updateLanguage(lang) {
    if (!TRANSLATIONS[lang]) return;
    currentLang = lang;
    localStorage.setItem(CONSTANTS.STORAGE.LANGUAGE, lang);

    // Update static elements
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (TRANSLATIONS[lang][key]) {
            if (el.tagName === 'INPUT' && el.type === 'button') {
                el.value = TRANSLATIONS[lang][key];
            } else {
                el.innerHTML = TRANSLATIONS[lang][key];
            }
        }
    });

    // Update placeholders
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        const key = el.getAttribute('data-i18n-placeholder');
        if (TRANSLATIONS[lang][key]) {
            el.placeholder = TRANSLATIONS[lang][key];
        }
    });
    
    // Update labels (custom attribute for m3e-form-field if needed, or just rely on inner text if structure allows)
    // m3e-form-field label is an attribute
    document.querySelectorAll('m3e-form-field[data-i18n-label]').forEach(el => {
        const key = el.getAttribute('data-i18n-label');
        if (TRANSLATIONS[lang][key]) {
            el.setAttribute('label', TRANSLATIONS[lang][key]);
        }
    });

    // Update titles (tooltips)
    document.querySelectorAll('[data-i18n-title]').forEach(el => {
        const key = el.getAttribute('data-i18n-title');
        if (TRANSLATIONS[lang][key]) {
            el.title = TRANSLATIONS[lang][key];
        }
    });

    // Re-render lists to update headings/sort options
    renderPasswordList(document.getElementById('fld').value);
    renderGeneratorHistory();
    
}

// Helper to set innerHTML safely using DOMPurify if needed
async function setSafeHTML(element, content) {
    if (!element) return;
    const { default: DOMPurify } = await import('dompurify');
    element.innerHTML = DOMPurify.sanitize(content);
}

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

// --- Crypto Utilities (Cloud Mode - Secure Derived Key) ---
async function deriveCloudKey(password, uid) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
    );
    
    // Use UID as salt to ensure unique keys per user while allowing sync across devices
    const saltBuffer = enc.encode(uid);
    
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

async function getCloudCryptoKey() {
    if (cloudKey) return cloudKey;
    throw new Error("Encryption key not available. Please re-login with master password.");
}

async function calculateCloudVerifier(password, uid) {
    const enc = new TextEncoder();
    // Use UID + suffix as salt to ensure it's distinct from the encryption key derivation
    const salt = enc.encode(uid + "_verifier");
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]
    );
    const derivedBits = await window.crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: CRYPTO_CONFIG.PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },
        keyMaterial,
        256
    );
    return arrayBufferToBase64(derivedBits);
}

async function saveCloudKey(key) {
    try {
        const exported = await window.crypto.subtle.exportKey("jwk", key);
        sessionStorage.setItem(CONSTANTS.STORAGE.CLOUD_KEY, JSON.stringify(exported));
    } catch (e) { console.error("Failed to save key", e); }
}

async function loadCloudKey() {
    try {
        // Migrate/Enforce Session Storage: Remove from localStorage if exists
        if (localStorage.getItem(CONSTANTS.STORAGE.CLOUD_KEY)) {
            localStorage.removeItem(CONSTANTS.STORAGE.CLOUD_KEY);
        }

        const json = sessionStorage.getItem(CONSTANTS.STORAGE.CLOUD_KEY);
        if (!json) return null;
        return await window.crypto.subtle.importKey(
            "jwk",
            JSON.parse(json),
            { name: "AES-GCM" },
            true,
            ["encrypt", "decrypt"]
        );
    } catch (e) { console.error("Failed to load key", e); return null; }
}

function clearCloudKey() {
    sessionStorage.removeItem(CONSTANTS.STORAGE.CLOUD_KEY);
    localStorage.removeItem(CONSTANTS.STORAGE.CLOUD_KEY); // Ensure cleanup
}

async function encryptWithKek(dataObj, key) {
    const enc = new TextEncoder();
    const encoded = enc.encode(JSON.stringify(dataObj));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
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

async function decryptWithKek(jsonStr, key) {
    const raw = JSON.parse(jsonStr);
    const iv = base64ToArrayBuffer(raw.iv);
    const data = base64ToArrayBuffer(raw.data);
    const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        data
    );
    return JSON.parse(new TextDecoder().decode(decrypted));
}

async function getHybridKeys(uid, overrideKey = null) {
    if (hybridKeyPair) return hybridKeyPair;

    const userConfigRef = doc(db, "user_config", uid);
    const snap = await getDoc(userConfigRef);
    
    // KEK derived from Master Password (cloudKey)
    const kek = overrideKey || await getCloudCryptoKey();
    
    if (snap.exists() && snap.data().publicKey && snap.data().encryptedPrivateKey) {
        const pubJwk = JSON.parse(snap.data().publicKey);
        const publicKey = await window.crypto.subtle.importKey(
            "jwk", pubJwk, HYBRID_CONFIG.RSA_ALGO, true, ["encrypt"]
        );

        const privateKeyJwk = await decryptWithKek(snap.data().encryptedPrivateKey, kek);
        const privateKey = await window.crypto.subtle.importKey(
            "jwk", privateKeyJwk, HYBRID_CONFIG.RSA_ALGO, true, ["decrypt"]
        );

        hybridKeyPair = { publicKey, privateKey };
    } else {
        const keyPair = await window.crypto.subtle.generateKey(
            HYBRID_CONFIG.RSA_ALGO,
            true,
            ["encrypt", "decrypt"]
        );
        
        const pubJwk = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
        const privJwk = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);
        
        const encPriv = await encryptWithKek(privJwk, kek);
        
        await setDoc(userConfigRef, {
            publicKey: JSON.stringify(pubJwk),
            encryptedPrivateKey: encPriv
        }, { merge: true });
        
        hybridKeyPair = keyPair;
    }
    
    return hybridKeyPair;
}

async function encryptCloud(plaintext) {
    if (!plaintext) return "";
    try {
        if (!currentUser) throw new Error("No user");
        const keys = await getHybridKeys(currentUser.uid);
        
        // 1. Generate Session Key (AES)
        const sessionKey = await window.crypto.subtle.generateKey(
            HYBRID_CONFIG.AES_ALGO,
            true,
            ["encrypt", "decrypt"]
        );
        
        // 2. Encrypt Data with Session Key
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(plaintext);
        const encryptedData = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            sessionKey,
            encoded
        );
        
        // 3. Encrypt Session Key with RSA Public Key
        const rawSessionKey = await window.crypto.subtle.exportKey("raw", sessionKey);
        const encryptedSessionKey = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            keys.publicKey,
            rawSessionKey
        );
        
        // 4. Package
        return JSON.stringify({
            k: arrayBufferToBase64(encryptedSessionKey),
            iv: arrayBufferToBase64(iv),
            d: arrayBufferToBase64(encryptedData),
            v: 'hybrid-v1'
        });
    } catch (e) {
      console.error("Cloud Encryption failed:", e);
      return plaintext;
    }
}

async function decryptCloud(encryptedBase64) {
    if (!encryptedBase64) return "";
    try {
        let hybridObj;
        try {
            hybridObj = JSON.parse(encryptedBase64);
        } catch (e) {
            // Not JSON, assume old format
            return await decryptCloudOld(encryptedBase64);
        }

        if (!hybridObj.k || !hybridObj.d || !hybridObj.iv) {
             return await decryptCloudOld(encryptedBase64);
        }

        if (!currentUser) throw new Error("No user");
        const keys = await getHybridKeys(currentUser.uid);
        
        // 1. Decrypt Session Key
        const encSessionKey = base64ToArrayBuffer(hybridObj.k);
        const rawSessionKey = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            keys.privateKey,
            encSessionKey
        );
        
        const sessionKey = await window.crypto.subtle.importKey(
            "raw",
            rawSessionKey,
            HYBRID_CONFIG.AES_ALGO,
            false,
            ["decrypt"]
        );
        
        // 2. Decrypt Data
        const iv = base64ToArrayBuffer(hybridObj.iv);
        const encData = base64ToArrayBuffer(hybridObj.d);
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            sessionKey,
            encData
        );
        
        return new TextDecoder().decode(decrypted);
    } catch (e) {
      console.warn("Cloud Decryption failed, returning original:", e);
      return DECRYPTION_ERROR_MARKER;
    }
}

async function decryptCloudOld(encryptedBase64) {
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
      return DECRYPTION_ERROR_MARKER;
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
        // Clear clipboard after 30 seconds for security
        setTimeout(() => {
            navigator.clipboard.writeText('').catch(() => {});
        }, 30000);
    }).catch(function(err) {
        console.error('Copy failed', err);
        showSnackbar(t('copy_fail'));
    });
}

function showDialog(message, isConfirm) {
    return new Promise(function(resolve) {
        const dialog = document.createElement('m3e-dialog');
        
        const content = document.createElement('div');
        content.textContent = message;
        content.style.padding = '10px 0';
        content.style.whiteSpace = 'pre-wrap';
        content.style.lineHeight = '1.5';
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
            const cancelBtn = createBtn(t('no'));
            cancelBtn.addEventListener('click', function() {
                dialog.open = false;
                resolve(false);
                setTimeout(function() { if(dialog.parentNode) dialog.parentNode.removeChild(dialog); }, 500);
            });
            btnContainer.appendChild(cancelBtn);
        }

        const okBtn = createBtn(isConfirm ? 'yes' : 'ok');
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
    if (currentSnackbar) {
        if (currentSnackbar.parentNode) currentSnackbar.parentNode.removeChild(currentSnackbar);
        currentSnackbar = null;
    }

    const el = document.createElement('div');
    el.textContent = message;
    el.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background-color:#323232;color:white;padding:14px 24px;border-radius:4px;z-index:10000;box-shadow:0 2px 5px rgba(0,0,0,0.2);opacity:0;transition:opacity 0.3s;font-family:sans-serif;pointer-events:none;';
    document.body.appendChild(el);
    currentSnackbar = el;
    requestAnimationFrame(function() { el.style.opacity = '1'; });
    setTimeout(function() {
        el.style.opacity = '0';
        setTimeout(function() { if(el.parentNode) el.parentNode.removeChild(el); currentSnackbar = null; }, 300);
    }, 3000);
}

function promptForInput(title, label, defaultValue = '') {
    return new Promise((resolve) => {
        const dialog = document.createElement('m3e-dialog');
        
        const header = document.createElement('span');
        header.slot = 'header';
        header.textContent = title;
        dialog.appendChild(header);

        const content = document.createElement('div');
        content.style.padding = '10px 0';
        
        const field = document.createElement('m3e-form-field');
        field.setAttribute('variant', 'outlined');
        field.setAttribute('label', label);
        field.style.width = '100%';
        
        const input = document.createElement('input');
        input.type = 'text';
        input.value = defaultValue;
        input.placeholder = label;
        input.addEventListener('focus', () => input.select());
        
        field.appendChild(input);
        content.appendChild(field);
        dialog.appendChild(content);

        const actions = document.createElement('div');
        actions.slot = 'actions';
        
        const cancelBtn = document.createElement('m3e-button');
        cancelBtn.setAttribute('variant', 'text');
        cancelBtn.innerHTML = `<span>${t('cancel')}</span>`;
        cancelBtn.addEventListener('click', () => {
            dialog.open = false;
            resolve(null);
            setTimeout(() => { if(dialog.parentNode) dialog.parentNode.removeChild(dialog); }, 500);
        });
        
        const confirmBtn = document.createElement('m3e-button');
        confirmBtn.setAttribute('variant', 'filled');
        confirmBtn.innerHTML = `<span>${t('ok')}</span>`;
        
        const submit = () => {
            const val = input.value;
            dialog.open = false;
            resolve(val);
            setTimeout(() => { if(dialog.parentNode) dialog.parentNode.removeChild(dialog); }, 500);
        };

        confirmBtn.addEventListener('click', submit);
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') submit();
        });

        actions.appendChild(cancelBtn);
        actions.appendChild(confirmBtn);
        dialog.appendChild(actions);

        document.body.appendChild(dialog);
        requestAnimationFrame(() => {
            dialog.open = true;
            setTimeout(() => input.focus(), 100);
        });
    });
}

async function promptForMasterPassword(returnPassword = false, checkUser = null, mode = 'local') {
    return new Promise((resolve) => {
        const dialog = document.createElement('m3e-dialog');
        
        const header = document.createElement('span');
        header.slot = 'header';
        header.textContent = mode === 'cloud' ? t('prompt_cloud_pass') : t('confirm_pass');
        dialog.appendChild(header);

        const content = document.createElement('div');
        content.style.padding = '10px 0';
        
        const field = document.createElement('m3e-form-field');
        field.setAttribute('variant', 'outlined');
        field.setAttribute('label', t('master_pass'));
        field.style.width = '100%';
        
        const input = document.createElement('input');
        input.type = 'password';
        input.placeholder = t('master_pass');
        
        field.appendChild(input);
        content.appendChild(field);
        dialog.appendChild(content);

        const actions = document.createElement('div');
        actions.slot = 'actions';
        
        const cancelBtn = document.createElement('m3e-button');
        cancelBtn.setAttribute('variant', 'text');
        cancelBtn.innerHTML = `<span>${t('cancel')}</span>`;
        cancelBtn.addEventListener('click', () => {
            dialog.open = false;
            resolve(false);
            setTimeout(() => { if(dialog.parentNode) dialog.parentNode.removeChild(dialog); }, 500);
        });
        
        const confirmBtn = document.createElement('m3e-button');
        confirmBtn.setAttribute('variant', 'filled');
        confirmBtn.innerHTML = `<span>${t('ok')}</span>`;
        
        const verify = async () => {
            const password = input.value;
            const userToCheck = checkUser || currentUser;

            // 1. Cloud Verification (Priority if logged in)
            if (userToCheck) {
                try {
                    const userConfigRef = doc(db, "user_config", userToCheck.uid);
                    const snap = await getDoc(userConfigRef);
                    if (snap.exists() && snap.data().verifier) {
                        const cloudVerifier = snap.data().verifier;
                        const check = await calculateCloudVerifier(password, userToCheck.uid);
                        if (check !== cloudVerifier) {
                            showSnackbar(t('login_fail'));
                            input.value = '';
                            input.focus();
                            return;
                        }
                        // Cloud verification passed
                        dialog.open = false;
                        resolve(returnPassword ? password : true);
                        setTimeout(() => { if(dialog.parentNode) dialog.parentNode.removeChild(dialog); }, 500);
                        return;
                    }
                } catch (e) {
                    console.warn("Cloud verification skipped (offline or error):", e);
                }
            }

            // 2. Local Verification (Fallback or Local Mode)
            const masterAuth = JSON.parse(localStorage.getItem(CONSTANTS.STORAGE.MASTER_AUTH));
            
            if (!masterAuth) {
                resolve(returnPassword ? password : true);
                dialog.open = false;
                setTimeout(() => { if(dialog.parentNode) dialog.parentNode.removeChild(dialog); }, 500);
                return;
            }

            const hash = await hashPassword(password, masterAuth.salt);
            if (hash === masterAuth.hash) {
                dialog.open = false;
                resolve(returnPassword ? password : true);
                setTimeout(() => { if(dialog.parentNode) dialog.parentNode.removeChild(dialog); }, 500);
            } else {
                showSnackbar(t('login_fail'));
                input.value = '';
                input.focus();
            }
        };

        confirmBtn.addEventListener('click', verify);
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') verify();
        });

        if (window.PublicKeyCredential) {
            const bioBtn = document.createElement('m3e-icon-button');
            bioBtn.innerHTML = '<m3e-icon name="fingerprint"></m3e-icon>';
            bioBtn.style.marginRight = 'auto';
            bioBtn.title = t('biometric_login');
            
            bioBtn.addEventListener('click', async () => {
                try {
                    const localKeys = getBiometricKeys(false);
                    const cloudKeys = getBiometricKeys(true);
                    
                    const localCredId = localStorage.getItem(localKeys.credId);
                    const cloudCredId = localStorage.getItem(cloudKeys.credId);
                    
                    const allowCredentials = [];
                    if (localCredId) allowCredentials.push({ id: base64ToArrayBuffer(localCredId), type: 'public-key', transports: ['internal'] });
                    if (cloudCredId) allowCredentials.push({ id: base64ToArrayBuffer(cloudCredId), type: 'public-key', transports: ['internal'] });

                    const assertionOptions = {
                        challenge: window.crypto.getRandomValues(new Uint8Array(32)),
                        rpId: window.location.hostname,
                        userVerification: "required",
                        extensions: { largeBlob: { read: true } }
                    };
                    
                    if (allowCredentials.length > 0) {
                        assertionOptions.allowCredentials = allowCredentials;
                    }

                    const assertion = await navigator.credentials.get({ publicKey: assertionOptions });
                    const extResults = assertion.getClientExtensionResults();
                    const usedCredId = arrayBufferToBase64(assertion.rawId);
                    const isCloudLogin = (usedCredId === cloudCredId);

                    let password = null;
                    if (extResults.largeBlob && extResults.largeBlob.blob) {
                        const blobData = extResults.largeBlob.blob;
                        const encryptedDataStr = localStorage.getItem(CONSTANTS.STORAGE.PASSKEY_ENCRYPTED_DATA);

                        if (encryptedDataStr) {
                            // New Mode: Blob is Key (Envelope Encryption)
                            const key = await window.crypto.subtle.importKey("raw", blobData, {name: "AES-GCM"}, false, ["decrypt"]);
                            password = await decryptLocal(encryptedDataStr, key);
                        } else {
                            // Legacy Mode: Blob is Data
                            const blobStr = bufferToStr(blobData);
                            try {
                                const blobKey = await getPasskeyBlobKey();
                                password = await decryptLocal(blobStr, blobKey);
                            } catch (e) {
                                password = blobStr; // Fallback for legacy plain text
                            }
                        }
                    } else {
                        if (isCloudLogin) {
                            password = await loadPasskeyFallback(cloudKeys.fallback);
                        } else {
                            password = await loadPasskeyFallback(localKeys.fallback);
                        }
                    }

                    if (password) {
                        input.value = password;
                        verify();
                    } else {
                        showSnackbar(t('passkey_read_failed'));
                    }
                } catch (e) {
                    console.error(e);
                }
            });
            actions.appendChild(bioBtn);
        }

        actions.appendChild(cancelBtn);
        actions.appendChild(confirmBtn);
        dialog.appendChild(actions);

        document.body.appendChild(dialog);
        requestAnimationFrame(() => {
            dialog.open = true;
            setTimeout(() => input.focus(), 100);
        });
    });
}

// --- Password Strength & TOTP ---

async function calculatePasswordStrength(password) {
    if (!password) return 0;
    const { default: zxcvbn } = await import('zxcvbn');
    // zxcvbn returns a score from 0 (weak) to 4 (very strong)
    const result = zxcvbn(password);
    return result.score;
}

async function getStrengthInfo(password, score = null) {
    const strength = score !== null ? score : await calculatePasswordStrength(password);
    let strengthClass = 'text-weak';
    let barClass = 'bg-weak';
    let strengthPercent = 0;
    let labelKey = 'weak';

    // zxcvbn score: 0-4
    if (strength === 0) { strengthPercent = 5; labelKey = 'weak'; }
    else if (strength === 1) { strengthPercent = 25; labelKey = 'weak'; }
    else if (strength === 2) { strengthPercent = 50; strengthClass = 'text-medium'; barClass = 'bg-medium'; labelKey = 'medium'; }
    else if (strength === 3) { strengthPercent = 75; strengthClass = 'text-medium'; barClass = 'bg-medium'; labelKey = 'medium'; }
    else if (strength === 4) { strengthPercent = 100; strengthClass = 'text-strong'; barClass = 'bg-strong'; labelKey = 'strong'; }

    if (!password) strengthPercent = 0;

    return { strength, strengthPercent, strengthClass, barClass, labelKey };
}

async function updateStrengthView(password, resultElId, barElId, crackTimeElId) {
    let analysis = null;
    if (password) {
        const { default: zxcvbn } = await import('zxcvbn');
        analysis = zxcvbn(password);
    }
    const info = await getStrengthInfo(password, analysis ? analysis.score : 0);

    const resultEl = typeof resultElId === 'string' ? document.getElementById(resultElId) : resultElId;
    const barEl = typeof barElId === 'string' ? document.getElementById(barElId) : barElId;
    const crackTimeEl = typeof crackTimeElId === 'string' ? document.getElementById(crackTimeElId) : crackTimeElId;

    if (resultEl) {
        if (!password) {
            resultEl.textContent = '';
            resultEl.className = 'font-bold text-small';
        } else {
            resultEl.textContent = t(info.labelKey);
            resultEl.className = 'font-bold text-small ' + info.strengthClass;
        }
    }

    if (barEl) {
        barEl.style.width = info.strengthPercent + '%';
        barEl.className = 'strength-meter-fill ' + info.barClass;
    }

    if (crackTimeEl) {
        crackTimeEl.textContent = analysis ? formatCrackTime(analysis.crack_times_seconds.offline_slow_hashing_1e4_per_second) : '';
    }
}

function formatCrackTime(seconds) {
    if (seconds === undefined || seconds === null) return '';
    // Use offline_slow_hashing_1e4_per_second for a conservative estimate (e.g. master password cracking)
    let timeString = 'instant';
    if (seconds >= 31536000 * 100) timeString = 'centuries';
    else if (seconds >= 31536000) timeString = Math.floor(seconds / 31536000) + t('year');
    else if (seconds >= 86400) timeString = Math.floor(seconds / 86400) + t('day');
    else if (seconds >= 3600) timeString = Math.floor(seconds / 3600) + t('hour');
    else if (seconds >= 60) timeString = Math.floor(seconds / 60) + t('minute');
    else if (seconds >= 1) timeString = Math.floor(seconds) + t('second');

    return t('crack_time') + (timeString === 'instant' || timeString === 'centuries' ? t(timeString) : timeString);
}

async function checkPwnedPassword(password) {
    if (!password) return null;
    // Hash password with SHA-1
    const msgBuffer = new TextEncoder().encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    
    const prefix = hashHex.substring(0, 5);
    const suffix = hashHex.substring(5);
    
    try {
        const response = await fetch('https://api.pwnedpasswords.com/range/' + prefix);
        const text = await response.text();
        const regex = new RegExp(`^${suffix}:([0-9]+)$`, 'm');
        const match = text.match(regex);
        return match ? parseInt(match[1]) : 0;
    } catch (e) {
        console.error("HIBP check failed", e);
        return -1; // Error
    }
}

async function generateTOTP(secret) {
    if (!secret) return null;
    try {
        // Remove spaces
        const cleanSecret = secret.replace(/\s/g, '');
        
        // Create TOTP object using otpauth library
        const OTPAuth = await import('otpauth');
        const totp = new OTPAuth.TOTP({
            algorithm: 'SHA1',
            digits: 6,
            period: 30,
            secret: OTPAuth.Secret.fromBase32(cleanSecret)
        });
        
        const code = totp.generate();
        
        // Calculate remaining time
        const epoch = Math.floor(Date.now() / 1000);
        const period = 30;
        const remaining = period - (epoch % period);

        return { code: code, remaining: remaining };
    } catch (e) {
        console.error("TOTP generation failed", e);
        return null;
    }
}

// --- WebAuthn / Passkey Logic ---

function strToBuffer(str) {
    return new TextEncoder().encode(str);
}

function bufferToStr(buf) {
    return new TextDecoder().decode(buf);
}

function getBiometricKeys(isCloud) {
    return isCloud ? {
        credId: 'soul_biometric_cred_id_cloud',
        fallback: 'soul_passkey_fallback_cloud'
    } : {
        credId: 'soul_biometric_cred_id',
        fallback: CONSTANTS.STORAGE.PASSKEY_FALLBACK
    };
}

async function getFallbackKey() {
    // Use a fixed salt for the fallback key derivation
    const salt = new TextEncoder().encode("soul_passkey_fallback_salt");
    
    // Use FIXED_ENCRYPTION_SECRET for fallback storage (obfuscation)
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw", enc.encode(FIXED_ENCRYPTION_SECRET), { name: "PBKDF2" }, false, ["deriveKey"]
    );

    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: CRYPTO_CONFIG.PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

async function getPasskeyBlobKey() {
    // Use a different salt for largeBlob encryption
    const salt = new TextEncoder().encode("soul_passkey_largeblob_salt");
    
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw", enc.encode(FIXED_ENCRYPTION_SECRET), { name: "PBKDF2" }, false, ["deriveKey"]
    );

    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: CRYPTO_CONFIG.PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

async function savePasskeyFallback(password, storageKey = CONSTANTS.STORAGE.PASSKEY_FALLBACK) {
    const key = await getFallbackKey();
    const encrypted = await encryptLocal(password, key);
    localStorage.setItem(storageKey, encrypted);
}

async function loadPasskeyFallback(storageKey = CONSTANTS.STORAGE.PASSKEY_FALLBACK) {
    const encrypted = localStorage.getItem(storageKey);
    if (!encrypted) return null;
    try {
        const key = await getFallbackKey();
        return await decryptLocal(encrypted, key);
    } catch (e) {
        console.error("Fallback load failed", e);
        return null;
    }
}

async function registerPasskey() {
    if (!window.PublicKeyCredential) {
        showAlertDialog(t('browser_not_support_biometric'));
        return;
    }

    // We need the plaintext password to store it in the largeBlob.
    // Since we don't keep it in memory, we must ask the user.
    const isCloud = !!currentUser;
    const password = await promptForMasterPassword(true, currentUser, isCloud ? 'cloud' : 'local');
    if (!password) return;

    try {
        // Verification is now handled inside promptForMasterPassword
        showSnackbar(t('passkey_register_prompt'));
        
        // 1. Create Credential
        const userId = new Uint8Array(16);
        window.crypto.getRandomValues(userId);

        let defaultName = "Soul User";
        if (currentUser) {
            defaultName = currentUser.email || currentUser.displayName || "Soul User";
        } else {
            const masterAuth = JSON.parse(localStorage.getItem(CONSTANTS.STORAGE.MASTER_AUTH));
            if (masterAuth && masterAuth.username) defaultName = masterAuth.username;
        }

        const username = await promptForInput(t('passkey_name_title'), t('passkey_name_label'), defaultName);
        if (username === null) return;

        const savedNames = JSON.parse(localStorage.getItem(CONSTANTS.STORAGE.PASSKEY_NAMES) || '[]');
        if (savedNames.includes(username)) {
            showAlertDialog(t('passkey_name_exists'));
            return;
        }

        const publicKeyCredentialCreationOptions = {
            challenge: window.crypto.getRandomValues(new Uint8Array(32)),
            rp: { name: "Soul Password Manager", id: window.location.hostname },
            user: { id: userId, name: username, displayName: username },
            pubKeyCredParams: [{ alg: -7, type: "public-key" }, { alg: -257, type: "public-key" }],
            authenticatorSelection: { 
                authenticatorAttachment: "platform", 
                residentKey: "required",
                requireResidentKey: true, 
                userVerification: "required" 
            },
            timeout: 60000,
            attestation: "none",
            extensions: { largeBlob: { support: "required" } }
        };

        const credential = await navigator.credentials.create({ publicKey: publicKeyCredentialCreationOptions });
        
        // Check if largeBlob is supported by the authenticator
        const credExts = credential.getClientExtensionResults();
        let largeBlobSuccess = false;

        if (credExts.largeBlob && credExts.largeBlob.supported) {
            try {
                // 2. Generate Random Key and Write to Large Blob (Envelope Encryption)
                const keyBytes = window.crypto.getRandomValues(new Uint8Array(32)); // 32 bytes random key
                
                const assertionOptions = {
                    challenge: window.crypto.getRandomValues(new Uint8Array(32)),
                    rpId: window.location.hostname,
                    allowCredentials: [{ id: credential.rawId, type: 'public-key' }],
                    userVerification: "required",
                    extensions: { largeBlob: { write: keyBytes } }
                };

                const assertion = await navigator.credentials.get({ publicKey: assertionOptions });
                const extResults = assertion.getClientExtensionResults();
                if (extResults.largeBlob && extResults.largeBlob.written) {
                    // 3. Encrypt Password with the Random Key and Save to Local Storage
                    const key = await window.crypto.subtle.importKey("raw", keyBytes, {name: "AES-GCM"}, false, ["encrypt"]);
                    const encryptedPassword = await encryptLocal(password, key);
                    localStorage.setItem(CONSTANTS.STORAGE.PASSKEY_ENCRYPTED_DATA, encryptedPassword);

                    let authType = "Passkey";
                    if (credential.authenticatorAttachment === 'platform') {
                        authType = t('passkey_device_type');
                    } else if (credential.authenticatorAttachment === 'cross-platform') {
                        authType = t('passkey_external_type');
                    }
                    if (typeof credential.response.getTransports === 'function') {
                        const transports = credential.response.getTransports();
                        if (transports.length > 0) authType += ` (${transports.join(', ')})`;
                    }
                    showSnackbar(t('passkey_registered', {type: authType}));
                    
                    const currentNames = JSON.parse(localStorage.getItem(CONSTANTS.STORAGE.PASSKEY_NAMES) || '[]');
                    if (!currentNames.includes(username)) {
                        currentNames.push(username);
                        localStorage.setItem(CONSTANTS.STORAGE.PASSKEY_NAMES, JSON.stringify(currentNames));
                    }
                    largeBlobSuccess = true;
                }
            } catch (e) {
                console.warn("LargeBlob write failed, attempting fallback", e);
            }
        }

        if (!largeBlobSuccess) {
            const confirmFallback = await showConfirmDialog(t('passkey_fallback_confirm'));
            if (confirmFallback) {
                const keys = getBiometricKeys(isCloud);
                await savePasskeyFallback(password, keys.fallback);
                
                const currentNames = JSON.parse(localStorage.getItem(CONSTANTS.STORAGE.PASSKEY_NAMES) || '[]');
                if (!currentNames.includes(username)) {
                    currentNames.push(username);
                    localStorage.setItem(CONSTANTS.STORAGE.PASSKEY_NAMES, JSON.stringify(currentNames));
                }
                showSnackbar(t('passkey_fallback_saved'));
            } else {
                showSnackbar(t('passkey_not_supported_cancel'));
            }
        }

    } catch (e) {
        console.error(e);
        let msg = e.message;
        if (e.name === 'NotAllowedError') {
            msg = t('auth_cancelled_or_timeout');
        } else if (e.name === 'NotSupportedError') {
            msg = t('device_not_support_passkey');
        } else if (e.name === 'SecurityError') {
            msg = t('auth_security_error');
        }
        showAlertDialog(t('passkey_registration_failed', {msg}));
    }
}

async function registerLocalBiometric() {
    if (!window.PublicKeyCredential) {
        showAlertDialog(t('browser_not_support_biometric_en'));
        return;
    }

    const isCloud = !!currentUser;
    const password = await promptForMasterPassword(true, currentUser, isCloud ? 'cloud' : 'local');
    if (!password) return;

    try {
        showSnackbar(t('biometric_register_prompt'));
        
        const userId = new Uint8Array(16);
        window.crypto.getRandomValues(userId);

        let defaultName = "Soul User";
        if (currentUser) {
            defaultName = currentUser.email || currentUser.displayName || "Soul User";
        } else {
            const masterAuth = JSON.parse(localStorage.getItem(CONSTANTS.STORAGE.MASTER_AUTH));
            if (masterAuth && masterAuth.username) defaultName = masterAuth.username;
        }

        const publicKeyCredentialCreationOptions = {
            challenge: window.crypto.getRandomValues(new Uint8Array(32)),
            rp: { name: "Soul Password Manager", id: window.location.hostname },
            user: { id: userId, name: defaultName, displayName: defaultName },
            pubKeyCredParams: [{ alg: -7, type: "public-key" }, { alg: -257, type: "public-key" }],
            authenticatorSelection: { 
                authenticatorAttachment: "platform", 
                residentKey: "discouraged", // Avoid creating a "Passkey" (Resident Key)
                requireResidentKey: false, 
                userVerification: "required" 
            },
            timeout: 60000,
            attestation: "none"
        };

        const credential = await navigator.credentials.create({ publicKey: publicKeyCredentialCreationOptions });
        
        // Save Credential ID for later use (allowCredentials)
        const credId = arrayBufferToBase64(credential.rawId);
        const keys = getBiometricKeys(isCloud);
        localStorage.setItem(keys.credId, credId);
        
        // Save Password using the existing fallback mechanism (Local Storage)
        await savePasskeyFallback(password, keys.fallback);
        
        // Also add to names list for UI consistency if needed, or just notify
        showSnackbar(isCloud ? t('biometric_cloud_registered') : t('biometric_local_registered'));

    } catch (e) {
        console.error(e);
        showAlertDialog(t('registration_failed', {msg: e.message}));
    }
}

async function unregisterLocalBiometric() {
    const confirm = await showConfirmDialog(t('unregister_passkey_confirm')); // Reuse confirmation message
    if (confirm) {
        const keys = getBiometricKeys(!!currentUser);
        localStorage.removeItem(keys.credId);
        localStorage.removeItem(keys.fallback);
        showSnackbar(t('passkey_unregistered'));
    }
}

async function loginWithPasskey() {
    if (!window.PublicKeyCredential) return;

    try {
        const localKeys = getBiometricKeys(false);
        const cloudKeys = getBiometricKeys(true);
        
        const localCredId = localStorage.getItem(localKeys.credId);
        const cloudCredId = localStorage.getItem(cloudKeys.credId);
        
        const allowCredentials = [];
        if (localCredId) allowCredentials.push({ id: base64ToArrayBuffer(localCredId), type: 'public-key', transports: ['internal'] });
        if (cloudCredId) allowCredentials.push({ id: base64ToArrayBuffer(cloudCredId), type: 'public-key', transports: ['internal'] });

        const assertionOptions = {
            challenge: window.crypto.getRandomValues(new Uint8Array(32)),
            rpId: window.location.hostname,
            userVerification: "required",
            extensions: { largeBlob: { read: true } }
        };

        if (allowCredentials.length > 0) {
            assertionOptions.allowCredentials = allowCredentials;
        }

        const assertion = await navigator.credentials.get({ publicKey: assertionOptions });
        const extResults = assertion.getClientExtensionResults();
        const usedCredId = arrayBufferToBase64(assertion.rawId);

        let password = null;
        let isFallback = false;
        let isCloudLogin = (usedCredId === cloudCredId);

        if (extResults.largeBlob && extResults.largeBlob.blob) {
            const blobData = extResults.largeBlob.blob;
            const encryptedDataStr = localStorage.getItem(CONSTANTS.STORAGE.PASSKEY_ENCRYPTED_DATA);

            if (encryptedDataStr) {
                // New Mode: Blob is Key
                const key = await window.crypto.subtle.importKey("raw", blobData, {name: "AES-GCM"}, false, ["decrypt"]);
                password = await decryptLocal(encryptedDataStr, key);
            } else {
                // Legacy Mode: Blob is Data
                const blobStr = bufferToStr(blobData);
                try {
                    const blobKey = await getPasskeyBlobKey();
                    password = await decryptLocal(blobStr, blobKey);
                } catch (e) {
                    password = blobStr; // Fallback for legacy plain text
                }
            }
        } else {
            if (isCloudLogin) {
                password = await loadPasskeyFallback(cloudKeys.fallback);
            } else {
                password = await loadPasskeyFallback(localKeys.fallback);
            }
            isFallback = true;
        }

        if (password) {
            if (currentUser || isCloudLogin) {
                if (!currentUser) {
                    showAlertDialog(t('cloud_session_expired'));
                    return;
                }
                cloudKey = await deriveCloudKey(password, currentUser.uid);
                showSnackbar(isFallback ? t('passkey_fallback_login') : t('passkey_unlock_success'));
                initFirestoreSync(currentUser);
            } else {
                const masterAuth = JSON.parse(localStorage.getItem(CONSTANTS.STORAGE.MASTER_AUTH));
                if (masterAuth) {
                    appKey = await deriveKey(password, masterAuth.salt);
                    document.getElementById('login_dialog').open = false;
                    initLocalApp();
                    showSnackbar(isFallback ? t('passkey_fallback_login') : t('passkey_login_success'));
                } else {
                    showAlertDialog(t('user_info_not_found'));
                }
            }
        } else {
            showAlertDialog(t('passkey_read_failed'));
        }
    } catch (e) {
        console.error(e);
        let msg = e.message;
        if (e.name === 'NotAllowedError') msg = t('auth_cancelled');
        else if (e.name === 'NotSupportedError') msg = t('auth_not_supported');
        else if (e.name === 'SecurityError') msg = t('auth_security_error');
        showSnackbar(t('passkey_auth_error', {msg}));
    }
}

async function unregisterPasskey() {
    const confirm = await showConfirmDialog(t('unregister_passkey_confirm'));
    if (confirm) {
        localStorage.removeItem(CONSTANTS.STORAGE.PASSKEY_FALLBACK);
        localStorage.removeItem(CONSTANTS.STORAGE.PASSKEY_NAMES);
        localStorage.removeItem(CONSTANTS.STORAGE.PASSKEY_ENCRYPTED_DATA);
        localStorage.removeItem('soul_biometric_cred_id');
        showAlertDialog(t('passkey_unregistered'));
    }
}

function openPasskeyManager() {
    const dialog = document.createElement('m3e-dialog');
    
    const header = document.createElement('span');
    header.slot = 'header';
    header.textContent = t('passkey_manager_title');
    dialog.appendChild(header);

    const content = document.createElement('div');
    content.style.padding = '10px 0';
    content.style.minWidth = '300px';

    const listContainer = document.createElement('div');
    
    const renderList = () => {
        listContainer.innerHTML = '';
        const names = JSON.parse(localStorage.getItem(CONSTANTS.STORAGE.PASSKEY_NAMES) || '[]');
        
        if (names.length === 0) {
            const empty = document.createElement('div');
            empty.textContent = t('passkey_list_empty');
            empty.style.color = 'var(--md-sys-color-secondary)';
            empty.style.textAlign = 'center';
            empty.style.padding = '20px';
            listContainer.appendChild(empty);
        } else {
            names.forEach(name => {
                const item = document.createElement('div');
                item.style.display = 'flex';
                item.style.alignItems = 'center';
                item.style.justifyContent = 'space-between';
                item.style.padding = '12px';
                item.style.borderBottom = '1px solid var(--md-sys-color-outline-variant)';
                
                const nameSpan = document.createElement('span');
                nameSpan.textContent = name;
                nameSpan.style.fontWeight = 'bold';
                
                const delBtn = document.createElement('m3e-icon-button');
                delBtn.innerHTML = '<m3e-icon name="delete" style="color:var(--md-sys-color-error)"></m3e-icon>';
                delBtn.addEventListener('click', async () => {
                    const confirm = await showConfirmDialog(t('passkey_delete_confirm'));
                    if (confirm) {
                        const currentNames = JSON.parse(localStorage.getItem(CONSTANTS.STORAGE.PASSKEY_NAMES) || '[]');
                        const newNames = currentNames.filter(n => n !== name);
                        localStorage.setItem(CONSTANTS.STORAGE.PASSKEY_NAMES, JSON.stringify(newNames));
                        renderList();
                        showSnackbar(t('passkey_deleted'));
                    }
                });
                
                item.appendChild(nameSpan);
                item.appendChild(delBtn);
                listContainer.appendChild(item);
            });
        }
    };
    
    renderList();
    content.appendChild(listContainer);
    dialog.appendChild(content);

    const actions = document.createElement('div');
    actions.slot = 'actions';
    
    const closeBtn = document.createElement('m3e-button');
    closeBtn.setAttribute('variant', 'text');
    closeBtn.innerHTML = `<span>${t('close')}</span>`;
    closeBtn.addEventListener('click', () => {
        dialog.open = false;
        setTimeout(() => { if(dialog.parentNode) dialog.parentNode.removeChild(dialog); }, 500);
    });
    
    actions.appendChild(closeBtn);
    dialog.appendChild(actions);

    document.body.appendChild(dialog);
    requestAnimationFrame(() => {
        dialog.open = true;
    });
}

async function updatePasskeyData(newPassword) {
    const hasFallback = !!localStorage.getItem(CONSTANTS.STORAGE.PASSKEY_FALLBACK);
    const hasSupport = !!window.PublicKeyCredential;

    if (!hasFallback && !hasSupport) return;

    const confirm = await showConfirmDialog(t('update_passkey_confirm'));
    if (!confirm) return;

    let updated = false;
    
    // Update Fallback (Local Storage)
    if (hasFallback) {
        await savePasskeyFallback(newPassword);
        updated = true;
    }

    // Update Large Blob (Passkey)
    if (hasSupport) {
        try {
            // Generate NEW random key for rotation/migration
            const keyBytes = window.crypto.getRandomValues(new Uint8Array(32));
            const assertionOptions = {
                challenge: window.crypto.getRandomValues(new Uint8Array(32)),
                rpId: window.location.hostname,
                userVerification: "required",
                extensions: { largeBlob: { write: keyBytes } }
            };

            showSnackbar(t('passkey_update_prompt'));
            const assertion = await navigator.credentials.get({ publicKey: assertionOptions });
            const extResults = assertion.getClientExtensionResults();
            
            if (extResults.largeBlob && extResults.largeBlob.written) {
                updated = true;
                const key = await window.crypto.subtle.importKey("raw", keyBytes, {name: "AES-GCM"}, false, ["encrypt"]);
                const encryptedPassword = await encryptLocal(newPassword, key);
                localStorage.setItem(CONSTANTS.STORAGE.PASSKEY_ENCRYPTED_DATA, encryptedPassword);
            } else {
                console.warn("Passkey update failed: largeBlob not written");
                showSnackbar(t('passkey_update_failed'));
            }
        } catch (e) {
            console.error("Passkey update skipped:", e);
            if (e.name !== 'NotAllowedError') {
                showSnackbar(t('passkey_update_error', {msg: e.message}));
            }
        }
    }
    
    if (updated) {
        showSnackbar(t('passkey_updated'));
    }
}

function getLoginAttempts(username) {
    const key = CONSTANTS.STORAGE.LOGIN_ATTEMPTS_PREFIX + username;
    const data = localStorage.getItem(key);
    if (!data) {
        return { attempts: 0, lockoutUntil: null };
    }
    return JSON.parse(data);
}

function setLoginAttempts(username, data) {
    const key = CONSTANTS.STORAGE.LOGIN_ATTEMPTS_PREFIX + username;
    localStorage.setItem(key, JSON.stringify(data));
}

function clearLoginAttempts(username) {
    const key = CONSTANTS.STORAGE.LOGIN_ATTEMPTS_PREFIX + username;
    localStorage.removeItem(key);
}

function formatRemainingTime(ms) {
    const totalSeconds = Math.ceil(ms / 1000);
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    return `${minutes}m ${seconds}s`;
}

async function handleFailedLogin(username) {
    const attemptsData = getLoginAttempts(username);
    attemptsData.attempts++;

    if (attemptsData.attempts >= MAX_LOGIN_ATTEMPTS) {
        attemptsData.lockoutUntil = Date.now() + LOCKOUT_DURATION_MINUTES * 60 * 1000;
        attemptsData.attempts = 0; // Reset counter after lockout
        setLoginAttempts(username, attemptsData);
        showAlertDialog(t('login_locked_out', { minutes: LOCKOUT_DURATION_MINUTES }));
    } else {
        setLoginAttempts(username, attemptsData);
        showAlertDialog(t('login_fail'));
    }
}

function generateRecoveryKit() {
    const masterAuth = JSON.parse(localStorage.getItem(CONSTANTS.STORAGE.MASTER_AUTH));
    const username = masterAuth ? masterAuth.username : (currentUser ? (currentUser.email || currentUser.displayName) : 'Unknown');
    
    const content = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Soul Password Manager - Recovery Kit</title>
            <style>
                body { font-family: sans-serif; padding: 40px; color: #333; max-width: 800px; margin: 0 auto; }
                .header { border-bottom: 2px solid #6750a4; padding-bottom: 20px; margin-bottom: 30px; }
                .logo { font-size: 24px; font-weight: bold; color: #6750a4; display: flex; align-items: center; gap: 10px; }
                .warning { background: #fff3e0; border: 1px solid #ffe0b2; padding: 15px; border-radius: 4px; margin-bottom: 30px; color: #e65100; }
                .field { margin-bottom: 25px; }
                .label { font-weight: bold; margin-bottom: 8px; display: block; text-transform: uppercase; font-size: 12px; letter-spacing: 1px; color: #666; }
                .value { border: 1px solid #ccc; padding: 15px; border-radius: 4px; font-family: monospace; font-size: 16px; background: #f9f9f9; min-height: 20px; }
                .value.write-in { background: white; border: 2px dashed #ccc; color: #ccc; }
                .footer { margin-top: 50px; font-size: 12px; color: #999; text-align: center; border-top: 1px solid #eee; padding-top: 20px; }
                @media print {
                    body { padding: 0; }
                    .warning { border: 1px solid #000; color: #000; }
                }
            </style>
        </head>
        <body>
            <div class="header">
                <div class="logo">
                    <span>🔒</span> Soul Password Manager
                </div>
                <h1>Recovery Kit</h1>
            </div>
            
            <div class="warning">
                <strong>${t('recovery_kit_emergency')}</strong><br>
                ${t('recovery_kit_warning_1')}<br>
                ${t('recovery_kit_warning_2')}
            </div>

            <div class="field">
                <span class="label">${t('recovery_kit_username')}</span>
                <div class="value">${username}</div>
            </div>

            <div class="field">
                <span class="label">${t('recovery_kit_master_password')}</span>
                <div class="value write-in">${t('recovery_kit_write_password')}</div>
            </div>

            <div class="field">
                <span class="label">Login URL</span>
                <div class="value">${window.location.origin}</div>
            </div>

            <div class="footer">
                Generated on ${new Date().toLocaleString()}
            </div>
            <script>
                window.onload = function() { window.print(); }
            </script>
        </body>
        </html>
    `;

    const win = window.open('', '_blank');
    if (win) {
        win.document.write(content);
        win.document.close();
    } else {
        showAlertDialog(t('popup_blocked'));
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
            timerEl.textContent = t('totp_timer', {remaining: result.remaining});
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

function updateSessionTypeDisplay() {
    const el = document.getElementById('current_session_type');
    if (!el) return;
    
    if (!currentUser) {
        el.textContent = t('session_memory');
        return;
    }

    const requireSecondAuth = localStorage.getItem(CONSTANTS.STORAGE.REQUIRE_SECOND_AUTH) === 'true';
    if (requireSecondAuth) {
        el.textContent = t('session_memory');
    } else {
        el.textContent = t('session_storage');
    }
}

async function scanQRCode(targetInputId) {
    const { default: jsQR } = await import('jsqr');
    const video = document.createElement('video');
    const canvasElement = document.createElement('canvas');
    const canvas = canvasElement.getContext('2d');

    const container = document.createElement('div');
    container.style.cssText = `
        position: fixed; top: 0; left: 0; width: 100%; height: 100%; 
        background: rgba(0,0,0,0.8); z-index: 10001; display: flex; 
        flex-direction: column; align-items: center; justify-content: center;
    `;

    const scanArea = document.createElement('div');
    scanArea.style.cssText = `
        position: relative;
        width: 250px;
        height: 250px;
        border: 2px solid rgba(255, 255, 255, 0.5);
        border-radius: 16px;
        box-shadow: 0 0 0 1000px rgba(0, 0, 0, 0.5);
        display: flex;
        align-items: center;
        justify-content: center;
    `;

    const message = document.createElement('p');
    message.textContent = t('scan_qr_guide') || 'QRコードを枠内に合わせてください';
    message.style.cssText = 'color: white; margin-bottom: 24px; font-size: 16px; font-weight: bold; text-shadow: 0 2px 4px rgba(0,0,0,0.5); z-index: 10002;';

    const closeBtn = document.createElement('m3e-button');
    closeBtn.setAttribute('variant', 'filled');
    closeBtn.innerHTML = `<span>${t('cancel')}</span>`;
    closeBtn.style.cssText = 'margin-top: 32px; z-index: 10002;';
    
    const switchCameraBtn = document.createElement('m3e-icon-button');
    switchCameraBtn.innerHTML = '<m3e-icon name="cameraswitch" style="color: white; font-size: 32px;"></m3e-icon>';
    switchCameraBtn.style.cssText = 'position: absolute; top: 24px; right: 24px; z-index: 10002; display: none;';
    
    const flashBtn = document.createElement('m3e-icon-button');
    flashBtn.innerHTML = '<m3e-icon name="flash_on" style="color: white; font-size: 32px;"></m3e-icon>';
    flashBtn.style.cssText = 'position: absolute; top: 24px; left: 24px; z-index: 10002; display: none;';
    
    const uploadBtn = document.createElement('m3e-icon-button');
    uploadBtn.innerHTML = '<m3e-icon name="image" style="color: white; font-size: 32px;"></m3e-icon>';
    uploadBtn.style.cssText = 'position: absolute; top: 24px; right: 80px; z-index: 10002;';
    
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.accept = 'image/*';
    fileInput.style.display = 'none';

    uploadBtn.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;
        
        const reader = new FileReader();
        reader.onload = (event) => {
            const img = new Image();
            img.onload = () => {
                const tempCanvas = document.createElement('canvas');
                const tempCtx = tempCanvas.getContext('2d');
                tempCanvas.width = img.width;
                tempCanvas.height = img.height;
                tempCtx.drawImage(img, 0, 0);
                const imageData = tempCtx.getImageData(0, 0, tempCanvas.width, tempCanvas.height);
                const code = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: "dontInvert" });
                
                if (code && code.data.startsWith('otpauth://')) {
                    if (navigator.vibrate) navigator.vibrate(200);

                    try {
                        const AudioContext = window.AudioContext || window.webkitAudioContext;
                        if (AudioContext) {
                            const ctx = new AudioContext();
                            const osc = ctx.createOscillator();
                            const gain = ctx.createGain();
                            osc.connect(gain);
                            gain.connect(ctx.destination);
                            osc.frequency.value = 800;
                            gain.gain.value = 0.1;
                            osc.start();
                            setTimeout(() => { osc.stop(); ctx.close(); }, 150);
                        }
                    } catch (e) {}

                    const url = new URL(code.data);
                    const secret = url.searchParams.get('secret');
                    document.getElementById(targetInputId).value = secret;
                    stopScan();
                } else {
                    showSnackbar(t('qr_not_found') || "QR code not found");
                }
            };
            img.src = event.target.result;
        };
        reader.readAsDataURL(file);
    });

    // Video should be behind the overlay
    video.style.cssText = 'position: absolute; top: 0; left: 0; width: 100%; height: 100%; object-fit: cover; z-index: -1;';

    container.appendChild(video); // Video first (background)
    container.appendChild(message);
    container.appendChild(flashBtn);
    container.appendChild(switchCameraBtn);
    container.appendChild(uploadBtn);
    container.appendChild(scanArea);
    container.appendChild(closeBtn);
    document.body.appendChild(container);

    let stream = null;
    let currentCameraIndex = 0;
    let videoDevices = [];
    let isFlashOn = false;

    const stopScan = () => {
        if (stream) {
            stream.getTracks().forEach(track => track.stop());
        }
        if (container.parentNode) {
            container.parentNode.removeChild(container);
        }
    };

    closeBtn.addEventListener('click', stopScan);

    const toggleFlash = async () => {
        if (!stream) return;
        const track = stream.getVideoTracks()[0];
        const capabilities = track.getCapabilities();
        
        if (capabilities.torch) {
            isFlashOn = !isFlashOn;
            try {
                await track.applyConstraints({ advanced: [{ torch: isFlashOn }] });
                flashBtn.querySelector('m3e-icon').name = isFlashOn ? 'flash_off' : 'flash_on';
            } catch (e) {
                console.error("Flash toggle failed", e);
                isFlashOn = !isFlashOn; // Revert state on fail
            }
        }
    };

    const startCamera = async (deviceId = null) => {
        if (stream) {
            stream.getTracks().forEach(track => track.stop());
        }
        
        // Try strict constraints first
        let constraints = { 
            video: deviceId ? { deviceId: { exact: deviceId } } : { facingMode: "environment" } 
        };

        try {
            const s = await navigator.mediaDevices.getUserMedia(constraints);
            handleStreamSuccess(s);
        } catch (err) {
            console.warn("Primary camera constraint failed, retrying...", err);
            
            // Fallback: try relaxed constraints if environment/deviceId fails
            if (!deviceId && (err.name === 'OverconstrainedError' || err.name === 'NotFoundError')) {
                try {
                    console.log("Retrying with relaxed constraints...");
                    constraints = { video: true };
                    const s = await navigator.mediaDevices.getUserMedia(constraints);
                    handleStreamSuccess(s);
                    return;
                } catch (retryErr) {
                    handleCameraError(retryErr);
                }
            } else {
                handleCameraError(err);
            }
        }
    };

    const handleStreamSuccess = (s) => {
        stream = s;
        video.srcObject = stream;
        video.setAttribute("playsinline", true); // for iOS
        video.play();
        
        // Check flash support
        const track = s.getVideoTracks()[0];
        const capabilities = track.getCapabilities ? track.getCapabilities() : {};
        if (capabilities.torch) {
            flashBtn.style.display = 'block';
            isFlashOn = false; // Reset state
            flashBtn.querySelector('m3e-icon').name = 'flash_on';
        } else {
            flashBtn.style.display = 'none';
        }
        requestAnimationFrame(tick);
    };

    const handleCameraError = (err) => {
        console.error(err);
        if (err.name === 'NotAllowedError' || err.name === 'PermissionDeniedError') {
            showAlertDialog(t('camera_access_denied'));
        } else {
            showAlertDialog(t('camera_access_failed', {msg: err.message}));
        }
        stopScan();
    };
    
    flashBtn.addEventListener('click', toggleFlash);

    // Get available cameras
    try {
        const devices = await navigator.mediaDevices.enumerateDevices();
        videoDevices = devices.filter(device => device.kind === 'videoinput');
        
        if (videoDevices.length > 1) {
            switchCameraBtn.style.display = 'block';
            switchCameraBtn.addEventListener('click', () => {
                currentCameraIndex = (currentCameraIndex + 1) % videoDevices.length;
                startCamera(videoDevices[currentCameraIndex].deviceId);
            });
        }
        
        // Start with default (usually back camera due to facingMode: environment preference if no deviceId)
        startCamera();
    } catch (e) {
        console.error("Error enumerating devices", e);
        startCamera(); // Try starting anyway
    }

    function tick() {
        if (video.readyState === video.HAVE_ENOUGH_DATA) {
            canvasElement.height = video.videoHeight;
            canvasElement.width = video.videoWidth;
            canvas.drawImage(video, 0, 0, canvasElement.width, canvasElement.height);
            const imageData = canvas.getImageData(0, 0, canvasElement.width, canvasElement.height);
            const code = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: "dontInvert" });
            if (code && code.data.startsWith('otpauth://')) {
                if (navigator.vibrate) navigator.vibrate(200);

                try {
                    const AudioContext = window.AudioContext || window.webkitAudioContext;
                    if (AudioContext) {
                        const ctx = new AudioContext();
                        const osc = ctx.createOscillator();
                        const gain = ctx.createGain();
                        osc.connect(gain);
                        gain.connect(ctx.destination);
                        osc.frequency.value = 800;
                        gain.gain.value = 0.1;
                        osc.start();
                        setTimeout(() => { osc.stop(); ctx.close(); }, 150);
                    }
                } catch (e) {}

                const url = new URL(code.data);
                const secret = url.searchParams.get('secret');
                document.getElementById(targetInputId).value = secret;
                stopScan();
                return;
            }
        }
        requestAnimationFrame(tick);
    }
}

// --- Security Advisor AI (Aura) ---

async function openSecurityAdvisor() {
    const dialog = document.getElementById('security_advisor_dialog');
    const list = document.getElementById('advisor_recommendations');
    if (!dialog || !list) return;

    list.innerHTML = `<div class="text-center mt-3"><m3e-loading-indicator></m3e-loading-indicator><p class="text-small text-secondary mt-1">${t('aura_thinking')}</p></div>`;
    
    const chatHistory = document.getElementById('advisor_chat_history');
    if (chatHistory) {
        // Keep only the first welcome message if it's the first time
        const welcome = chatHistory.querySelector('.advisor-avatar-row');
        chatHistory.innerHTML = '';
        if (welcome) chatHistory.appendChild(welcome);
        chatHistory.appendChild(list);
    }
    
    dialog.open = true;

    // Simulate AI thinking for initial advice
    setTimeout(async () => {
        const advice = await generateAIAdvice();
        renderAdvice(advice);
    }, 1200);
}

function sendAdvisorMessage(text, role = 'aura') {
    const chatHistory = document.getElementById('advisor_chat_history');
    if (!chatHistory) return;

    const row = document.createElement('div');
    row.className = role === 'user' ? 'user-message-row' : 'advisor-avatar-row';

    if (role === 'user') {
        row.innerHTML = `<div class="user-bubble">${DOMPurify.sanitize(text)}</div>`;
    } else {
        row.innerHTML = `
            <div class="advisor-avatar shine-animation">
                <m3e-icon name="auto_awesome"></m3e-icon>
            </div>
            <div class="advisor-bubble">
                <p>${text}</p>
            </div>
        `;
    }

    chatHistory.appendChild(row);
    chatHistory.scrollTop = chatHistory.scrollHeight;
}

async function handleAdvisorChat() {
    const input = document.getElementById('advisor_chat_input');
    const text = input.value.trim();
    if (!text) return;

    input.value = '';
    sendAdvisorMessage(text, 'user');

    // Show typing indicator
    const chatHistory = document.getElementById('advisor_chat_history');
    const typingRow = document.createElement('div');
    typingRow.className = 'advisor-avatar-row aura-typing-indicator';
    typingRow.innerHTML = `
        <div class="advisor-avatar shine-animation">
            <m3e-icon name="auto_awesome"></m3e-icon>
        </div>
        <div class="advisor-bubble typing-bubble">
            <div class="dot-pulse"></div>
            <span>${t('aura_typing')}</span>
        </div>
    `;
    chatHistory.appendChild(typingRow);
    chatHistory.scrollTop = chatHistory.scrollHeight;

    setTimeout(async () => {
        typingRow.remove();
        const response = await generateAIResponse(text);
        sendAdvisorMessage(response, 'aura');
    }, 1000 + Math.random() * 1000);
}

async function generateAIResponse(userMessage) {
    const msg = userMessage.toLowerCase();
    const adviceList = await generateAIAdvice();

    // 1. Weak Passwords
    if (msg.includes('弱い') || msg.includes('weak') || msg.includes('強度') || msg.includes('strength')) {
        const weak = adviceList.filter(a => a.priority === 'high' || a.title === t('advice_strong_pass'));
        if (weak.length > 0) {
            return t('aura_weak_passwords_found', {count: weak.length, title: weak[0].item.title});
        }
        return t('aura_no_weak_passwords');
    }

    // 2. 2FA / 二段階認証
    if (msg.includes('2fa') || msg.includes('認証') || msg.includes('auth')) {
        const no2fa = adviceList.filter(a => a.title === t('advice_enable_2fa'));
        if (no2fa.length > 0) {
            return t('aura_2fa_recommendation', {title: no2fa[0].item.title});
        }
        return t('aura_2fa_all_set');
    }

    // 3. Reuse / 使い回し
    if (msg.includes('使い回し') || msg.includes('同じ') || msg.includes('reuse') || msg.includes('same')) {
        const reused = adviceList.filter(a => a.title === t('advice_unique_pass'));
        if (reused.length > 0) {
            return t('aura_reused_passwords_found', {desc: reused[0].desc});
        }
        return t('aura_no_reused_passwords');
    }

    // 4. Specific service check
    for (const item of savedPasswords) {
        if (item.deleted) continue;
        if (msg.includes(item.title.toLowerCase()) || (item.website && msg.includes(item.website.toLowerCase()))) {
            const score = await calculatePasswordStrength(item.password);
            let response = t('aura_service_check_about', {title: item.title});
            if (score < 3) response += t('aura_service_weak_password');
            if (!item.secret) response += t('aura_service_no_2fa');
            if (score >= 3 && item.secret) response += t('aura_service_secure');
            return response;
        }
    }

    // Default
    return t('aura_no_match');
}

async function generateAIAdvice() {
    if (!savedPasswords) return [];
    const adviceList = [];

    // Prioritize high-value accounts (keywords in title/website)
    const highValueKeywords = ['google', 'gmail', 'bank', 'bank', 'crypto', 'coin', 'amazon', 'apple', 'microsoft', 'github', 'paypal', 'facebook', 'instagram', 'twitter', 'x.com'];
    
    for (const item of savedPasswords) {
        if (item.deleted) continue;

        const lowcaseTitle = (item.title || "").toLowerCase();
        const lowcaseWebsite = (item.website || "").toLowerCase();
        const isHighValue = highValueKeywords.some(kw => lowcaseTitle.includes(kw) || lowcaseWebsite.includes(kw));
        
        const score = await calculatePasswordStrength(item.password);
        
        // 1. Weak Password on High Value Account
        if (isHighValue && score < 3) {
            adviceList.push({
                priority: 'high',
                title: t('advice_strong_pass'),
                desc: `${item.title}: ${t('risk_weak')}`,
                icon: 'priority_high',
                itemId: item.id,
                item: item
            });
        }

        // 2. Missing 2FA on High Value Account
        if (isHighValue && !item.secret) {
            adviceList.push({
                priority: 'medium',
                title: t('advice_enable_2fa'),
                desc: `${item.title}: ${t('risk_no_2fa')}`,
                icon: 'vpn_key',
                itemId: item.id,
                item: item
            });
        }
    }

    // 3. Password Reuse
    const passGroups = {};
    savedPasswords.forEach(item => {
        if (item.deleted || !item.password) return;
        if (!passGroups[item.password]) passGroups[item.password] = [];
        passGroups[item.password].push(item);
    });

    Object.values(passGroups).forEach(group => {
        if (group.length > 1) {
            adviceList.push({
                priority: 'medium',
                title: t('advice_unique_pass'),
                desc: group.map(p => p.title).join(', '),
                icon: 'sync_problem',
                itemId: group[0].id,
                item: group[0]
            });
        }
    });

    // Sort by priority
    const priorityMap = { high: 0, medium: 1, low: 2 };
    return adviceList.sort((a, b) => priorityMap[a.priority] - priorityMap[b.priority]);
}

function renderAdvice(adviceList) {
    const list = document.getElementById('advisor_recommendations');
    if (!list) return;
    list.innerHTML = '';

    if (adviceList.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'text-center mt-3 text-secondary';
        empty.textContent = t('safe');
        list.appendChild(empty);
        return;
    }

    adviceList.forEach((adv, index) => {
        const card = document.createElement('div');
        card.className = 'recommendation-card';
        card.style.animationDelay = `${index * 0.1}s`;
        
        card.innerHTML = `
            <div class="recommendation-header">
                <span class="priority-tag priority-${adv.priority}">${t(adv.priority + '_priority')}</span>
                <m3e-icon name="chevron_right" style="font-size: 18px; color: var(--md-sys-color-outline);"></m3e-icon>
            </div>
            <div class="recommendation-title">
                <m3e-icon name="${adv.icon}" style="font-size: 20px; color: var(--md-sys-color-primary);"></m3e-icon>
                <span>${adv.title}</span>
            </div>
            <div class="recommendation-desc">${adv.desc}</div>
            <div class="recommendation-target">
                ${adv.item.iconImage ? `<img src="${adv.item.iconImage}" class="recommendation-target-icon">` : `<m3e-icon name="${adv.item.iconCustom || 'key'}" class="recommendation-target-m3e-icon"></m3e-icon>`}
                <span class="text-small text-secondary">${adv.item.title}</span>
            </div>
        `;

        card.addEventListener('click', () => {
            document.getElementById('security_advisor_dialog').open = false;
            document.getElementById('security_hub_dialog').open = false;
            openDetailDialog(adv.item);
        });

        list.appendChild(card);
    });
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

    updateStrengthView(password, 'maker_pass_strength', 'maker_pass_strength_bar', 'maker_pass_crack_time');

    // Debounce history save to prevent spamming while dragging slider
    if (historyDebounceTimer) clearTimeout(historyDebounceTimer);
    historyDebounceTimer = setTimeout(() => {
        addToGeneratorHistory(password);
    }, 500);
}

function updateDetailStrength(password) {
    updateStrengthView(password, 'detail_pass_strength', 'detail_pass_strength_bar', 'detail_pass_crack_time');
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
        list.textContent = t('history_empty');
        return;
    }

    history.forEach(pass => {
        const item = document.createElement('div');
        item.className = 'history-item';
        item.style.cursor = 'pointer';
        item.title = t('click_to_copy') || 'Click to copy';
        
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
            copyToClipboard(pass, t('pass_copied'));
        });
        
        list.appendChild(item);
    });
}

function updateSecurityHub() {
    if (!savedPasswords) return;

    securityHubLists = {
        weak: [],
        no2fa: [],
        reused: []
    };

    let weakCount = 0;
    let no2faCount = 0;
    let reusedCount = 0;
    const passMap = {};

    savedPasswords.forEach(item => {
        if (item.deleted) return; // Skip deleted items
        // Weak check (score < 3 is considered weak/medium)
        const strength = calculatePasswordStrength(item.password);
        if (strength < 3) {
            weakCount++;
            securityHubLists.weak.push(item);
        }

        // 2FA check
        if (!item.secret) {
            no2faCount++;
            securityHubLists.no2fa.push(item);
        }

        // Reuse check
        if (item.password) {
            if (!passMap[item.password]) {
                passMap[item.password] = [];
            }
            passMap[item.password].push(item);
        }
    });

    Object.values(passMap).forEach(items => {
        if (items.length > 1) {
            // Count all items that are part of a reuse group
            reusedCount += items.length;
            securityHubLists.reused.push(...items);
        }
    });

    // Calculate Score (Simple Algorithm: Base 100)
    const totalItems = savedPasswords.length;
    let score = 100;
    if (totalItems > 0) {
        const weakDeduction = (weakCount / totalItems) * 40; // Max 40 deduction
        const no2faDeduction = (no2faCount / totalItems) * 20; // Max 20 deduction
        const reusedDeduction = (reusedCount / totalItems) * 40; // Max 40 deduction
        score = Math.max(0, Math.round(100 - weakDeduction - no2faDeduction - reusedDeduction));
    }

    const scoreEl = document.getElementById('hub_score');
    const circle = document.getElementById('hub_score_circle');

    // Animation
    const duration = 1000;
    const startTime = performance.now();

    function animate(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const ease = 1 - Math.pow(1 - progress, 3); // Ease out cubic
        
        const currentScore = Math.floor(score * ease);
        
        if (scoreEl) scoreEl.textContent = currentScore;
        
        let color = 'var(--md-sys-color-primary)';
        if (currentScore < 50) color = 'var(--md-sys-color-error)';
        else if (currentScore < 80) color = 'var(--color-status-medium)'; // warning color
        else color = 'var(--color-status-strong)'; // success color
        
        if (scoreEl) scoreEl.style.color = color;
        if (circle) {
            circle.style.setProperty('--score-percent', `${currentScore}%`);
        }

        if (progress < 1) {
            requestAnimationFrame(animate);
        }
    }
    
    requestAnimationFrame(animate);

    document.getElementById('hub_weak_count').textContent = weakCount;
    document.getElementById('hub_no_2fa_count').textContent = no2faCount;
    document.getElementById('hub_reused_count').textContent = reusedCount;

    // Breakdown details
    const detailsEl = document.getElementById('hub_score_details');
    if (detailsEl) {
        detailsEl.innerHTML = '';
        if (score === 100) {
            detailsEl.textContent = t('safe') || "Perfect!";
        } else {
            const ul = document.createElement('ul');
            ul.style.paddingLeft = '20px';
            ul.style.margin = '0';
            
            const addDetail = (labelKey, count, deduction) => {
                if (count > 0) {
                    const li = document.createElement('li');
                    li.textContent = `${t(labelKey)}: -${Math.round(deduction)}`;
                    ul.appendChild(li);
                }
            };

            if (totalItems > 0) {
                addDetail('weak_pass_count', weakCount, (weakCount / totalItems) * 40);
                addDetail('no_2fa_count', no2faCount, (no2faCount / totalItems) * 20);
                addDetail('reused_pass_count', reusedCount, (reusedCount / totalItems) * 40);
            }
            detailsEl.appendChild(ul);
        }
    }
}

function updateDetailRisks(item) {
    const container = document.getElementById('detail_security_risks');
    if (!container) return;
    container.innerHTML = '';

    const risks = [];

    // Strength
    const strength = calculatePasswordStrength(item.password);
    if (strength < 2) risks.push({ key: 'risk_weak', icon: 'warning', advice: 'advice_weak' });
    else if (strength < 3) risks.push({ key: 'risk_medium', icon: 'gpp_maybe', advice: 'advice_medium' });

    // 2FA
    if (!item.secret) risks.push({ key: 'risk_no_2fa', icon: 'no_encryption', advice: 'advice_no_2fa' });

    // Reused
    if (item.password) {
        const isReused = savedPasswords.some(p => !p.deleted && p.password === item.password && p.id !== item.id);
        if (isReused) risks.push({ key: 'risk_reused', icon: 'sync_problem', advice: 'advice_reused' });
    }

    risks.forEach(r => {
        const chip = document.createElement('div');
        chip.className = 'security-risk-chip';
        chip.innerHTML = `<m3e-icon name="${r.icon}" style="font-size: 16px;"></m3e-icon> <span>${t(r.key)}</span>`;
        chip.addEventListener('click', () => {
            showAlertDialog(`${t('risk_solution')}:\n${t(r.advice)}`);
        });
        container.appendChild(chip);
    });
}

function hexToRgb(hex) {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result ? {
        r: parseInt(result[1], 16),
        g: parseInt(result[2], 16),
        b: parseInt(result[3], 16)
    } : null;
}

function rgbToHsl(r, g, b) {
    r /= 255; g /= 255; b /= 255;
    const max = Math.max(r, g, b), min = Math.min(r, g, b);
    let h, s, l = (max + min) / 2;

    if (max === min) {
        h = s = 0; // achromatic
    } else {
        const d = max - min;
        s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
        switch (max) {
            case r: h = (g - b) / d + (g < b ? 6 : 0); break;
            case g: h = (b - r) / d + 2; break;
            case b: h = (r - g) / d + 4; break;
        }
        h /= 6;
    }
    return { h: h * 360, s: s * 100, l: l * 100 };
}

function applyThemeColor(color) {
    const root = document.documentElement;
    const rgb = hexToRgb(color);
    if (!rgb) return;

    const hsl = rgbToHsl(rgb.r, rgb.g, rgb.b);
    const isDark = document.body.classList.contains('dark-theme');

    // Update primary color variables
    root.style.setProperty('--md-sys-color-primary', color);
    
    // Generate Palette Tokens
    // Logic: Adjust lightness for containers and secondary colors
    if (isDark) {
        // Dark Mode Adjustments
        root.style.setProperty('--md-sys-color-primary-container', `hsl(${hsl.h}, ${hsl.s * 0.8}%, 30%)`);
        root.style.setProperty('--md-sys-color-on-primary-container', `hsl(${hsl.h}, ${hsl.s * 0.5}%, 90%)`);
        
        root.style.setProperty('--md-sys-color-secondary', `hsl(${hsl.h}, ${hsl.s * 0.4}%, 70%)`);
        root.style.setProperty('--md-sys-color-on-secondary', `hsl(${hsl.h}, 10%, 10%)`);
        root.style.setProperty('--md-sys-color-secondary-container', `hsl(${hsl.h}, ${hsl.s * 0.3}%, 25%)`);
        root.style.setProperty('--md-sys-color-on-secondary-container', `hsl(${hsl.h}, ${hsl.s * 0.4}%, 85%)`);
    } else {
        // Light Mode Adjustments
        root.style.setProperty('--md-sys-color-primary-container', `hsl(${hsl.h}, ${hsl.s * 0.7}%, 90%)`);
        root.style.setProperty('--md-sys-color-on-primary-container', `hsl(${hsl.h}, ${hsl.s}%, 15%)`);
        
        root.style.setProperty('--md-sys-color-secondary', `hsl(${hsl.h}, ${hsl.s * 0.3}%, 40%)`);
        root.style.setProperty('--md-sys-color-on-secondary', '#ffffff');
        root.style.setProperty('--md-sys-color-secondary-container', `hsl(${hsl.h}, ${hsl.s * 0.2}%, 92%)`);
        root.style.setProperty('--md-sys-color-on-secondary-container', `hsl(${hsl.h}, ${hsl.s * 0.3}%, 15%)`);
    }

    // Update UI input
    const input = document.getElementById('setting_theme_color');
    const label = document.getElementById('theme_color_value');
    if (input) input.value = color;
    if (label) label.textContent = color;

    // Save
    localStorage.setItem(CONSTANTS.STORAGE.THEME_COLOR, color);
    
    // Update meta theme-color
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', color);
}

function updateLayout() {
    const width = window.innerWidth;
    const newMode = width >= 900;
    
    if (newMode !== isTwoPaneMode) {
        isTwoPaneMode = newMode;
        const detailBody = document.getElementById('detail_form_body');
        const detailActions = document.getElementById('detail_form_actions');
        const rightPaneContainer = document.getElementById('right_pane_detail_container');
        const dialog = document.getElementById('detail_password_dialog');
        
        if (isTwoPaneMode) {
            // Move to Right Pane
            if (dialog.open) dialog.open = false; // Close dialog if open
            rightPaneContainer.appendChild(detailBody);
            rightPaneContainer.appendChild(detailActions);
            detailActions.removeAttribute('slot');
            
            // If we have a selected item, ensure pane is visible
            if (currentDetailId) {
                document.getElementById('right_pane_placeholder').classList.add('hidden');
                rightPaneContainer.classList.remove('hidden');
            }
        } else {
            // Move back to Dialog
            dialog.appendChild(detailBody);
            dialog.appendChild(detailActions);
            detailActions.setAttribute('slot', 'actions');
            document.getElementById('right_pane_content').classList.add('hidden');
        }
    }
}

function closeDetailView() {
    currentDetailId = null;
    isDetailEditMode = false;
    stopTOTPUpdate();
    
    // Clear sensitive fields
    document.getElementById('detail_pass_value').value = '';
    document.getElementById('detail_pass_secret').value = '';

    if (isTwoPaneMode) {
        document.getElementById('right_pane_detail_container').classList.add('hidden');
        document.getElementById('right_pane_placeholder').classList.remove('hidden');
        document.querySelectorAll('m3e-nav-menu-item.selected').forEach(el => el.classList.remove('selected'));
    } else {
        document.getElementById('detail_password_dialog').open = false;
    }
}

function hasDetailChanges() {
    if (!currentDetailId || !isDetailEditMode) return false;
    const item = savedPasswords.find(p => p.id === currentDetailId);
    if (!item) return false;

    const currentTitle = document.getElementById('detail_pass_title').value;
    const currentCategory = document.getElementById('detail_pass_category').value;
    const currentWebsite = document.getElementById('detail_pass_website').value;
    const currentUsername = document.getElementById('detail_pass_username').value;
    const currentValue = document.getElementById('detail_pass_value').value;
    const currentSecret = document.getElementById('detail_pass_secret').value;
    const favIcon = document.getElementById('detail_pass_favorite_btn')?.querySelector('m3e-icon');
    const isFavorite = favIcon ? (favIcon.getAttribute('name') === 'star') : (item.favorite || false);

    return (
        currentTitle !== (item.title || '') ||
        currentCategory !== (item.category || '') ||
        currentWebsite !== (item.website || '') ||
        currentUsername !== (item.username || '') ||
        currentValue !== (item.password || '') ||
        currentSecret !== (item.secret || '') ||
        isFavorite !== (item.favorite || false) ||
        (selectedIconName || null) !== (item.iconCustom || null) ||
        (selectedIconImage || null) !== (item.iconImage || null)
    );
}

function updateIconPreview(target, iconName, iconImage) {
    const preview = document.getElementById(target === 'new' ? 'new_pass_icon_preview' : 'detail_pass_icon_preview');
    if (!preview) return;
    preview.innerHTML = '';
    
    if (iconImage) {
        const img = document.createElement('img');
        img.src = iconImage;
        preview.appendChild(img);
    } else {
        const icon = document.createElement('m3e-icon');
        icon.setAttribute('name', iconName || 'key');
        preview.appendChild(icon);
    }
}

function initIconPicker() {
    const grid = document.getElementById('icon_picker_grid');
    if (!grid) return;
    grid.innerHTML = '';
    
    PREDEFINED_ICONS.forEach(iconName => {
        const item = document.createElement('div');
        item.className = 'icon-grid-item';
        item.innerHTML = `<m3e-icon name="${iconName}"></m3e-icon>`;
        item.addEventListener('click', () => {
            selectedIconName = iconName;
            selectedIconImage = null;
            updateIconPreview(currentIconPickerTarget, selectedIconName, selectedIconImage);
            document.getElementById('icon_picker_dialog').open = false;
            if (currentIconPickerTarget === 'detail') checkDetailChanges();
        });
        grid.appendChild(item);
    });

    document.getElementById('reset_icon_btn')?.addEventListener('click', () => {
        selectedIconName = null;
        selectedIconImage = null;
        updateIconPreview(currentIconPickerTarget, null, null);
        document.getElementById('icon_picker_dialog').open = false;
        if (currentIconPickerTarget === 'detail') checkDetailChanges();
    });
}

function handleIconUpload(e, target) {
    const file = e.target.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = (event) => {
        // Simple resize/crop could be added here, but for now just base64
        selectedIconImage = event.target.result;
        selectedIconName = null;
        updateIconPreview(target, null, selectedIconImage);
        if (target === 'detail') checkDetailChanges();
    };
    reader.readAsDataURL(file);
}


function checkDetailChanges() {
    const updateBtn = document.getElementById('update_password_btn');
    if (updateBtn) updateBtn.disabled = !hasDetailChanges();
}

function setDetailEditMode(enabled) {
    isDetailEditMode = enabled;
    const inputs = [
        'detail_pass_title', 'detail_pass_category', 'detail_pass_website',
        'detail_pass_username', 'detail_pass_value', 'detail_pass_secret'
    ];
    
    inputs.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.readOnly = !enabled;
            // Material 3 components might need parent form-field adjustment if they support it
            // but standard HTML readOnly should work for the input itself.
        }
    });

    // Toggle Buttons
    const editBtn = document.getElementById('edit_password_btn');
    const updateBtn = document.getElementById('update_password_btn');
    const cancelBtn = document.getElementById('cancel_edit_btn');
    const deleteBtn = document.getElementById('delete_password_btn');
    const closeBtn = document.getElementById('close_detail_btn');

    if (editBtn) editBtn.classList.toggle('hidden', enabled);
    if (updateBtn) updateBtn.classList.toggle('hidden', !enabled);
    if (cancelBtn) cancelBtn.classList.toggle('hidden', !enabled);
    if (deleteBtn) deleteBtn.classList.toggle('hidden', !enabled);
    if (closeBtn) closeBtn.classList.toggle('hidden', enabled && !isTwoPaneMode);

    // Hide edit-related actions in view mode
    const editActions = [
        'open_detail_icon_picker_btn', 'upload_detail_icon_btn',
        'fill_default_username_btn', 'generate_detail_pass_btn', 'scan_qr_detail_btn'
    ];
    editActions.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.toggle('hidden', !enabled);
    });

    // Hide TOTP secret field container in view mode
    const secretFieldContainer = document.getElementById('detail_pass_secret')?.closest('.flex-row-center-gap');
    if (secretFieldContainer) {
        secretFieldContainer.classList.toggle('hidden', !enabled);
    }

    if (!enabled) {
        checkDetailChanges();
    }
}

async function openDetailDialog(item) {
    currentDetailId = item.id;
    setDetailEditMode(false);
    const dialog = document.getElementById('detail_password_dialog');
    
    document.getElementById('detail_pass_title').value = item.title || '';
    document.getElementById('detail_pass_category').value = item.category || '';
    document.getElementById('detail_pass_website').value = item.website || '';
    document.getElementById('detail_pass_username').value = item.username || '';
    
    // Handle decryption errors safely
    const passInput = document.getElementById('detail_pass_value');
    if (item.password === DECRYPTION_ERROR_MARKER) {
        passInput.value = t('decryption_fail');
        passInput.disabled = true;
    } else {
        passInput.value = item.password || '';
        passInput.disabled = false;
    }

    // Secret field
    document.getElementById('detail_pass_secret').value = (item.secret === DECRYPTION_ERROR_MARKER) ? '' : (item.secret || '');
    
    // Reset breach check button
    const breachBtn = document.getElementById('check_breach_btn');
    if (breachBtn) {
        breachBtn.innerHTML = `<m3e-icon slot="icon" name="security"></m3e-icon> ${t('check_breach')}`;
        breachBtn.style.setProperty('--md-sys-color-primary', '');
    }

    // Store docId for cloud updates
    dialog.dataset.docId = item.id;
    
    const dFavIcon = document.getElementById('detail_pass_favorite_btn').querySelector('m3e-icon');
    dFavIcon.name = item.favorite ? 'star' : 'star_border';
    dFavIcon.style.color = item.favorite ? '#fbc02d' : '';
    
    const lastMod = item.lastModified ? new Date(item.lastModified).toLocaleString() : '-';
    document.getElementById('detail_last_modified').textContent = lastMod;

    selectedIconName = item.iconCustom || null;
    selectedIconImage = item.iconImage || null;
    updateIconPreview('detail', selectedIconName, selectedIconImage);

    const history = item.history || [];
    document.getElementById('detail_revision_count').textContent = history.length;

    const historyList = document.getElementById('detail_history_list');
    historyList.innerHTML = '';
    if (history.length === 0) {
        historyList.textContent = t('hist_empty_detail');
    } else {
        history.slice().reverse().forEach(h => {
            const div = document.createElement('div');
            div.className = 'history-item';

            const infoDiv = document.createElement('div');
            infoDiv.style.flex = '1';
            const dateStr = new Date(h.date).toLocaleString();
            
            const dateDiv = document.createElement('div');
            dateDiv.className = 'font-bold text-small';
            dateDiv.textContent = dateStr;
            infoDiv.appendChild(dateDiv);

            const titleDiv = document.createElement('div');
            titleDiv.className = 'text-small';
            titleDiv.style.opacity = '0.8';
            titleDiv.textContent = `Title: ${h.title || '-'}`;
            infoDiv.appendChild(titleDiv);

            const userDiv = document.createElement('div');
            userDiv.className = 'text-small';
            userDiv.style.opacity = '0.8';
            userDiv.textContent = `User: ${h.username || '-'}`;
            infoDiv.appendChild(userDiv);
            
            const restoreBtn = document.createElement('m3e-button');
            restoreBtn.setAttribute('variant', 'text');
            restoreBtn.style.marginLeft = 'auto';
            
            restoreBtn.addEventListener('click', function() {
                showConfirmDialog(t('restore_confirm')).then(res => {
                    if (res) {
                        document.getElementById('detail_pass_title').value = h.title || '';
                        document.getElementById('detail_pass_category').value = h.category || '';
                        document.getElementById('detail_pass_website').value = h.website || '';
                        document.getElementById('detail_pass_username').value = h.username || '';
                        document.getElementById('detail_pass_value').value = h.password || '';
                        document.getElementById('detail_pass_secret').value = h.secret || '';
                        
                        updateDetailStrength(h.password || '');
                        startTOTPUpdate(h.secret || '');
                        checkDetailChanges();
                    }
                });
            });

            const restoreLabel = document.createElement('span');
            restoreLabel.textContent = t('restore');
            restoreBtn.appendChild(restoreLabel);

            div.appendChild(infoDiv);
            div.appendChild(restoreBtn);
            historyList.appendChild(div);
        });
    }

    updateDetailStrength((item.password === DECRYPTION_ERROR_MARKER) ? '' : (item.password || ''));
    startTOTPUpdate(item.secret);
    updateDetailRisks(item); // Update risks
    checkDetailChanges(); // Initialize button state
    
    if (isTwoPaneMode) {
        document.getElementById('right_pane_placeholder').classList.add('hidden');
        document.getElementById('right_pane_detail_container').classList.remove('hidden');
        
        // Highlight selection
        document.querySelectorAll('m3e-nav-menu-item').forEach(el => {
            if (el.dataset.id === item.id) el.classList.add('selected');
            else el.classList.remove('selected');
        });
        
        // Hide close button in pane mode as it's redundant or change behavior
        document.getElementById('close_detail_btn').style.display = 'none';
    } else {
        document.getElementById('close_detail_btn').style.display = '';
        dialog.open = true;
    }
}

function getDeviceIcon(ua) {
    if (!ua) return 'devices';
    ua = ua.toLowerCase();
    if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone')) return 'smartphone';
    if (ua.includes('ipad') || ua.includes('tablet')) return 'tablet';
    return 'computer';
}

async function renderDeviceList() {
    const list = document.getElementById('device_list');
    if (!list) return;
    
    if (!currentUser) {
        list.textContent = t('history_empty');
        return;
    }
    
    list.innerHTML = '<div style="padding:10px; text-align:center;"><m3e-loading-indicator></m3e-loading-indicator></div>';
    
    try {
        const q = query(collection(db, "devices"), where("uid", "==", currentUser.uid));
        const querySnapshot = await getDocs(q);
        
        list.innerHTML = '';
        const currentDeviceId = getDeviceId();
        
        const devices = [];
        querySnapshot.forEach((doc) => {
            devices.push(doc.data());
        });
        
        // Sort by lastLogin desc
        devices.sort((a, b) => b.lastLogin - a.lastLogin);
        
        if (devices.length === 0) {
            list.textContent = t('history_empty');
            return;
        }

        devices.forEach(device => {
            const div = document.createElement('div');
            div.className = 'history-item';
            
            const isCurrent = device.deviceId === currentDeviceId;
            const iconName = getDeviceIcon(device.userAgent);
            
            // Create elements safely
            const container = document.createElement('div');
            container.style.cssText = "display:flex; align-items:center; gap:12px; width:100%;";
            
            const icon = document.createElement('m3e-icon');
            icon.name = iconName;
            icon.style.cssText = "font-size:24px; color:var(--md-sys-color-secondary);";
            
            const infoDiv = document.createElement('div');
            infoDiv.style.flex = '1';
            
            const nameDiv = document.createElement('div');
            nameDiv.className = 'font-bold';
            nameDiv.style.cssText = "display:flex; align-items:center; gap:8px;";
            nameDiv.textContent = device.deviceName || t('unknown_device');
            
            if (isCurrent) {
                const badge = document.createElement('span');
                badge.className = 'bg-strong';
                badge.style.cssText = "color:white; padding:2px 6px; border-radius:4px; font-size:10px;";
                badge.textContent = t('current_device');
                nameDiv.appendChild(badge);
            }
            
            const uaDiv = document.createElement('div');
            uaDiv.className = 'text-small text-secondary';
            uaDiv.style.cssText = "word-break: break-all; display: -webkit-box; -webkit-line-clamp: 1; -webkit-box-orient: vertical; overflow: hidden;";
            uaDiv.textContent = device.userAgent;
            
            const timeDiv = document.createElement('div');
            timeDiv.className = 'text-small text-secondary';
            timeDiv.textContent = t('last_access') + new Date(device.lastLogin).toLocaleString();
            
            infoDiv.appendChild(nameDiv);
            infoDiv.appendChild(uaDiv);
            infoDiv.appendChild(timeDiv);
            
            container.appendChild(icon);
            container.appendChild(infoDiv);
            
            if (!isCurrent) {
                const revokeBtn = document.createElement('m3e-icon-button');
                revokeBtn.title = t('force_logout');
                revokeBtn.innerHTML = '<m3e-icon name="logout" class="color-error"></m3e-icon>';
                revokeBtn.addEventListener('click', () => {
                    showConfirmDialog(t('force_logout_confirm')).then(async (res) => {
                        if (res) {
                            const mpCheck = await promptForMasterPassword();
                            if (!mpCheck) return;

                            try {
                                const provider = new GoogleAuthProvider();
                                await reauthenticateWithPopup(currentUser, provider);
                                revokeDevice(device.deviceId);
                            } catch (e) {
                                console.error("Re-auth failed", e);
                                showSnackbar(t('error'));
                            }
                        }
                    });
                });
                container.appendChild(revokeBtn);
            }
            
            div.appendChild(container);
            
            list.appendChild(div);
        });
        
    } catch (e) {
        console.error("Error fetching devices:", e);
        
        list.innerHTML = '';
        const div = document.createElement('div');
        div.style.padding = '16px';
        div.style.textAlign = 'center';
        div.style.color = 'var(--md-sys-color-error)';
        
        const text = document.createElement('div');
        text.textContent = t('error');
        if (e.code === 'permission-denied') {
             text.textContent += ' (Permission Denied)';
        }
        text.style.marginBottom = '12px';

        const btnContainer = document.createElement('div');
        btnContainer.style.display = 'flex';
        btnContainer.style.justifyContent = 'center';
        btnContainer.style.gap = '8px';

        const retryBtn = document.createElement('m3e-button');
        retryBtn.setAttribute('variant', 'outlined');
        retryBtn.innerHTML = `<m3e-icon slot="icon" name="refresh"></m3e-icon><span>${t('retry')}</span>`;
        retryBtn.addEventListener('click', () => renderDeviceList());

        const feedbackBtn = document.createElement('m3e-button');
        feedbackBtn.setAttribute('variant', 'text');
        feedbackBtn.innerHTML = `<m3e-icon slot="icon" name="feedback"></m3e-icon><span>${t('send_feedback')}</span>`;
        feedbackBtn.addEventListener('click', () => {
            document.getElementById('feedback_message').value = `Error: ${e.message} (${e.code})`;
            if (document.getElementById('feedback_include_logs')) document.getElementById('feedback_include_logs').checked = true;
            document.getElementById('feedback_dialog').open = true;
        });

        btnContainer.appendChild(retryBtn);
        btnContainer.appendChild(feedbackBtn);

        div.appendChild(text);
        div.appendChild(btnContainer);
        list.appendChild(div);
    }
}

function renderSecurityList(type) {
    const dialog = document.getElementById('security_list_dialog');
    const titleEl = document.getElementById('security_list_title');
    const contentEl = document.getElementById('security_list_content');
    
    let list = [];
    let titleKey = '';

    if (type === 'weak') {
        list = securityHubLists.weak;
        titleKey = 'security_list_weak';
    } else if (type === 'no_2fa') {
        list = securityHubLists.no2fa;
        titleKey = 'security_list_no_2fa';
    } else if (type === 'reused') {
        list = securityHubLists.reused;
        titleKey = 'security_list_reused';
    }

    titleEl.textContent = t(titleKey);
    contentEl.innerHTML = '';

    if (list.length === 0) {
        contentEl.textContent = t('history_empty'); // Reuse empty message
    } else {
        list.forEach(item => {
            const div = document.createElement('div');
            div.className = 'history-item cursor-pointer'; // Reuse history item style
            div.style.padding = '12px 8px';
            
            const infoDiv = document.createElement('div');
            
            const titleDiv = document.createElement('div');
            titleDiv.className = 'font-bold';
            titleDiv.textContent = item.title;
            infoDiv.appendChild(titleDiv);

            const userDiv = document.createElement('div');
            userDiv.className = 'text-small text-secondary';
            userDiv.textContent = item.username || '(No Username)';
            infoDiv.appendChild(userDiv);

            div.appendChild(infoDiv);

            div.addEventListener('click', () => {
                if (hasDetailChanges()) {
                    showConfirmDialog(t('discard_changes_confirm')).then(res => {
                        if (res) {
                            openDetailDialog(item);
                        }
                    });
                } else {
                    openDetailDialog(item);
                }
            });

            contentEl.appendChild(div);
        });
    }

    dialog.open = true;
}

function showContextMenu(x, y, item) {
    contextMenuItem = item;
    const menu = document.getElementById('context_menu');
    if (!menu) return;

    // Position
    menu.style.left = `${x}px`;
    menu.style.top = `${y}px`;
    menu.classList.remove('hidden');

    // Adjust if off screen (simple check)
    const rect = menu.getBoundingClientRect();
    if (rect.right > window.innerWidth) {
        menu.style.left = `${window.innerWidth - rect.width - 8}px`;
    }
    if (rect.bottom > window.innerHeight) {
        menu.style.top = `${y - rect.height}px`;
    }
}

function hideContextMenu() {
    const menu = document.getElementById('context_menu');
    if (menu) menu.classList.add('hidden');
    contextMenuItem = null;
}

function toggleSelectionMode(active) {
    isSelectionMode = active;
    selectedIds.clear();
    
    const normalBar = document.getElementById('normal_app_bar');
    const selectBar = document.getElementById('selection_app_bar');
    const fab = document.getElementById('make_fab');
    
    if (active) {
        normalBar.classList.add('hidden');
        selectBar.classList.remove('hidden');
        fab.classList.add('hidden');
        updateSelectionCount();
    } else {
        normalBar.classList.remove('hidden');
        selectBar.classList.add('hidden');
        fab.classList.remove('hidden');
    }
    
    renderPasswordList(document.getElementById('fld').value);
}

function toggleItemSelection(id) {
    if (selectedIds.has(id)) {
        selectedIds.delete(id);
    } else {
        selectedIds.add(id);
    }
    updateSelectionCount();
    // Re-render to update UI state (checkboxes/background)
    renderPasswordList(document.getElementById('fld').value);
}

function selectAllItems() {
    const filterText = document.getElementById('fld').value.toLowerCase();
    const visibleItems = savedPasswords.filter(item => {
        if (item.deleted) return false;
        if (filterText && !item.title.toLowerCase().includes(filterText) && 
            !(item.website || '').toLowerCase().includes(filterText)) {
            return false;
        }
        return true;
    });

    if (visibleItems.length === 0) return;

    const allSelected = visibleItems.every(item => selectedIds.has(item.id));

    if (allSelected) {
        visibleItems.forEach(item => selectedIds.delete(item.id));
    } else {
        visibleItems.forEach(item => selectedIds.add(item.id));
    }

    updateSelectionCount();
    renderPasswordList(document.getElementById('fld').value);
}

function updateSelectionCount() {
    document.getElementById('selection_count').textContent = t('selected_count', {count: selectedIds.size});
    
    const selectAllBtn = document.getElementById('select_all_btn');
    if (selectAllBtn) {
        const icon = selectAllBtn.querySelector('m3e-icon');
        const filterText = document.getElementById('fld').value.toLowerCase();
        const visibleItems = savedPasswords.filter(item => {
            if (item.deleted) return false;
            if (filterText && !item.title.toLowerCase().includes(filterText) && 
                !(item.website || '').toLowerCase().includes(filterText)) {
                return false;
            }
            return true;
        });
        
        const allSelected = visibleItems.length > 0 && visibleItems.every(item => selectedIds.has(item.id));
        icon.name = allSelected ? 'deselect' : 'select_all';
        selectAllBtn.title = t('select_all');
    }
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
    const emptyState = document.getElementById('empty_state_container');

    // Check if currently opened item still exists
    if (currentDetailId) {
        const exists = savedPasswords.some(p => p.id === currentDetailId && !p.deleted);
        if (!exists) {
            closeDetailView();
        } else {
            checkDetailChanges();
        }
    }

    // Clear lists
    favList.querySelectorAll('m3e-nav-menu-item').forEach(item => item.remove());
    
    // Remove dynamic groups
    const groups = navMenu.querySelectorAll('m3e-nav-menu-item-group:not(#favorite_list)');
    groups.forEach(g => g.remove());

    const categories = {};
    const categoryNames = new Set();
    let visibleCount = 0;

    savedPasswords.forEach((item, index) => {
        if (item.deleted) return; // Skip deleted items
        if (filterText && !item.title.toLowerCase().includes(filterText.toLowerCase()) && 
            !(item.website || '').toLowerCase().includes(filterText.toLowerCase())) {
            return;
        }

        visibleCount++;
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

    // Handle Empty State
    if (visibleCount === 0) {
        if (emptyState) emptyState.classList.remove('hidden');
        if (favList) favList.classList.add('hidden');
    } else {
        if (emptyState) emptyState.classList.add('hidden');
        // Only show favorite list if it has items
        if (favList.children.length > 1) favList.classList.remove('hidden'); // > 1 because of heading
        else favList.classList.add('hidden');
    }

    // Create groups
    Object.keys(categories).sort().forEach(catName => {
        const group = document.createElement('m3e-nav-menu-item-group');
        group.style.marginBottom = '8px';
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
    newItem.classList.add('swipe-item');
    newItem.dataset.id = item.id; // For selection highlighting
    
    if (isSelectionMode) {
        // Selection Mode UI
        const isSelected = selectedIds.has(item.id);
        if (isSelected) newItem.classList.add('selected');
        
        const icon = document.createElement('m3e-icon');
        icon.name = isSelected ? 'check_box' : 'check_box_outline_blank';
        icon.slot = 'icon';
        if (isSelected) icon.style.color = 'var(--md-sys-color-primary)';
        newItem.appendChild(icon);

        const label = document.createElement('div');
        label.slot = 'label';
        label.className = 'nav-item-label-container';

        const titleSpan = document.createElement('span');
        titleSpan.textContent = item.title;
        titleSpan.className = 'nav-item-title';
        label.appendChild(titleSpan);

        if (item.category) {
            const catSpan = document.createElement('span');
            catSpan.className = 'category-badge';
            catSpan.textContent = item.category;
            label.appendChild(catSpan);
        }
        newItem.appendChild(label);

        newItem.addEventListener('click', (e) => {
            e.preventDefault();
            toggleItemSelection(item.id);
        });
    } else {
        // Normal Mode UI
        newItem.draggable = true;
        newItem.dataset.index = index;
        newItem.addEventListener('dragstart', handleDragStart);
        newItem.addEventListener('dragover', handleDragOver);
        newItem.addEventListener('dragleave', handleDragLeave);
        newItem.addEventListener('drop', handleDrop);
        newItem.addEventListener('dragend', handleDragEnd);
        
        if (isTwoPaneMode && currentDetailId === item.id) {
            newItem.classList.add('selected');
        }

        let icon;
        if (item.iconImage) {
            icon = document.createElement('img');
            icon.src = item.iconImage;
            icon.className = 'nav-item-custom-icon';
        } else if (item.iconCustom) {
            icon = document.createElement('m3e-icon');
            icon.setAttribute('name', item.iconCustom);
        } else if (item.website) {
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

        // Async strength calculation for UI
        getStrengthInfo(item.password).then(info => {
            if (icon.tagName.toLowerCase() === 'm3e-icon' && icon.name === 'key') {
                icon.classList.add(info.strengthClass);
            }
            titleSpan.classList.add(info.strengthClass);
        });

        const label = document.createElement('div');
        label.slot = 'label';
        label.className = 'nav-item-label-container';

        const titleSpan = document.createElement('span');
        titleSpan.textContent = item.title;
        titleSpan.className = 'nav-item-title'; // Classes added async above

        label.appendChild(titleSpan);

        if (item.username) {
            const usernameSpan = document.createElement('span');
            usernameSpan.className = 'nav-item-username';
            usernameSpan.textContent = item.username;
            label.appendChild(usernameSpan);
        }

        if (item.category) {
            const catSpan = document.createElement('span');
            catSpan.className = 'category-badge';
            catSpan.textContent = item.category;
            label.appendChild(catSpan);
        }

        newItem.appendChild(icon);
        newItem.appendChild(label);

        // Trailing Icons Container
        const trailingContainer = document.createElement('div');
        trailingContainer.slot = 'trailing-icon';
        trailingContainer.style.display = 'flex';
        trailingContainer.style.alignItems = 'center';
        trailingContainer.style.gap = '4px';
        trailingContainer.style.paddingRight = '8px';

        // Favorite Button
        const favBtn = document.createElement('m3e-icon-button');
        const favIcon = document.createElement('m3e-icon');
        favIcon.name = item.favorite ? 'star' : 'star_border';
        if (item.favorite) favIcon.style.color = '#fbc02d';
        favBtn.appendChild(favIcon);

        favBtn.addEventListener('click', async function(e) {
            e.stopPropagation();
            item.favorite = !item.favorite;
            await saveOrUpdateItem(item);
            showSnackbar(item.favorite ? t('fav_added') : t('fav_removed'));
        });
        trailingContainer.appendChild(favBtn);

        // Drag Handle for Mobile
        const dragHandle = document.createElement('m3e-icon');
        dragHandle.setAttribute('name', 'drag_indicator');
        dragHandle.name = 'drag_indicator';
        dragHandle.style.cursor = 'grab';
        dragHandle.style.color = 'var(--md-sys-color-on-surface-variant)';
        dragHandle.classList.add('mobile-drag-handle');

        let isDragging = false;
        let startY = 0;
        let lastItem = null;

        dragHandle.addEventListener('touchstart', (e) => {
            isDragging = true;
            startY = e.touches[0].clientY;
            newItem.style.zIndex = '100';
            newItem.style.boxShadow = 'var(--md-sys-elevation-3)';
            newItem.style.backgroundColor = 'var(--md-sys-color-surface-container-high)';
            if (navigator.vibrate) navigator.vibrate(10);
            e.stopPropagation();
        }, {passive: false});

        dragHandle.addEventListener('touchmove', (e) => {
            if (!isDragging) return;
            e.preventDefault();
            const currentY = e.touches[0].clientY;
            const diffY = currentY - startY;
            newItem.style.transform = `translateY(${diffY}px)`;

            // Find item under touch
            const elementUnder = document.elementFromPoint(e.touches[0].clientX, currentY);
            const targetItem = elementUnder?.closest('m3e-nav-menu-item');
            
            if (targetItem && targetItem !== newItem && targetItem.dataset.index !== undefined) {
                if (lastItem) lastItem.style.border = '';
                targetItem.style.borderTop = diffY < 0 ? '2px solid var(--md-sys-color-primary)' : '';
                targetItem.style.borderBottom = diffY > 0 ? '2px solid var(--md-sys-color-primary)' : '';
                lastItem = targetItem;
            } else if (lastItem) {
                lastItem.style.border = '';
                lastItem = null;
            }
        }, {passive: false});

        dragHandle.addEventListener('touchend', async (e) => {
            if (!isDragging) return;
            isDragging = false;
            newItem.style.zIndex = '';
            newItem.style.boxShadow = '';
            newItem.style.transform = '';
            newItem.style.backgroundColor = '';
            if (lastItem) lastItem.style.border = '';

            const currentY = e.changedTouches[0].clientY;
            const elementUnder = document.elementFromPoint(e.changedTouches[0].clientX, currentY);
            const targetItem = elementUnder?.closest('m3e-nav-menu-item');

            if (targetItem && targetItem !== newItem && targetItem.dataset.index !== undefined) {
                const srcIndex = parseInt(newItem.dataset.index);
                const targetIndex = parseInt(targetItem.dataset.index);
                
                if (!isNaN(srcIndex) && !isNaN(targetIndex)) {
                    const itemToMove = savedPasswords[srcIndex];
                    savedPasswords.splice(srcIndex, 1);
                    savedPasswords.splice(targetIndex, 0, itemToMove);
                    if (!currentUser) await savePasswordsData();
                    renderPasswordList(document.getElementById('fld').value);
                }
            }
            lastItem = null;
        });

        trailingContainer.appendChild(dragHandle);
        newItem.appendChild(trailingContainer);

        // Click to open detail
        newItem.addEventListener('click', function(e) {
            if (longPressTriggered) {
                e.preventDefault();
                e.stopPropagation();
                return;
            }

            if (hasDetailChanges()) {
                showConfirmDialog(t('discard_changes_confirm')).then(res => {
                    if (res) {
                        openDetailDialog(item);
                    }
                });
            } else {
                openDetailDialog(item);
            }
        });

        // Swipe Logic
        let touchStartX = 0;
        let touchStartY = 0;
        let currentX = 0;
        let longPressTimer;
        let longPressTriggered = false;
        const SWIPE_THRESHOLD = 80;

        newItem.addEventListener('touchstart', (e) => {
            if (isSelectionMode) return;
            touchStartX = e.touches[0].clientX;
            touchStartY = e.touches[0].clientY;
            currentX = 0;
            longPressTriggered = false;
            newItem.style.transition = 'none';
            
            longPressTimer = setTimeout(() => {
                longPressTriggered = true;
                if (navigator.vibrate) navigator.vibrate(50);
                showContextMenu(touchStartX, touchStartY, item);
            }, 500);
        }, {passive: true});

        newItem.addEventListener('touchmove', (e) => {
            if (isSelectionMode) return;
            if (longPressTimer) clearTimeout(longPressTimer);
            if (!touchStartX) return;
            
            const touch = e.touches[0];
            const diffX = touch.clientX - touchStartX;
            const diffY = touch.clientY - touchStartY;

            // Check if movement is mostly horizontal
            if (Math.abs(diffX) > Math.abs(diffY) && Math.abs(diffX) > 10) {
                if (e.cancelable) e.preventDefault();
                
                currentX = diffX;
                // Limit drag distance visually
                const dragX = diffX > 0 ? Math.min(diffX, 150) : Math.max(diffX, -150);
                newItem.style.transform = `translateX(${dragX}px)`;
                
                // Visual cues
                if (diffX > 0) {
                    // Right: Favorite (Yellowish)
                    newItem.style.backgroundColor = 'var(--md-sys-color-secondary-container)';
                } else {
                    // Left: Delete (Reddish)
                    newItem.style.backgroundColor = 'var(--md-sys-color-error-container)';
                }
            }
        }, {passive: false});

        newItem.addEventListener('touchend', async () => {
            if (isSelectionMode) return;
            if (longPressTimer) clearTimeout(longPressTimer);
            newItem.style.transition = 'transform 0.3s ease, background-color 0.3s ease';
            newItem.style.transform = '';
            newItem.style.backgroundColor = '';
            
            if (currentX > SWIPE_THRESHOLD) {
                // Favorite
                item.favorite = !item.favorite;
                await saveOrUpdateItem(item);
                showSnackbar(item.favorite ? t('fav_added') : t('fav_removed'));
            } else if (currentX < -SWIPE_THRESHOLD) {
                // Delete
                showConfirmDialog(t('delete_confirm')).then(async res => {
                    if (res) {
                        const verified = await verifyDestructiveAction();
                        if (verified) deleteItem(item.id);
                    }
                });
            }
        });

        // Desktop Right Click
        newItem.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            showContextMenu(e.clientX, e.clientY, item);
        });
    }

    listGroup.appendChild(newItem);
}

// --- Storage Operations (Unified) ---

async function saveOrUpdateItem(item) {
    if (currentUser) {
        // Cloud Mode
        
        // Check for decryption errors to prevent overwriting data with error messages
        if (item.password === DECRYPTION_ERROR_MARKER || item.secret === DECRYPTION_ERROR_MARKER) {
             showAlertDialog(t('decryption_fail'));
             return;
        }

        try {
            // Encrypt all sensitive fields
            const encryptedTitle = await encryptCloud(item.title || '');
            const encryptedCategory = await encryptCloud(item.category || '');
            const encryptedWebsite = await encryptCloud(item.website || '');
            const encryptedUsername = await encryptCloud(item.username || '');
            const encryptedPassword = await encryptCloud(item.password || '');
            const encryptedSecret = await encryptCloud(item.secret || '');
            const encryptedFavorite = await encryptCloud(String(item.favorite || false));
            const encryptedHistory = await encryptCloud(JSON.stringify(item.history || []));

            const dataToSave = {
                uid: currentUser.uid,
                title: encryptedTitle,
                category: encryptedCategory,
                website: encryptedWebsite,
                username: encryptedUsername,
                password: encryptedPassword,
                secret: encryptedSecret,
                favorite: encryptedFavorite,
                history: encryptedHistory,
                iconCustom: item.iconCustom || null,
                iconImage: item.iconImage || null,
                lastModified: item.lastModified,
                deleted: item.deleted || false,
                deletedAt: item.deletedAt || null
            };

            if (item.id) {
                await updateDoc(doc(db, "passwords", item.id), dataToSave);
            } else {
                await addDoc(collection(db, "passwords"), dataToSave);
            }
            // Note: onSnapshot will handle the UI update
        } catch (e) {
            console.error("Error saving to cloud:", e);
            showSnackbar(t('save_fail') + ": " + e.message);
        }
    } else {
        // Local Mode
        const existingIndex = item.id ? savedPasswords.findIndex(p => p.id === item.id) : -1;
        if (existingIndex !== -1) {
            savedPasswords[existingIndex] = item;
        } else {
            item.id = crypto.randomUUID();
            savedPasswords.push(item);
        }
        await savePasswordsData();
        renderPasswordList(document.getElementById('fld').value);
    }
}

async function verifyDestructiveAction() {
    const isRequired = localStorage.getItem(CONSTANTS.STORAGE.REQUIRE_AUTH_ON_DELETE) === 'true';
    if (!isRequired) return true;

    const mpCheck = await promptForMasterPassword();
    if (!mpCheck) return false;

    if (currentUser) {
         try {
             const provider = new GoogleAuthProvider();
             await reauthenticateWithPopup(currentUser, provider);
         } catch (e) {
             console.error("Re-auth failed", e);
             showSnackbar(t('error'));
             return false;
         }
    }
    return true;
}

async function verifySensitiveAction() {
    const isRequired = localStorage.getItem(CONSTANTS.STORAGE.REQUIRE_AUTH_ON_SHOW_COPY) === 'true';
    if (!isRequired) return true;

    const mpCheck = await promptForMasterPassword();
    if (!mpCheck) return false;

    if (currentUser) {
         try {
             const provider = new GoogleAuthProvider();
             await reauthenticateWithPopup(currentUser, provider);
         } catch (e) {
             console.error("Re-auth failed", e);
             showSnackbar(t('error'));
             return false;
         }
    }
    return true;
}

// Soft delete (Move to Trash)
async function deleteItem(id) {
    const item = savedPasswords.find(p => p.id === id);
    if (!item) return;

    const updatedItem = { ...item, deleted: true, deletedAt: Date.now() };
    await saveOrUpdateItem(updatedItem);
}

// Restore from Trash
async function restoreItem(id) {
    const item = savedPasswords.find(p => p.id === id);
    if (!item) return;

    const updatedItem = { ...item, deleted: false, deletedAt: null };
    await saveOrUpdateItem(updatedItem);
    renderTrashList(); // Refresh trash UI
}

async function deleteSelectedItems() {
    const count = selectedIds.size;
    if (count === 0) return;

    const confirm = await showConfirmDialog(t('delete_selected_confirm', {count: count}));
    if (confirm) {
        const verified = await verifyDestructiveAction();
        if (!verified) return;

        if (currentUser) {
            // Cloud: parallel delete
            const promises = Array.from(selectedIds).map(id => deleteItem(id));
            await Promise.all(promises);
        } else {
            // Local: batch update
            const now = Date.now();
            savedPasswords.forEach(p => {
                if (selectedIds.has(p.id)) {
                    p.deleted = true;
                    p.deletedAt = now;
                }
            });
            await savePasswordsData();
            renderPasswordList(document.getElementById('fld').value);
        }
        toggleSelectionMode(false);
        showSnackbar(t('pass_deleted'));
    }
}

// Hard delete (Permanent)
async function permanentDeleteItem(id) {
    const index = savedPasswords.findIndex(p => p.id === id);
    if (index === -1) return;

    if (currentUser) {
        try {
            await deleteDoc(doc(db, "passwords", id));
        } catch (e) {
            console.error("Error deleting from cloud:", e);
            showSnackbar(t('delete_fail'));
        }
    } else {
        savedPasswords.splice(index, 1);
        await savePasswordsData();
    }
    renderTrashList(); // Refresh trash UI
}

async function emptyTrash() {
    const verified = await verifyDestructiveAction();
    if (!verified) return;

    const deletedItems = savedPasswords.filter(p => p.deleted);
    for (const item of deletedItems) {
        await permanentDeleteItem(item.id);
    }
    renderTrashList();
}

function renderTrashList() {
    const list = document.getElementById('trash_list');
    list.innerHTML = '';
    const deletedItems = savedPasswords.filter(p => p.deleted).sort((a, b) => b.deletedAt - a.deletedAt);
    
    if (deletedItems.length === 0) {
        list.textContent = t('trash_empty');
        return;
    }

    deletedItems.forEach(item => {
        const div = document.createElement('div');
        div.className = 'history-item';

        // Create elements safely instead of innerHTML
        const infoDiv = document.createElement('div');
        infoDiv.style.flex = '1';
        
        const titleDiv = document.createElement('div');
        titleDiv.className = 'font-bold';
        titleDiv.textContent = item.title;
        
        const dateDiv = document.createElement('div');
        dateDiv.className = 'text-small text-secondary';
        dateDiv.textContent = new Date(item.deletedAt).toLocaleString();
        
        infoDiv.appendChild(titleDiv);
        infoDiv.appendChild(dateDiv);
        
        const btnDiv = document.createElement('div');
        btnDiv.style.display = 'flex';
        btnDiv.style.gap = '8px';
        
        const restoreBtn = document.createElement('m3e-icon-button');
        restoreBtn.title = t('restore');
        restoreBtn.innerHTML = '<m3e-icon name="restore_from_trash"></m3e-icon>';
        restoreBtn.addEventListener('click', () => restoreItem(item.id));
        
        const deleteBtn = document.createElement('m3e-icon-button');
        deleteBtn.title = t('delete_permanently');
        deleteBtn.innerHTML = '<m3e-icon name="delete_forever" style="color:var(--md-sys-color-error)"></m3e-icon>';
        deleteBtn.addEventListener('click', () => {
            showConfirmDialog(t('delete_confirm')).then(async res => {
                if (res) {
                    const verified = await verifyDestructiveAction();
                    if (verified) permanentDeleteItem(item.id);
                }
            });
        });

        btnDiv.appendChild(restoreBtn);
        btnDiv.appendChild(deleteBtn);

        div.appendChild(infoDiv);
        div.appendChild(btnDiv);

        list.appendChild(div);
    });
}

// --- Initialization & Auth ---

function getDeviceId() {
    let deviceId = localStorage.getItem('soul_device_id');
    if (!deviceId) {
        deviceId = crypto.randomUUID();
        localStorage.setItem('soul_device_id', deviceId);
    }
    return deviceId;
}

function getDeviceName() {
    const ua = navigator.userAgent;
    let browser = "Unknown";
    if (ua.indexOf("Firefox") > -1) browser = "Firefox";
    else if (ua.indexOf("SamsungBrowser") > -1) browser = "Samsung Internet";
    else if (ua.indexOf("Opera") > -1 || ua.indexOf("OPR") > -1) browser = "Opera";
    else if (ua.indexOf("Trident") > -1) browser = "Internet Explorer";
    else if (ua.indexOf("Edge") > -1) browser = "Edge";
    else if (ua.indexOf("Chrome") > -1) browser = "Chrome";
    else if (ua.indexOf("Safari") > -1) browser = "Safari";

    let os = "Unknown";
    if (ua.indexOf("Win") > -1) os = "Windows";
    else if (ua.indexOf("Mac") > -1) os = "MacOS";
    else if (ua.indexOf("Linux") > -1) os = "Linux";
    else if (ua.indexOf("Android") > -1) os = "Android";
    else if (ua.indexOf("like Mac") > -1) os = "iOS";

    return `${browser} on ${os}`;
}

async function registerLoginDevice(user) {
    if (!user) return;
    const deviceId = getDeviceId();
    const deviceName = getDeviceName();
    
    const deviceData = {
        deviceId: deviceId,
        deviceName: deviceName,
        userAgent: navigator.userAgent,
        lastLogin: Date.now(),
        uid: user.uid,
        email: user.email || ''
    };

    try {
        // Store in 'devices' collection with a composite key to allow querying by user
        const deviceRef = doc(db, "devices", `${user.uid}_${deviceId}`);
        await setDoc(deviceRef, deviceData, { merge: true });

        // Listen for revocation (deletion of this document)
        if (deviceCheckUnsubscribe) deviceCheckUnsubscribe();
        deviceCheckUnsubscribe = onSnapshot(deviceRef, (docSnapshot) => {
            if (!docSnapshot.exists()) {
                console.log("Device session revoked.");
                signOut(auth).then(() => {
                    // Use alert or simple dialog since we are reloading
                    alert(t('session_expired'));
                    location.reload();
                });
            }
        }, (error) => {
            console.error("Device check error:", error);
        });

    } catch (e) {
        console.error("Error registering device:", e);
    }
}

function initFirestoreSync(user) {
    // console.log("Sync initialized for user:", user.uid); // Removed for production privacy
    const q = query(collection(db, "passwords"), where("uid", "==", user.uid));
    
    if (firestoreSyncUnsubscribe) firestoreSyncUnsubscribe();
    firestoreSyncUnsubscribe = onSnapshot(q, async (querySnapshot) => {
        const newPasswords = [];
        for (const doc of querySnapshot.docs) {
            const data = doc.data();
            
            // Helper to safely decrypt or return original if not a string (for backward compatibility)
            const safeDecrypt = async (val) => {
                if (typeof val !== 'string') return val;
                return await decryptCloud(val);
            };

            const title = await safeDecrypt(data.title);
            const category = await safeDecrypt(data.category);
            const website = await safeDecrypt(data.website);
            const username = await safeDecrypt(data.username);
            const password = await safeDecrypt(data.password);
            const secret = await safeDecrypt(data.secret);
            
            let favorite = false;
            const favVal = await safeDecrypt(data.favorite);
            // Handle both boolean (old data) and string "true"/"false" (new encrypted data)
            favorite = (favVal === 'true' || favVal === true);

            let history = [];
            const histVal = await safeDecrypt(data.history);
            if (typeof histVal === 'string') {
                try { history = JSON.parse(histVal); } catch (e) { history = []; }
            } else if (Array.isArray(histVal)) {
                history = histVal;
            }

            newPasswords.push({
                id: doc.id,
                uid: data.uid,
                title: title || '',
                category: category || '',
                website: website || '',
                username: username || '',
                password: password || '',
                secret: secret || '',
                favorite: favorite,
                history: history,
                iconCustom: data.iconCustom || null,
                iconImage: data.iconImage || null,
                lastModified: data.lastModified,
                deleted: data.deleted,
                deletedAt: data.deletedAt
            });
        }
        savedPasswords = newPasswords;
        renderPasswordList(document.getElementById('fld').value);
    }, (error) => {
        console.error("Firestore sync error:", error);
        showSnackbar(t('error') + ": " + error.code);
    });
}

async function revokeDevice(deviceId) {
    if (!currentUser) return;
    try {
        await deleteDoc(doc(db, "devices", `${currentUser.uid}_${deviceId}`));
        renderDeviceList();
        showSnackbar(t('device_revoked'));
    } catch (e) {
        console.error("Error revoking device:", e);
        showSnackbar(t('error'));
    }
}

function listenForNewDevices(user) {
    if (newDeviceListenerUnsubscribe) newDeviceListenerUnsubscribe();

    const q = query(collection(db, "devices"), where("uid", "==", user.uid));
    
    // Start monitoring from now. We ignore past logins.
    const monitorStartTime = Date.now();

    newDeviceListenerUnsubscribe = onSnapshot(q, (snapshot) => {
        snapshot.docChanges().forEach((change) => {
            // 'added' means a new device record, 'modified' means an existing device logged in again
            if (change.type === 'added' || change.type === 'modified') {
                const data = change.doc.data();
                const currentDeviceId = getDeviceId();
                
                // Notify if it's NOT this device AND the login happened just now
                if (data.deviceId !== currentDeviceId && data.lastLogin > monitorStartTime) {
                    const deviceName = data.deviceName || t('unknown_device');
                    const msg = t('new_login_detected', { device: deviceName });
                    
                    if ("Notification" in window && Notification.permission === "granted") {
                        new Notification(t('security_alert'), {
                            body: msg,
                            icon: './icons/icon-192.png'
                        });
                    } else {
                        showSnackbar(msg);
                    }
                }
            }
        });
    }, (error) => {
        console.error("New device listener error:", error);
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
onAuthStateChanged(auth, async (user) => {
    if (user) {
        console.log("User logged in"); // Removed email logging for privacy
        
        const requireSecondAuth = localStorage.getItem(CONSTANTS.STORAGE.REQUIRE_SECOND_AUTH) === 'true';
        
        if (!requireSecondAuth) {
            cloudKey = await loadCloudKey();
        }

        if (!cloudKey) {
            const password = await promptForMasterPassword(true, user, 'cloud');
            if (!password) { await signOut(auth); return; }
            cloudKey = await deriveCloudKey(password, user.uid);
            
            // Ensure verifier exists in cloud (for new devices/first run)
            try {
                const userConfigRef = doc(db, "user_config", user.uid);
                const snap = await getDoc(userConfigRef);
                if (!snap.exists() || !snap.data().verifier) {
                    const newVerifier = await calculateCloudVerifier(password, user.uid);
                    await setDoc(userConfigRef, { verifier: newVerifier }, { merge: true });
                }
            } catch (e) {
                console.warn("Failed to sync verifier:", e);
            }

            if (!requireSecondAuth) {
                await saveCloudKey(cloudKey);
            }
        }

        currentUser = user;
        const loginDialog = document.getElementById('login_dialog');
        if (loginDialog) loginDialog.open = false;
        initFirestoreSync(user);
        registerLoginDevice(user);
        
        if ("Notification" in window && Notification.permission === "default") {
            Notification.requestPermission();
        }
        listenForNewDevices(user);
    } else {
        currentUser = null;
        hybridKeyPair = null;
        if (deviceCheckUnsubscribe) {
            deviceCheckUnsubscribe();
            deviceCheckUnsubscribe = null;
        }
        if (newDeviceListenerUnsubscribe) {
            newDeviceListenerUnsubscribe();
            newDeviceListenerUnsubscribe = null;
        }
        if (firestoreSyncUnsubscribe) {
            firestoreSyncUnsubscribe();
            firestoreSyncUnsubscribe = null;
        }
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
    // Anti-DevTools: Disable Context Menu & Shortcuts
    document.addEventListener('contextmenu', (e) => {
        if (['INPUT', 'TEXTAREA'].includes(e.target.tagName)) return;
        e.preventDefault();
    });
    document.addEventListener('keydown', (e) => {
        if (
            e.key === 'F12' ||
            (e.ctrlKey && e.shiftKey && ['I', 'J', 'C', 'i', 'j', 'c'].includes(e.key)) ||
            (e.ctrlKey && ['U', 'u'].includes(e.key))
        ) {
            e.preventDefault();
        }
    });

    // Anti-DevTools: Detect Open (Debugger Timing Attack)
    setInterval(() => {
        const start = performance.now();
        debugger; 
        if (performance.now() - start > 100) {
            document.body.innerHTML = '<div style="display:flex;flex-direction:column;justify-content:center;align-items:center;height:100vh;background:#121212;color:#cf6679;font-family:sans-serif;text-align:center;padding:20px;"><h1 style="margin:0 0 16px;">Security Alert</h1><p style="margin:0;">Developer Tools detected.<br>Please close them to continue.</p></div>';
            throw new Error("DevTools detected");
        }
    }, 1000);

    // Privacy Blur on Visibility Change
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            document.body.classList.add('privacy-blur');
        } else {
            document.body.classList.remove('privacy-blur');
        }
    });

    // Password Checker
    const passCheckInput = document.getElementById('pass_check_form');
    if (passCheckInput) {
        passCheckInput.addEventListener('input', (e) => {
            updateStrengthView(e.target.value, 'pass_check_result', 'check_pass_strength_bar', 'pass_crack_time');
        });
    }

    // Security Hub
    document.getElementById('open_security_hub_btn')?.addEventListener('click', () => {
        updateSecurityHub();
    });

    document.getElementById('hub_weak_item')?.addEventListener('click', () => renderSecurityList('weak'));
    document.getElementById('hub_no_2fa_item')?.addEventListener('click', () => renderSecurityList('no_2fa'));
    document.getElementById('hub_reused_item')?.addEventListener('click', () => renderSecurityList('reused'));

    // Trash
    document.getElementById('open_trash_btn')?.addEventListener('click', () => {
        renderTrashList();
        document.getElementById('trash_dialog').open = true;
    });

    document.getElementById('empty_trash_btn')?.addEventListener('click', () => {
        showConfirmDialog(t('delete_confirm')).then(res => { if(res) emptyTrash(); });
    });

    // Selection Mode
    document.getElementById('start_selection_btn')?.addEventListener('click', () => {
        toggleSelectionMode(true);
    });

    document.getElementById('cancel_selection_btn')?.addEventListener('click', () => {
        toggleSelectionMode(false);
    });

    document.getElementById('select_all_btn')?.addEventListener('click', selectAllItems);

    document.getElementById('delete_selected_btn')?.addEventListener('click', deleteSelectedItems);

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

            // Show guide for new users
            setTimeout(() => {
                document.getElementById('guide_dialog').open = true;
            }, 500);
        } else {
            showAlertDialog(t('login_fail')); // Reusing login fail or generic error
        }
    });

    // Login Dialog
    document.getElementById('login_btn')?.addEventListener('click', async () => {
        const user = document.getElementById('login_username').value;
        const pass = document.getElementById('login_password').value;
        const masterAuth = JSON.parse(localStorage.getItem(CONSTANTS.STORAGE.MASTER_AUTH));

        if (!masterAuth) return;

        // Check for lockout
        const attemptsData = getLoginAttempts(user);
        if (attemptsData.lockoutUntil && attemptsData.lockoutUntil > Date.now()) {
            const remainingTime = formatRemainingTime(attemptsData.lockoutUntil - Date.now());
            showAlertDialog(t('login_locked_out_remaining', { time: remainingTime }));
            return;
        }

        let loginSuccess = false;
        if (user === masterAuth.username && masterAuth.hash && masterAuth.salt) {
            const hash = await hashPassword(pass, masterAuth.salt);
            if (hash === masterAuth.hash) {
                loginSuccess = true;
            }
        }

        if (loginSuccess) {
            clearLoginAttempts(user);
            appKey = await deriveKey(pass, masterAuth.salt);
            document.getElementById('login_dialog').open = false;
            initLocalApp();
        } else {
            handleFailedLogin(user);
        }
    });

    // Biometric Login
    document.getElementById('biometric_login_btn')?.addEventListener('click', loginWithPasskey);
    const setupPasskeyBtn = document.getElementById('setup_passkey_btn');
    if (setupPasskeyBtn) {
        setupPasskeyBtn.addEventListener('click', registerPasskey);
        
        const manageBtn = document.createElement('m3e-button');
        manageBtn.setAttribute('variant', 'outlined');
        manageBtn.style.marginLeft = '8px';
        manageBtn.innerHTML = `<span data-i18n="manage_passkeys">${t('manage_passkeys')}</span>`;
        manageBtn.addEventListener('click', openPasskeyManager);
        setupPasskeyBtn.parentNode.insertBefore(manageBtn, setupPasskeyBtn.nextSibling);

        const bioLocalBtn = document.createElement('m3e-button');
        bioLocalBtn.setAttribute('variant', 'outlined');
        bioLocalBtn.style.marginLeft = '8px';
        bioLocalBtn.textContent = t('biometric_local');
        bioLocalBtn.addEventListener('click', registerLocalBiometric);
        setupPasskeyBtn.parentNode.insertBefore(bioLocalBtn, manageBtn.nextSibling);

        const unregisterBioLocalBtn = document.createElement('m3e-button');
        unregisterBioLocalBtn.setAttribute('variant', 'text');
        unregisterBioLocalBtn.style.marginLeft = '8px';
        unregisterBioLocalBtn.textContent = t('unregister_local');
        unregisterBioLocalBtn.addEventListener('click', unregisterLocalBiometric);
        setupPasskeyBtn.parentNode.insertBefore(unregisterBioLocalBtn, bioLocalBtn.nextSibling);

        const unregisterBtn = document.createElement('m3e-button');
        unregisterBtn.setAttribute('variant', 'text');
        unregisterBtn.style.marginLeft = '8px';
        unregisterBtn.innerHTML = `<span data-i18n="unregister_passkey">${t('unregister_passkey')}</span>`;
        unregisterBtn.addEventListener('click', unregisterPasskey);
        setupPasskeyBtn.parentNode.insertBefore(unregisterBtn, manageBtn.nextSibling);

        const helpBtn = document.createElement('m3e-icon-button');
        helpBtn.innerHTML = '<m3e-icon name="help_outline"></m3e-icon>';
        helpBtn.style.marginLeft = '8px';
        helpBtn.title = t('passkey_help_title');
        helpBtn.addEventListener('click', () => showAlertDialog(t('passkey_help_content')));
        setupPasskeyBtn.parentNode.appendChild(helpBtn);
    }

    // Google Login
    document.getElementById('google_login_btn')?.addEventListener('click', () => {
        const provider = new GoogleAuthProvider();
        signInWithPopup(auth, provider)
            .catch((error) => {
                console.error("Login failed:", error);
                showAlertDialog(t('google_login_fail') + error.message);
            });
    });

    // Logout
    document.getElementById('logout_btn')?.addEventListener('click', () => {
        showConfirmDialog(t('logout_confirm')).then(res => {
            if (res) {
                savedPasswords = []; // Clear memory
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
                iconCustom: selectedIconName,
                iconImage: selectedIconImage,
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
            selectedIconName = null;
            selectedIconImage = null;
            updateIconPreview('new', null, null);

            document.getElementById('add_password_dialog').open = false;
            showSnackbar(t('pass_created'));
        }
    });

    document.getElementById('new_pass_value')?.addEventListener('input', (e) => {
        updateStrengthView(e.target.value, null, 'new_pass_strength_bar', null);
    });

    document.getElementById('scan_qr_new_btn')?.addEventListener('click', () => {
        scanQRCode('new_pass_secret');
    });

    // Update Password
    document.getElementById('update_password_btn')?.addEventListener('click', async () => {
        if (currentDetailId) {
            const title = document.getElementById('detail_pass_title').value;
            if (title) {
                const oldItem = savedPasswords.find(p => p.id === currentDetailId);
                if (!oldItem) return;

                const favIcon = document.getElementById('detail_pass_favorite_btn')?.querySelector('m3e-icon');
                const isFavorite = favIcon ? (favIcon.getAttribute('name') === 'star') : oldItem.favorite;

                const newItem = {
                    ...oldItem,
                    title: title,
                    category: document.getElementById('detail_pass_category').value,
                    website: document.getElementById('detail_pass_website').value,
                    username: document.getElementById('detail_pass_username').value,
                    password: document.getElementById('detail_pass_value').value,
                    secret: document.getElementById('detail_pass_secret').value,
                    iconCustom: selectedIconName || null,
                    iconImage: selectedIconImage || null,
                    favorite: isFavorite
                };

                // Check changes for history
                const hasChanged = (oldItem.title !== newItem.title) ||
                                   (oldItem.password !== newItem.password) ||
                                   (oldItem.username !== newItem.username) ||
                                   (oldItem.iconCustom !== newItem.iconCustom) ||
                                   (oldItem.iconImage !== newItem.iconImage);
                
                if (hasChanged) {
                    const history = oldItem.history || [];
                    history.push({
                        date: Date.now(),
                        title: oldItem.title,
                        category: oldItem.category,
                        website: oldItem.website,
                        username: oldItem.username,
                        password: oldItem.password,
                        secret: oldItem.secret,
                        iconCustom: oldItem.iconCustom,
                        iconImage: oldItem.iconImage
                    });
                    newItem.history = history;
                    newItem.lastModified = Date.now();
                }

                await saveOrUpdateItem(newItem);
                
                setDetailEditMode(false);
                showSnackbar(t('pass_updated'));
            }
        }
    });

    // Delete Password
    document.getElementById('delete_password_btn')?.addEventListener('click', () => {
        if (currentDetailId) {
            showConfirmDialog(t('delete_confirm')).then(async res => {
                if (res) {
                    const verified = await verifyDestructiveAction();
                    if (!verified) return;

                    await deleteItem(currentDetailId);
                    closeDetailView();
                    showSnackbar(t('pass_deleted'));
                }
            });
        }
    });

    document.getElementById('close_detail_btn')?.addEventListener('click', () => {
        if (hasDetailChanges()) {
            showConfirmDialog(t('discard_changes_confirm')).then(res => {
                if (res) {
                    closeDetailView();
                }
            });
        } else {
            closeDetailView();
        }
    });

    // Generators
    document.getElementById('generate_new_pass_btn')?.addEventListener('click', () => {
        const password = generatePasswordString(16, true, true, true);
        document.getElementById('new_pass_value').value = password;
        updateStrengthView(password, null, 'new_pass_strength_bar', null);
    });

    document.getElementById('check_breach_btn')?.addEventListener('click', async function() {
        const password = document.getElementById('detail_pass_value').value;
        if (!password) return;
        
        this.innerHTML = `<m3e-icon slot="icon" name="security"></m3e-icon> ${t('checking')}`;
        const count = await checkPwnedPassword(password);
        
        if (count === -1) {
            this.innerHTML = `<m3e-icon slot="icon" name="security"></m3e-icon> ${t('error')}`;
        } else if (count === 0) {
            this.innerHTML = `<m3e-icon slot="icon" name="security"></m3e-icon> ${t('safe')}`;
            this.style.setProperty('--md-sys-color-primary', '#388e3c'); // Green
        } else {
            this.innerHTML = `<m3e-icon slot="icon" name="security"></m3e-icon> ${t('breach_found', {count: count.toLocaleString()})}`;
            this.style.setProperty('--md-sys-color-primary', '#b3261e'); // Red
        }
    });

    document.getElementById('generate_detail_pass_btn')?.addEventListener('click', () => {
        const password = generatePasswordString(16, true, true, true);
        document.getElementById('detail_pass_value').value = password;
        updateDetailStrength(password);
        checkDetailChanges();
    });

    document.getElementById('scan_qr_detail_btn')?.addEventListener('click', () => {
        scanQRCode('detail_pass_secret');
    });

    document.getElementById('regenerate_password_btn')?.addEventListener('click', generatePassword);
    document.getElementById('password_length')?.addEventListener('input', generatePassword);
    document.getElementById('include_uppercase')?.addEventListener('change', generatePassword);
    document.getElementById('include_numbers')?.addEventListener('change', generatePassword);
    document.getElementById('include_symbols')?.addEventListener('change', generatePassword);
    document.getElementById('copy_password_btn')?.addEventListener('click', () => {
        copyToClipboard(document.getElementById('auto_make_password').textContent, t('pass_copied'));
    });

    // Search
    document.getElementById('fld')?.addEventListener('input', (e) => {
        if (searchDebounceTimer) clearTimeout(searchDebounceTimer);
        searchDebounceTimer = setTimeout(() => {
            renderPasswordList(e.target.value);
        }, 300);
    });

    // FAB Listener
    document.getElementById('make_fab')?.addEventListener('click', () => {
        selectedIconName = null;
        selectedIconImage = null;
        updateIconPreview('new', null, null);
        // document.getElementById('add_password_dialog').open = true; // Removed per user request
    });

    // Detail Dialog Events
    document.getElementById('detail_password_dialog')?.addEventListener('closed', () => {
        stopTOTPUpdate();
        selectedIconName = null;
        selectedIconImage = null;
        if (!isTwoPaneMode) {
            document.getElementById('detail_pass_value').value = '';
            document.getElementById('detail_pass_secret').value = '';
            currentDetailId = null;
        }
    });

    document.getElementById('add_password_dialog')?.addEventListener('closed', () => {
        // Clear sensitive fields from DOM when dialog closes
        document.getElementById('new_pass_value').value = '';
        document.getElementById('new_pass_secret').value = '';
        updateStrengthView('', null, 'new_pass_strength_bar', null);
        selectedIconName = null;
        selectedIconImage = null;
    });

    document.getElementById('detail_pass_value')?.addEventListener('input', (e) => {
        updateDetailStrength(e.target.value);
        checkDetailChanges();
    });

    ['detail_pass_title', 'detail_pass_category', 'detail_pass_website', 'detail_pass_username', 'detail_pass_secret'].forEach(id => {
        document.getElementById(id)?.addEventListener('input', checkDetailChanges);
    });

    document.getElementById('open_website_btn')?.addEventListener('click', () => {
        let url = document.getElementById('detail_pass_website').value;
        if (url) {
            if (!/^https?:\/\//i.test(url)) url = 'http://' + url;
            const newWindow = window.open(url, '_blank');
            if (newWindow) newWindow.opener = null;
        }
    });

    document.getElementById('copy_detail_pass_btn')?.addEventListener('click', async () => {
        const verified = await verifySensitiveAction();
        if (!verified) return;
        const password = document.getElementById('detail_pass_value').value;
        copyToClipboard(password, t('pass_copied'));
    });

    document.getElementById('copy_detail_username_btn')?.addEventListener('click', () => {
        const username = document.getElementById('detail_pass_username').value;
        copyToClipboard(username, t('user_copied'));
    });

    document.getElementById('clear_history_btn')?.addEventListener('click', () => {
        if (currentDetailId) {
            showConfirmDialog(t('clear_hist_confirm')).then(async res => {
                if (res) {
                    const item = savedPasswords.find(p => p.id === currentDetailId);
                    if (!item) return;
                    item.history = [];
                    await saveOrUpdateItem(item);
                    document.getElementById('detail_revision_count').textContent = '0';
                    document.getElementById('detail_history_list').innerHTML = t('hist_empty_detail');
                    showSnackbar(t('hist_cleared'));
                }
            });
        }
    });

    document.getElementById('clear_maker_history_btn')?.addEventListener('click', () => {
        showConfirmDialog(t('clear_gen_confirm')).then(res => {
            if (res) {
                localStorage.removeItem(CONSTANTS.STORAGE.GENERATOR_HISTORY);
                renderGeneratorHistory();
                showSnackbar(t('gen_cleared'));
            }
        });
    });

    document.getElementById('totp_code')?.addEventListener('click', function() {
        const code = this.textContent;
        if (code && code !== 'Invalid Secret') {
            copyToClipboard(code, t('code_copied'));
        }
    });

    document.getElementById('detail_pass_favorite_btn')?.addEventListener('click', async function() {
        const icon = this.querySelector('m3e-icon');
        const isFav = icon.name === 'star';
        
        if (isDetailEditMode) {
            // In Edit Mode, just toggle UI and let "Update" handle the save
            if (isFav) {
                icon.name = 'star_border';
                icon.style.color = '';
            } else {
                icon.name = 'star';
                icon.style.color = '#fbc02d';
            }
            checkDetailChanges();
        } else {
            // In View Mode, save immediately
            const item = savedPasswords.find(p => p.id === currentDetailId);
            if (item) {
                item.favorite = !isFav;
                await saveOrUpdateItem(item);
                
                // Update UI
                icon.name = item.favorite ? 'star' : 'star_border';
                icon.style.color = item.favorite ? '#fbc02d' : '';
                
                showSnackbar(item.favorite ? t('fav_added') : t('fav_removed'));
            }
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

    // Language Setting
    document.getElementById('setting_language')?.addEventListener('change', (e) => {
        updateLanguage(e.target.value);
        showSnackbar(t('settings_saved'));
    });

    // Default Username Setting
    document.getElementById('save_username_btn')?.addEventListener('click', () => {
        const defaultUser = document.getElementById('setting_default_username').value;
        localStorage.setItem(CONSTANTS.STORAGE.DEFAULT_USER, defaultUser);
        showSnackbar(t('settings_saved'));
    });

    // Auto Logout Setting
    document.getElementById('save_autologout_btn')?.addEventListener('click', () => {
        const autoLogout = document.getElementById('setting_auto_logout').value;
        localStorage.setItem(CONSTANTS.STORAGE.AUTO_LOGOUT, autoLogout);
        resetAutoLogoutTimer();
        showSnackbar(t('settings_saved'));
    });

    // Require Second Auth Setting
    const requireSecondAuthCheckbox = document.getElementById('setting_require_second_auth');
    if (requireSecondAuthCheckbox) {
        requireSecondAuthCheckbox.checked = localStorage.getItem(CONSTANTS.STORAGE.REQUIRE_SECOND_AUTH) === 'true';
        requireSecondAuthCheckbox.addEventListener('change', async (e) => {
            const isRequired = e.target.checked;
            localStorage.setItem(CONSTANTS.STORAGE.REQUIRE_SECOND_AUTH, isRequired);
            if (isRequired) {
                clearCloudKey();
            } else {
                if (cloudKey) await saveCloudKey(cloudKey);
            }
            showSnackbar(t('settings_saved'));
            updateSessionTypeDisplay();
        });
    }

    // Require Auth on Delete Setting
    const requireAuthOnDeleteCheckbox = document.getElementById('setting_require_auth_on_delete');
    if (requireAuthOnDeleteCheckbox) {
        requireAuthOnDeleteCheckbox.checked = localStorage.getItem(CONSTANTS.STORAGE.REQUIRE_AUTH_ON_DELETE) === 'true';
        requireAuthOnDeleteCheckbox.addEventListener('change', (e) => {
            localStorage.setItem(CONSTANTS.STORAGE.REQUIRE_AUTH_ON_DELETE, e.target.checked);
            showSnackbar(t('settings_saved'));
        });
    }

    // Require Auth on Show/Copy Setting
    const requireAuthOnShowCopyCheckbox = document.getElementById('setting_require_auth_on_show_copy');
    if (requireAuthOnShowCopyCheckbox) {
        requireAuthOnShowCopyCheckbox.checked = localStorage.getItem(CONSTANTS.STORAGE.REQUIRE_AUTH_ON_SHOW_COPY) === 'true';
        requireAuthOnShowCopyCheckbox.addEventListener('change', (e) => {
            localStorage.setItem(CONSTANTS.STORAGE.REQUIRE_AUTH_ON_SHOW_COPY, e.target.checked);
            showSnackbar(t('settings_saved'));
        });
    }

    // Inject sync warning into setup dialog
    // ... (This part seems to be missing from the provided context, but it's okay)

    // Settings Dialog Open
    document.getElementById('settings_dialog')?.addEventListener('open', () => {
        const localSection = document.getElementById('local_master_pass_section');
        const cloudSection = document.getElementById('cloud_master_pass_section');
        if (currentUser) {
            localSection.classList.add('hidden');
            cloudSection.classList.remove('hidden');
        } else {
            localSection.classList.remove('hidden');
            cloudSection.classList.add('hidden');
        }
        updateSessionTypeDisplay();
    });
    // Recovery Kit
    document.getElementById('download_recovery_kit_btn')?.addEventListener('click', generateRecoveryKit);

    // Update Master Password
    document.getElementById('update_master_pass_btn')?.addEventListener('click', async () => {
        const currentPass = document.getElementById('setting_current_pass').value;
        const newPass = document.getElementById('setting_new_pass').value;
        const confirmPass = document.getElementById('setting_new_pass_confirm').value; // This is the old combined logic

        if (!currentPass || !newPass || !confirmPass) {
            showSnackbar(t('error'));
            return;
        }
        
        if (newPass !== confirmPass) {
            showAlertDialog(t('login_fail'));
            return;
        }

        const confirmChange = await showConfirmDialog(t('change_master_pass_confirm'));
        if (!confirmChange) return;

        const masterAuth = JSON.parse(localStorage.getItem(CONSTANTS.STORAGE.MASTER_AUTH));
        if (!masterAuth) return;

        // Verify current password
        const hash = await hashPassword(currentPass, masterAuth.salt);
        if (hash !== masterAuth.hash) {
            showAlertDialog(t('login_fail'));
            return;
        }

        try {
            const newSalt = await generateSalt();
            const newSaltB64 = arrayBufferToBase64(newSalt);
            const newHash = await hashPassword(newPass, newSalt);

            if (currentUser) {
                // Cloud Mode
                const newCloudKey = await deriveCloudKey(newPass, currentUser.uid);
                
                // Helper to encrypt with specific key
                const encryptWithKey = async (text, key) => {
                     if (!text) return "";
                     const iv = window.crypto.getRandomValues(new Uint8Array(12));
                     const encoded = new TextEncoder().encode(text);
                     const ciphertext = await window.crypto.subtle.encrypt(
                        { name: "AES-GCM", iv: iv },
                        key,
                        encoded
                     );
                     const combined = new Uint8Array(iv.length + ciphertext.byteLength);
                     combined.set(iv);
                     combined.set(new Uint8Array(ciphertext), iv.length);
                     return arrayBufferToBase64(combined);
                };

                showSnackbar(t('updating_cloud_data'));
                
                // Pause sync to avoid decryption errors during transition
                if (firestoreSyncUnsubscribe) firestoreSyncUnsubscribe();

                const updates = savedPasswords.map(async (item) => {
                    const encryptedTitle = await encryptWithKey(item.title || '', newCloudKey);
                    const encryptedCategory = await encryptWithKey(item.category || '', newCloudKey);
                    const encryptedWebsite = await encryptWithKey(item.website || '', newCloudKey);
                    const encryptedUsername = await encryptWithKey(item.username || '', newCloudKey);
                    const encryptedPassword = await encryptWithKey(item.password || '', newCloudKey);
                    const encryptedSecret = await encryptWithKey(item.secret || '', newCloudKey);
                    const encryptedFavorite = await encryptWithKey(String(item.favorite || false), newCloudKey);
                    const encryptedHistory = await encryptWithKey(JSON.stringify(item.history || []), newCloudKey);

                    return updateDoc(doc(db, "passwords", item.id), {
                        title: encryptedTitle,
                        category: encryptedCategory,
                        website: encryptedWebsite,
                        username: encryptedUsername,
                        password: encryptedPassword,
                        secret: encryptedSecret,
                        favorite: encryptedFavorite,
                        history: encryptedHistory
                    });
                });

                await Promise.all(updates);
                
                cloudKey = newCloudKey;
                
                // Update Cloud Verifier
                const newVerifier = await calculateCloudVerifier(newPass, currentUser.uid);
                await setDoc(doc(db, "user_config", currentUser.uid), { verifier: newVerifier }, { merge: true });

                // Update stored auth
                masterAuth.hash = newHash;
                masterAuth.salt = newSaltB64;
                localStorage.setItem(CONSTANTS.STORAGE.MASTER_AUTH, JSON.stringify(masterAuth));

                // Always clear saved cloud key to force authentication on next login
                clearCloudKey();
                
                // Resume sync
                initFirestoreSync(currentUser);

            } else {
                // Local Mode
                const newAppKey = await deriveKey(newPass, newSalt);
                appKey = newAppKey;
                
                masterAuth.hash = newHash;
                masterAuth.salt = newSaltB64;
                localStorage.setItem(CONSTANTS.STORAGE.MASTER_AUTH, JSON.stringify(masterAuth));
                
                await savePasswordsData();
            }

            await updatePasskeyData(newPass);

            showSnackbar(t('settings_saved'));
            document.getElementById('setting_current_pass').value = '';
            document.getElementById('setting_new_pass').value = '';
            document.getElementById('setting_new_pass_confirm').value = '';

        } catch (e) {
            console.error("Error updating master password:", e);
            showAlertDialog(t('error') + ": " + e.message);
            // Try to resume sync if it failed
            if (currentUser && !firestoreSyncUnsubscribe) initFirestoreSync(currentUser);
        }
    });

    // Update Local Master Password
    document.getElementById('update_local_master_pass_btn')?.addEventListener('click', async () => {
        const currentPass = document.getElementById('setting_local_current_pass').value;
        const newPass = document.getElementById('setting_local_new_pass').value;
        const confirmPass = document.getElementById('setting_local_new_pass_confirm').value;

        if (!currentPass || !newPass || newPass !== confirmPass) {
            showAlertDialog(t('login_fail'));
            return;
        }

        const masterAuth = JSON.parse(localStorage.getItem(CONSTANTS.STORAGE.MASTER_AUTH));
        if (!masterAuth) return;

        const hash = await hashPassword(currentPass, masterAuth.salt);
        if (hash !== masterAuth.hash) {
            showAlertDialog(t('login_fail'));
            return;
        }

        const confirmChange = await showConfirmDialog(t('change_master_pass_confirm'));
        if (!confirmChange) return;

        try {
            const newSalt = await generateSalt();
            const newSaltB64 = arrayBufferToBase64(newSalt);
            const newHash = await hashPassword(newPass, newSalt);

            const newAppKey = await deriveKey(newPass, newSalt);
            appKey = newAppKey;
            
            masterAuth.hash = newHash;
            masterAuth.salt = newSaltB64;
            localStorage.setItem(CONSTANTS.STORAGE.MASTER_AUTH, JSON.stringify(masterAuth));
            
            await savePasswordsData(); // Re-encrypts with new appKey

            await updatePasskeyData(newPass);

            showSnackbar(t('settings_saved'));
            document.getElementById('setting_local_current_pass').value = '';
            document.getElementById('setting_local_new_pass').value = '';
            document.getElementById('setting_local_new_pass_confirm').value = '';
        } catch (e) {
            console.error("Error updating local master password:", e);
            showAlertDialog(t('error') + ": " + e.message);
        }
    });

    // Update Cloud Master Password
    document.getElementById('update_cloud_master_pass_btn')?.addEventListener('click', async () => {
        if (!currentUser) return;

        const currentPass = document.getElementById('setting_cloud_current_pass').value;
        const newPass = document.getElementById('setting_cloud_new_pass').value;
        const confirmPass = document.getElementById('setting_cloud_new_pass_confirm').value;

        if (!currentPass || !newPass || newPass !== confirmPass) {
            showAlertDialog(t('login_fail'));
            return;
        }

        const verified = await promptForMasterPassword(false, currentUser, 'cloud');
        if (!verified) return;

        const confirmChange = await showConfirmDialog(t('change_master_pass_confirm'));
        if (!confirmChange) return;

        try {
            showSnackbar(t('updating_cloud_data'));
            
            // Pause sync to avoid decryption errors during transition
            if (firestoreSyncUnsubscribe) firestoreSyncUnsubscribe();

            // Ensure we have the current keys loaded (decrypted with OLD password)
            // We use currentPass to derive the key, ensuring we can decrypt even if the session key is stale
            if (!hybridKeyPair) {
                const currentCloudKey = await deriveCloudKey(currentPass, currentUser.uid);
                await getHybridKeys(currentUser.uid, currentCloudKey);
            }
            
            if (!hybridKeyPair || !hybridKeyPair.privateKey) {
                throw new Error("Failed to load current private key.");
            }

            const newCloudKey = await deriveCloudKey(newPass, currentUser.uid);

            // Re-encrypt the RSA Private Key with the NEW KEK
            const privJwk = await window.crypto.subtle.exportKey("jwk", hybridKeyPair.privateKey);
            const newEncryptedPrivateKey = await encryptWithKek(privJwk, newCloudKey);

            // Update Cloud Verifier
            const newVerifier = await calculateCloudVerifier(newPass, currentUser.uid);
            await setDoc(doc(db, "user_config", currentUser.uid), { 
                encryptedPrivateKey: newEncryptedPrivateKey,
                verifier: newVerifier 
            }, { merge: true });

            // Clear any cached key and resume sync
            clearCloudKey();
            
            // Update current session key
            cloudKey = newCloudKey;
            
            initFirestoreSync(currentUser);
            
            await updatePasskeyData(newPass);

            showSnackbar(t('settings_saved'));
            
            // Clear inputs
            document.getElementById('setting_cloud_current_pass').value = '';
            document.getElementById('setting_cloud_new_pass').value = '';
            document.getElementById('setting_cloud_new_pass_confirm').value = '';

        } catch (e) {
            console.error("Error updating cloud master password:", e);
            showAlertDialog(t('error') + ": " + e.message);
            if (currentUser && !firestoreSyncUnsubscribe) initFirestoreSync(currentUser);
        }
    });

    // Lock Vault (Destroy Key)
    document.getElementById('lock_vault_btn')?.addEventListener('click', () => {
        showConfirmDialog(t('lock_confirm')).then(res => {
            if (res) {
                clearCloudKey();
                appKey = null;
                cloudKey = null;
                savedPasswords = []; // Clear data from memory
                hybridKeyPair = null;
                location.reload();
            }
        });
    });

    // Theme Color Setting
    document.getElementById('setting_theme_color')?.addEventListener('input', (e) => {
        applyThemeColor(e.target.value);
    });

    document.getElementById('reset_theme_color_btn')?.addEventListener('click', () => {
        applyThemeColor('#0061a4'); // Default Blue
    });

    // Fill default username in "Add Password" dialog
    document.getElementById('fill_new_pass_default_username_btn')?.addEventListener('click', () => {
        const val = localStorage.getItem(CONSTANTS.STORAGE.DEFAULT_USER);
        if (val) {
            document.getElementById('new_pass_username').value = val;
            showSnackbar(t('default_user_filled'));
        } else {
            showSnackbar(t('no_default_user'));
        }
    });

    // Fill default username in "Detail" dialog
    document.getElementById('fill_default_username_btn')?.addEventListener('click', () => {
        const val = localStorage.getItem(CONSTANTS.STORAGE.DEFAULT_USER);
        if (val) {
            document.getElementById('detail_pass_username').value = val;
            showSnackbar(t('default_user_filled'));
            checkDetailChanges();
        } else {
            showSnackbar(t('no_default_user'));
        }
    });

    // Setup Password Toggles
    const passwordIds = [
        'new_pass_value', 'detail_pass_value', 'setup_password', 'setup_password_confirm',
        'login_password', 'new_pass_secret', 'detail_pass_secret',
        'setting_local_current_pass', 'setting_local_new_pass', 'setting_local_new_pass_confirm',
        'setting_cloud_current_pass', 'setting_cloud_new_pass', 'setting_cloud_new_pass_confirm'
    ];
    passwordIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.type = 'password';
            const btn = document.createElement('m3e-icon-button');
            btn.style.marginLeft = '4px';
            const icon = document.createElement('m3e-icon');
            icon.name = 'visibility';
            btn.appendChild(icon);
            btn.addEventListener('click', async (e) => {
                e.preventDefault();
                if (el.type === 'password') {
                    // Check auth for sensitive fields
                    if (id === 'detail_pass_value' || id === 'detail_pass_secret') {
                        const verified = await verifySensitiveAction();
                        if (!verified) return;
                    }
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
    const sortBtn = document.getElementById('sort_btn');
    const sortMenu = document.getElementById('sort_menu');
    
    if (sortBtn && sortMenu) {
        sortBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            sortMenu.classList.toggle('hidden');
        });

        document.addEventListener('click', (e) => {
            if (!sortMenu.contains(e.target) && !sortBtn.contains(e.target)) {
                sortMenu.classList.add('hidden');
            }
        });

        document.querySelectorAll('.sort-item').forEach(item => {
            item.addEventListener('click', async (e) => {
                const val = e.currentTarget.dataset.value;
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
                    
                    if (!currentUser) await savePasswordsData();
                    renderPasswordList(document.getElementById('fld').value);
                    showSnackbar(t('list_sorted'));
                }
                sortMenu.classList.add('hidden');
            });
        });
    }

    // Settings Tabs
    const tabBtns = document.querySelectorAll('.settings-tab-btn');
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.settings-tab-btn').forEach(b => b.setAttribute('variant', 'text'));
            document.querySelectorAll('.settings-tab-panel').forEach(p => p.classList.remove('active'));
            
            btn.setAttribute('variant', 'filled');
            const targetId = btn.getAttribute('data-tab');
            const targetPanel = document.getElementById('settings_tab_' + targetId);
            if (targetPanel) targetPanel.classList.add('active');

            if (targetId === 'security') {
                renderDeviceList();
            }
        });
    });

    // Guide
    document.getElementById('open_guide_btn')?.addEventListener('click', () => {
        document.getElementById('guide_dialog').open = true;
    });

    document.getElementById('open_ai_advisor_btn')?.addEventListener('click', () => {
        openSecurityAdvisor();
    });

    document.getElementById('fab_open_advisor_btn')?.addEventListener('click', () => {
        openSecurityAdvisor();
    });

    document.getElementById('send_advisor_chat_btn')?.addEventListener('click', handleAdvisorChat);
    document.getElementById('advisor_chat_input')?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleAdvisorChat();
    });

    // Guide Actions
    const closeGuideAndOpen = (dialogId) => {
        document.getElementById('guide_dialog').open = false;
        setTimeout(() => {
            const dialog = document.getElementById(dialogId);
            if (dialog) dialog.open = true;
        }, 200);
    };

    document.getElementById('guide_action_add')?.addEventListener('click', () => closeGuideAndOpen('add_password_dialog'));
    document.getElementById('guide_action_gen')?.addEventListener('click', () => closeGuideAndOpen('pass_maker'));
    document.getElementById('guide_action_hub')?.addEventListener('click', () => {
        updateSecurityHub();
        closeGuideAndOpen('security_hub_dialog');
    });
    document.getElementById('guide_action_advisor')?.addEventListener('click', async () => {
        await openSecurityAdvisor();
        document.getElementById('guide_dialog').open = false;
    });
    document.getElementById('guide_action_data')?.addEventListener('click', () => closeGuideAndOpen('settings_dialog'));
    document.getElementById('guide_action_settings')?.addEventListener('click', () => closeGuideAndOpen('settings_dialog'));

    // Placeholder Action
    document.getElementById('placeholder_create_btn')?.addEventListener('click', () => {
        document.getElementById('add_password_dialog').open = true;
    });

    // Context Menu Actions
    document.getElementById('ctx_copy_pass')?.addEventListener('click', async () => {
        const item = contextMenuItem;
        hideContextMenu();
        if (item && await verifySensitiveAction()) {
            copyToClipboard(item.password, t('pass_copied'));
        }
    });

    document.getElementById('ctx_copy_user')?.addEventListener('click', () => {
        if (contextMenuItem) {
            copyToClipboard(contextMenuItem.username, t('user_copied'));
        }
        hideContextMenu();
    });

    document.getElementById('ctx_edit')?.addEventListener('click', () => {
        if (contextMenuItem) {
            openDetailDialog(contextMenuItem);
        }
        hideContextMenu();
    });

    document.getElementById('ctx_move_up')?.addEventListener('click', async () => {
        if (contextMenuItem) {
            const index = savedPasswords.findIndex(p => p.id === contextMenuItem.id);
            if (index > 0) {
                const item = savedPasswords[index];
                savedPasswords.splice(index, 1);
                savedPasswords.splice(index - 1, 0, item);
                if (!currentUser) await savePasswordsData();
                renderPasswordList(document.getElementById('fld').value);
            }
        }
        hideContextMenu();
    });

    document.getElementById('ctx_move_down')?.addEventListener('click', async () => {
        if (contextMenuItem) {
            const index = savedPasswords.findIndex(p => p.id === contextMenuItem.id);
            if (index !== -1 && index < savedPasswords.length - 1) {
                const item = savedPasswords[index];
                savedPasswords.splice(index, 1);
                savedPasswords.splice(index + 1, 0, item);
                if (!currentUser) await savePasswordsData();
                renderPasswordList(document.getElementById('fld').value);
            }
        }
        hideContextMenu();
    });

    document.getElementById('ctx_delete')?.addEventListener('click', () => {
        if (contextMenuItem) {
            const id = contextMenuItem.id;
            showConfirmDialog(t('delete_confirm')).then(async res => {
                if (res) {
                    const verified = await verifyDestructiveAction();
                    if (verified) deleteItem(id);
                }
            });
        }
        hideContextMenu();
    });

    // Hide context menu on click outside
    document.addEventListener('click', (e) => {
        const menu = document.getElementById('context_menu');
        if (menu && !menu.classList.contains('hidden') && !menu.contains(e.target)) {
            hideContextMenu();
        }
    });
    document.addEventListener('scroll', hideContextMenu, {capture: true, passive: true});

    // Sidebar Resizer
    const resizer = document.getElementById('sidebar_resizer');
    const sidebar = document.getElementById('left_sidebar_content');
    if (resizer && sidebar) {
        let isResizing = false;

        resizer.addEventListener('mousedown', (e) => {
            isResizing = true;
            resizer.classList.add('resizing');
            document.body.style.cursor = 'col-resize';
            e.preventDefault();
        });

        document.addEventListener('mousemove', (e) => {
            if (!isResizing) return;
            let newWidth = e.clientX;
            if (newWidth < 200) newWidth = 200; // Min width
            if (newWidth > 600) newWidth = 600; // Max width
            sidebar.style.width = newWidth + 'px';
        });

        document.addEventListener('mouseup', () => {
            if (isResizing) {
                isResizing = false;
                resizer.classList.remove('resizing');
                document.body.style.cursor = '';
                localStorage.setItem(CONSTANTS.STORAGE.SIDEBAR_WIDTH, sidebar.style.width);
            }
        });
    }

    // Feedback
    document.getElementById('open_feedback_btn')?.addEventListener('click', () => {
        document.getElementById('feedback_message').value = '';
        const logCheck = document.getElementById('feedback_include_logs');
        if (logCheck) logCheck.checked = false;
        document.getElementById('feedback_dialog').open = true;
    });

    document.getElementById('submit_feedback_btn')?.addEventListener('click', async () => {
        const msg = document.getElementById('feedback_message').value;
        const includeLogs = document.getElementById('feedback_include_logs')?.checked;
        if (!msg) return;

        try {
            const feedbackData = {
                message: msg,
                uid: currentUser ? currentUser.uid : 'anonymous',
                userAgent: navigator.userAgent,
                version: CONSTANTS.APP_VERSION,
                timestamp: Date.now()
            };

            if (includeLogs) {
                feedbackData.logs = appLogs.join('\n');
            }

            await addDoc(collection(db, "feedback"), feedbackData);
            document.getElementById('feedback_dialog').open = false;
            showSnackbar(t('feedback_sent'));
        } catch (e) {
            console.error("Error sending feedback:", e);
            showSnackbar(t('error'));
        }
    });

    // Import/Export Logic (Simplified for brevity, similar to original script.js)
    const deleteAllBtn = document.getElementById('delete_all_data_btn');
    if (deleteAllBtn && deleteAllBtn.parentNode) {
        const container = document.createElement('div');
        container.className = 'data-management-container';

        const title = document.createElement('h4');
        title.textContent = t('data_mgmt');
        title.className = 'mt-2 mb-2';
        container.appendChild(title);

        const btnContainer = document.createElement('div');
        btnContainer.className = 'flex-row-center-gap';

        const exportBtn = document.createElement('m3e-button');
        exportBtn.setAttribute('variant', 'outlined');
        const exportLabel = document.createElement('span');
        exportLabel.textContent = t('export_json');
        exportBtn.appendChild(exportLabel);
        
        exportBtn.addEventListener('click', async () => {
            const mpCheck = await promptForMasterPassword();
            if (!mpCheck) return;

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

        const importBtn = document.createElement('m3e-button');
        importBtn.setAttribute('variant', 'outlined');
        const importLabel = document.createElement('span');
        importLabel.textContent = t('import_json');
        importBtn.appendChild(importLabel);

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
                    
                    // Validate Data Structure
                    const isValid = Array.isArray(importedData) && importedData.every(item => 
                        typeof item === 'object' && item !== null && typeof item.title === 'string'
                    );
                    if (!isValid) {
                        showAlertDialog(t('invalid_data'));
                        return;
                    }

                    if (Array.isArray(importedData)) {
                        showConfirmDialog(t('import_confirm', {count: importedData.length})).then(async res => {
                            if (res) {
                                for (const item of importedData) {
                                    // Sanitize imported data using DOMPurify to prevent XSS
                                    // Note: Password and Secret are NOT sanitized to preserve exact values
                                    if (typeof item.title === 'string') item.title = DOMPurify.sanitize(item.title);
                                    if (typeof item.category === 'string') item.category = DOMPurify.sanitize(item.category);
                                    if (typeof item.website === 'string') item.website = DOMPurify.sanitize(item.website);
                                    if (typeof item.username === 'string') item.username = DOMPurify.sanitize(item.username);

                                    if (item.history && Array.isArray(item.history)) {
                                        item.history.forEach(h => {
                                            if (typeof h.title === 'string') h.title = DOMPurify.sanitize(h.title);
                                            if (typeof h.category === 'string') h.category = DOMPurify.sanitize(h.category);
                                            if (typeof h.website === 'string') h.website = DOMPurify.sanitize(h.website);
                                            if (typeof h.username === 'string') h.username = DOMPurify.sanitize(h.username);
                                        });
                                    }

                                    if (!item.lastModified) item.lastModified = Date.now();
                                    
                                    // Ensure new IDs for imported items if they don't have them or to avoid conflicts
                                    if (!item.id || !currentUser) {
                                        item.id = crypto.randomUUID();
                                    }

                                    if (currentUser) {
                                        await saveOrUpdateItem(item);
                                    } else {
                                        savedPasswords.push(item);
                                    }
                                }
                                if (!currentUser) {
                                    await savePasswordsData();
                                    renderPasswordList(document.getElementById('fld').value);
                                }
                                showAlertDialog(t('import_done'));
                            }
                        });
                    }
                } catch (error) {
                    console.error(error);
                    showAlertDialog(t('file_error'));
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

    // Delete All Data Action
    document.getElementById('delete_all_data_btn')?.addEventListener('click', () => {
        showConfirmDialog(t('delete_all_desc')).then(async (res) => {
            if (res) {
                const mpCheck = await promptForMasterPassword();
                if (!mpCheck) return;

                if (currentUser) {
                    try {
                        const provider = new GoogleAuthProvider();
                        await reauthenticateWithPopup(currentUser, provider);
                        
                        // Delete Cloud Data
                        const qPass = query(collection(db, "passwords"), where("uid", "==", currentUser.uid));
                        const snapPass = await getDocs(qPass);
                        await Promise.all(snapPass.docs.map(d => deleteDoc(d.ref)));

                        const qDev = query(collection(db, "devices"), where("uid", "==", currentUser.uid));
                        const snapDev = await getDocs(qDev);
                        await Promise.all(snapDev.docs.map(d => deleteDoc(d.ref)));

                    } catch (e) {
                        console.error("Re-auth or delete failed", e);
                        showSnackbar(t('error'));
                        return;
                    }
                }
                
                // Local Wipe
                localStorage.clear();
                location.reload();
            }
        });
    });

    // Initialize Auto Logout
    resetAutoLogoutTimer();
    ['mousedown', 'keydown', 'touchstart', 'scroll'].forEach(evt => {
        document.addEventListener(evt, resetAutoLogoutTimer, { passive: true });
    });
    document.addEventListener('visibilitychange', resetAutoLogoutTimer); // Handle tab switching
    document.body.classList.add('loaded');

    // Initialize Language
    const savedLang = localStorage.getItem(CONSTANTS.STORAGE.LANGUAGE);
    
    let browserLang = 'en';
    const navLang = navigator.language || '';
    if (navLang.startsWith('ja')) browserLang = 'ja';
    else if (navLang.startsWith('zh')) browserLang = 'zh';
    else if (navLang.startsWith('ko')) browserLang = 'ko';
    else if (navLang.startsWith('de')) browserLang = 'de';
    else if (navLang.startsWith('fr')) browserLang = 'fr';
    else if (navLang.startsWith('it')) browserLang = 'it';

    updateLanguage(savedLang || browserLang);
    const langSelect = document.getElementById('setting_language');
    if (langSelect) {
        langSelect.value = currentLang;
    }

    // Set App Version
    const versionEl = document.getElementById('setting_app_version');
    if (versionEl) versionEl.textContent = CONSTANTS.APP_VERSION;

    // Load Sidebar Width
    const savedWidth = localStorage.getItem(CONSTANTS.STORAGE.SIDEBAR_WIDTH);
    if (savedWidth && sidebar) {
        sidebar.style.width = savedWidth;
    }

    // Load Theme Color
    const savedColor = localStorage.getItem(CONSTANTS.STORAGE.THEME_COLOR);
    if (savedColor) {
        applyThemeColor(savedColor);
    }

    // Populate Encryption Info
    const encAlgoDataEl = document.getElementById('enc_algo_data');
    if (encAlgoDataEl) encAlgoDataEl.textContent = `${HYBRID_CONFIG.AES_ALGO.name} ${HYBRID_CONFIG.AES_ALGO.length}-bit`;

    const encAlgoKeyEl = document.getElementById('enc_algo_key');
    if (encAlgoKeyEl) encAlgoKeyEl.textContent = `PBKDF2 (SHA-256)`;

    const encIterationsEl = document.getElementById('enc_iterations');
    if (encIterationsEl) encIterationsEl.textContent = CRYPTO_CONFIG.PBKDF2_ITERATIONS.toLocaleString();

    const encHybridEl = document.getElementById('enc_hybrid');
    if (encHybridEl) encHybridEl.textContent = `${HYBRID_CONFIG.RSA_ALGO.name} ${HYBRID_CONFIG.RSA_ALGO.modulusLength}-bit`;

    // Layout handling
    // Icon Picker Initialization
    initIconPicker();

    // New Password Icon Selection
    document.getElementById('open_new_icon_picker_btn')?.addEventListener('click', () => {
        currentIconPickerTarget = 'new';
        document.getElementById('icon_picker_dialog').open = true;
    });

    document.getElementById('upload_new_icon_btn')?.addEventListener('click', () => {
        document.getElementById('new_pass_icon_upload').click();
    });

    document.getElementById('new_pass_icon_upload')?.addEventListener('change', (e) => {
        handleIconUpload(e, 'new');
    });

    // Detail Password Icon Selection
    document.getElementById('open_detail_icon_picker_btn')?.addEventListener('click', () => {
        currentIconPickerTarget = 'detail';
        document.getElementById('icon_picker_dialog').open = true;
    });

    document.getElementById('upload_detail_icon_btn')?.addEventListener('click', () => {
        document.getElementById('detail_pass_icon_upload').click();
    });

    document.getElementById('detail_pass_icon_upload')?.addEventListener('change', (e) => {
        handleIconUpload(e, 'detail');
    });

    document.getElementById('edit_password_btn')?.addEventListener('click', () => {
        setDetailEditMode(true);
    });

    document.getElementById('cancel_edit_btn')?.addEventListener('click', () => {
        const item = savedPasswords.find(p => p.id === currentDetailId);
        if (item) {
            openDetailDialog(item); // Re-populate and exit edit mode
        }
    });

    window.addEventListener('resize', updateLayout);
    updateLayout(); // Initial check
});
