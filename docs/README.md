**English** | [日本語](README_JA.md)

# Soul Password Manager

A secure password manager built with modern JavaScript, Web Crypto API, Firebase, and Vite. It features strong encryption, cloud synchronization, a built-in password generator, and TOTP support.

[**Visit Introduction Site**](https://noimzip.github.io/soul-password-manager-with-vibe-coding/web/index.html)

## Features

### ☁️ Cloud Sync & Auth
*   **Google Login**: Sign in with your Google account to sync passwords across devices.
*   **Real-time Sync**: Data is stored in Firestore and updates instantly across open sessions.
*   **Cloud Encryption**: Passwords stored in the cloud are encrypted before upload.

### 🔒 Security
*   **AES-256 Encryption**: All data is encrypted locally using AES-GCM before being saved to `localStorage`.
*   **PBKDF2 Key Derivation**: The master password is strengthened using PBKDF2 (600,000 iterations) with a unique salt.
*   **Zero Knowledge**: The master password is never stored in plain text; only the derived hash is verified.
*   **Auto-Logout**: Automatically locks the vault after a configurable period of inactivity.
*   **Login Lockout**: Temporarily locks the account after consecutive failed login attempts to prevent brute-force attacks.
*   **Session Key Management**: Cloud encryption keys are stored in `sessionStorage` and are automatically discarded when the tab or browser is closed (improving security on shared PCs).
*   **Privacy Protection**: The screen blurs when the app goes to the background to prevent shoulder surfing. Auto-learning and caching for input fields are disabled.

### 🔐 Next-Gen Authentication (Passkeys)
*   **Biometric Login**: Support for **Passkeys (WebAuthn)** allows logging in with Face ID, Touch ID, or Windows Hello.
*   **Secure Key Storage**: Utilizes the **`largeBlob`** extension of the WebAuthn standard to store the master password safely within the authenticator. This allows for a seamless "passwordless" experience while maintaining zero-knowledge encryption locally.
*   **Fallback Support**: Includes a fallback mechanism using local storage for devices that do not support `largeBlob` (with reduced security).

###  Password Management
*   **Organization**: Group passwords by categories and mark important items as favorites.
*   **Drag & Drop**: Reorder your password list easily.
*   **History Tracking**: Keeps a revision history of password entries, allowing you to restore previous versions.
*   **Search & Sort**: Filter entries by title or website, and sort by name, strength, or modification date.
*   **Recovery Kit**: Generate and download an emergency access PDF sheet in case you forget your master password.

### 🛠 Tools
*   **Password Generator**: Generate strong, random passwords with customizable length and character types (uppercase, numbers, symbols).
*   **Strength Meter**: Real-time feedback on password strength and estimated crack time.
*   **TOTP Authenticator**: Built-in support for generating 2FA codes (Time-based One-Time Passwords).
*   **Breach Detection**: Integrated **Have I Been Pwned** check.
    *   **Privacy-Preserving**: Uses *k-Anonymity* model. Only the first 5 characters of the password's SHA-1 hash are sent to the API; the full hash never leaves your device.

### ⚙️ Settings & Data
*   **Import/Export**: Backup your vault to JSON or import data from other sources.
*   **Dark Mode**: Toggle between light and dark themes.
*   **Default Username**: Configure a default username to speed up entry creation.

## Security Architecture

### Local Mode (High Security)
*   **Key Derivation**: The master password is never stored. An encryption key is derived using **PBKDF2** (SHA-256, 100,000 iterations) with a unique 16-byte random salt.
*   **Encryption**: Data is encrypted using **AES-GCM** (256-bit) with a random 12-byte IV (Initialization Vector) for each save operation.
*   **Storage**: The encrypted blob (IV + Ciphertext) is stored in the browser's `localStorage`.

### Cloud Mode (E2EE / Zero-Knowledge)
*   **Authentication**: Uses Firebase Authentication (Google Sign-In).
*   **Hybrid Encryption (E2EE)**:
    *   **Data Encryption**: Each password entry is encrypted client-side using a random **Session Key (AES-256-GCM)**.
    *   **Key Protection**: The Session Key is encrypted using the user's unique **RSA-2048 Public Key** and stored with the data.
    *   **Private Key Protection**: The RSA Private Key is encrypted using a **Key Encryption Key (KEK)** derived from the user's Master Password and stored in the cloud.
*   **Zero-Knowledge Architecture**:
    *   **Master Password Privacy**: The Master Password never leaves your device. Authentication and decryption occur entirely client-side (in the browser).
    *   **Protection from Admins**: The server (Firebase) stores only "encrypted data" and the "encrypted private key". Without the Master Password, it is mathematically impossible for developers or server administrators to decrypt your data.
*   **Transport**: All data transfer to Firebase is secured via HTTPS/TLS.

## Current Limitations
Soul is a developing project. For transparency, we openly disclose current technical limitations and dependencies.

*   **Dependency on Google Infrastructure**: Uses Google Firebase for backend (Auth/DB). While data is E2EE protected and unreadable by Google, service availability depends on Google's infrastructure.
*   **Native Integration Limits**: Built on Web technologies (PWA), it currently does not support system-level autofill (e.g., keyboard password suggestions) on iOS or Android.
*   **Development Stage (Beta)**: Currently an "Unstable" version. Frequent feature additions or changes may occur, and long-term stable support like commercial products is not guaranteed.

## Technical Overview

The application relies on the browser's native `window.crypto.subtle` API for cryptographic operations and Firebase for cloud features.

*   **Storage Keys**:
    *   `soul_passwords`: Encrypted vault data.
    *   `soul_master_auth`: Salt and hash for master password verification.
    *   `soul_theme`: User interface theme preference.
    *   **Firestore**: Used for storing encrypted password entries when logged in.

### Data Structure (Firestore)

```json
{
  "uid": "user_id_string",
  "title": "Service Name",
  "username": "user@example.com",
  "password": "BASE64_ENCRYPTED_STRING",
  "website": "https://example.com",
  "category": "Social",
  "favorite": boolean,
  "secret": "TOTP_SECRET",
  "lastModified": timestamp
}
```

## Usage

1.  **Initial Setup**: When launching for the first time, you can choose to login with Google for cloud sync or create a Master Password for local storage.
2.  **Adding Passwords**: Use the interface to add credentials. You can generate a secure password and add a TOTP secret if applicable.
3.  **Management**: Click on an item to view details, copy the password/username to clipboard, or edit the entry.
4.  **Data Backup**: Use the "Data Management" section in settings to export your encrypted vault as a JSON file.

## Getting Started

### Prerequisites
*   Node.js (v16 or higher)
*   npm or yarn
*   A Firebase project (for cloud sync features)

### Installation

1.  **Clone the repository**
    ```bash
    git clone https://github.com/yourusername/soul-password-manager.git
    cd soul-password-manager
    ```

2.  **Install dependencies**
    ```bash
    npm install
    ```

3.  **Configuration**
    Create a `.env.local` file in the root directory (`www/`) and add your Firebase configuration keys.

    ```env
    VITE_FIREBASE_APIKEY=your_api_key
    VITE_FIREBASE_AUTHDOMAIN=your_project.firebaseapp.com
    VITE_FIREBASE_PROJECTID=your_project_id
    VITE_FIREBASE_STORAGEBUCKET=your_project.appspot.com
    VITE_FIREBASE_MESSAGINGSENDERID=your_sender_id
    VITE_FIREBASE_APPID=your_app_id
    ```

4.  **Run Development Server**
    ```bash
    npm run dev
    ```

## Firebase Security Rules

To secure your data in Firestore, apply the following security rules in your Firebase Console (Firestore Database > Rules).

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    
    match /passwords/{docId} {
      allow create: if request.auth != null && request.resource.data.uid == request.auth.uid;
      allow read, update, delete: if request.auth != null && resource.data.uid == request.auth.uid;
    }
    
    match /devices/{docId} {
      allow create: if request.auth != null && request.resource.data.uid == request.auth.uid;
      allow read, update, delete: if request.auth != null && resource.data.uid == request.auth.uid;
    }

    match /feedback/{docId} {
      allow create: if true;
    }

    match /user_config/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
```

## Browser Support

This application uses modern web standards.

*   **Core Features**: Chrome, Edge, Firefox, Safari (Latest versions).
*   **Passkey (largeBlob)**:
    *   Chrome / Edge on macOS (Touch ID) and Windows (Hello).
    *   *Note*: Support for `largeBlob` extension varies by platform and browser implementation.

## Directory Structure

```text
www/
├── css/
│   └── style.css       # Application styles
├── docs/
│   ├── README.md       # English Documentation
│   └── README_JA.md    # Japanese Documentation
├── js/
│   └── script.js       # Main application logic (Firebase, Crypto, UI)
├── web/                # Landing Page
│   ├── index.html
│   └── style.css
├── node_modules/       # Third-party libraries (@m3e components)
├── index.html          # Main entry point
├── package.json        # Project dependencies and scripts
└── vite.config.js      # Vite configuration
```

## Dependencies

The application relies on the following key libraries:

*   **Firebase SDK**: Authentication and Firestore.
*   **@m3e/components**: Custom Material Design 3 web components for the UI.
*   **zxcvbn**: For realistic password strength estimation.
*   **otpauth**: For TOTP (2FA) code generation.
*   **DOMPurify**: For sanitizing imported data to prevent XSS attacks.