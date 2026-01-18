# Soul Password Manager

A secure password manager built with modern JavaScript, Web Crypto API, and Firebase. It features strong encryption, cloud synchronization, a built-in password generator, and TOTP support.

## Features

### ☁️ Cloud Sync & Auth
*   **Google Login**: Sign in with your Google account to sync passwords across devices.
*   **Real-time Sync**: Data is stored in Firestore and updates instantly across open sessions.
*   **Cloud Encryption**: Passwords stored in the cloud are encrypted before upload.

### 🔒 Security
*   **AES-256 Encryption**: All data is encrypted locally using AES-GCM before being saved to `localStorage`.
*   **PBKDF2 Key Derivation**: The master password is strengthened using PBKDF2 (100,000 iterations) with a unique salt.
*   **Zero Knowledge**: The master password is never stored in plain text; only the derived hash is verified.
*   **Auto-Logout**: Automatically locks the vault after a configurable period of inactivity.

### 🔑 Password Management
*   **Organization**: Group passwords by categories and mark important items as favorites.
*   **Drag & Drop**: Reorder your password list easily.
*   **History Tracking**: Keeps a revision history of password entries, allowing you to restore previous versions.
*   **Search & Sort**: Filter entries by title or website, and sort by name, strength, or modification date.

### 🛠 Tools
*   **Password Generator**: Generate strong, random passwords with customizable length and character types (uppercase, numbers, symbols).
*   **Strength Meter**: Real-time feedback on password strength and estimated crack time.
*   **TOTP Authenticator**: Built-in support for generating 2FA codes (Time-based One-Time Passwords).

### ⚙️ Settings & Data
*   **Import/Export**: Backup your vault to JSON or import data from other sources.
*   **Dark Mode**: Toggle between light and dark themes.
*   **Default Username**: Configure a default username to speed up entry creation.

## Security Architecture

### Local Mode (High Security)
*   **Key Derivation**: The master password is never stored. An encryption key is derived using **PBKDF2** (SHA-256, 100,000 iterations) with a unique 16-byte random salt.
*   **Encryption**: Data is encrypted using **AES-GCM** (256-bit) with a random 12-byte IV (Initialization Vector) for each save operation.
*   **Storage**: The encrypted blob (IV + Ciphertext) is stored in the browser's `localStorage`.

### Cloud Mode (Demo Implementation)
*   **Authentication**: Uses Firebase Authentication (Google Sign-In).
*   **Encryption**: Client-side encryption is performed using **AES-GCM** before data is sent to Firestore.
    *   *Note*: For this demo version, a fixed application-level key is used for cloud sync to simplify multi-device key exchange. For a production environment, a user-derived key or public-key cryptography (ECDH) should be implemented.
*   **Transport**: All data transfer to Firebase is secured via HTTPS/TLS.

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

## Directory Structure

```text
www/
├── css/
│   └── style.css       # Application styles
├── js/
│   └── script.js       # Main application logic (Firebase, Crypto, UI)
├── node_modules/       # Third-party libraries (@m3e components)
├── index.html          # Main entry point
├── package.json        # Project dependencies and scripts
└── README.md           # Project documentation
```

## Dependencies

The application uses Firebase SDKs (Auth, Firestore, Analytics) via CDN and custom elements (e.g., `m3e-dialog`, `m3e-icon`) from a Material Design web component library.