**English** | [日本語](README_JA.md)

# Soul Password Manager

A secure password manager built with modern JavaScript, Web Crypto API, Firebase, and Vite. It features strong encryption, cloud synchronization, a built-in password generator, and TOTP support.

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

### 🔐 Next-Gen Authentication (Passkeys)
*   **Biometric Login**: Support for **Passkeys (WebAuthn)** allows logging in with Face ID, Touch ID, or Windows Hello.
*   **Secure Key Storage**: Utilizes the **`largeBlob`** extension of the WebAuthn standard to store the master password safely within the authenticator. This allows for a seamless "passwordless" experience while maintaining zero-knowledge encryption locally.

###  Password Management
*   **Organization**: Group passwords by categories and mark important items as favorites.
*   **Drag & Drop**: Reorder your password list easily.
*   **History Tracking**: Keeps a revision history of password entries, allowing you to restore previous versions.
*   **Search & Sort**: Filter entries by title or website, and sort by name, strength, or modification date.

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
    match /passwords/{document} {
      allow create: if request.auth != null && request.resource.data.uid == request.auth.uid;
      allow read, update, delete: if request.auth != null && resource.data.uid == request.auth.uid;
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