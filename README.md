# Soul Password Manager

A secure, client-side password manager built with modern JavaScript and the Web Crypto API. It features strong encryption, a built-in password generator, and TOTP support.

## Features

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

## Technical Overview

The application relies on the browser's native `window.crypto.subtle` API for cryptographic operations.

*   **Storage Keys**:
    *   `soul_passwords`: Encrypted vault data.
    *   `soul_master_auth`: Salt and hash for master password verification.
    *   `soul_theme`: User interface theme preference.

## Usage

1.  **Initial Setup**: When launching for the first time, you will be prompted to create a Master Password.
2.  **Adding Passwords**: Use the interface to add credentials. You can generate a secure password and add a TOTP secret if applicable.
3.  **Management**: Click on an item to view details, copy the password/username to clipboard, or edit the entry.
4.  **Data Backup**: Use the "Data Management" section in settings to export your encrypted vault as a JSON file.

## Dependencies

The application code references custom elements (e.g., `m3e-dialog`, `m3e-icon`), suggesting usage of a Material Design web component library.