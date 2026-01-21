[English](README.md) | 日本語

# Soul Password Manager

モダンなJavaScript、Web Crypto API、Firebase、Viteで構築されたセキュアなパスワードマネージャーです。強力な暗号化、クラウド同期、組み込みのパスワード生成機能、TOTPサポートを備えています。

## 機能

### ☁️ クラウド同期 & 認証
*   **Googleログイン**: Googleアカウントでサインインして、デバイス間でパスワードを同期します。
*   **リアルタイム同期**: データはFirestoreに保存され、開いているセッション間で即座に更新されます。
*   **クラウド暗号化**: パスワードはアップロードされる前にクラウド用に暗号化されます。

### 🔒 セキュリティ
*   **AES-256暗号化**: すべてのデータは `localStorage` に保存される前に、AES-GCMを使用してローカルで暗号化されます。
*   **PBKDF2鍵導出**: マスターパスワードは、一意のソルトを使用したPBKDF2（100,000回の反復）で強化されます。
*   **ゼロ知識**: マスターパスワードが平文で保存されることはありません。検証されるのは派生したハッシュのみです。
*   **自動ログアウト**: 一定期間操作がない場合、自動的に保管庫をロックします。

### 🔐 次世代認証 (Passkeys)
*   **生体認証ログイン**: **Passkeys (WebAuthn)** のサポートにより、Face ID、Touch ID、またはWindows Helloでのログインが可能です。
*   **セキュアな鍵ストレージ**: WebAuthn標準の **`largeBlob`** 拡張機能を利用して、マスターパスワードを認証器内に安全に保存します。これにより、ローカルでのゼロ知識暗号化を維持しながら、シームレスな「パスワードレス」体験が可能になります。

### 🔑 パスワード管理
*   **整理**: パスワードをカテゴリ別にグループ化し、重要なアイテムをお気に入りとしてマークします。
*   **ドラッグ＆ドロップ**: パスワードリストの順序を簡単に変更できます。
*   **履歴追跡**: パスワードエントリの変更履歴を保持し、以前のバージョンを復元できます。
*   **検索と並べ替え**: タイトルやウェブサイトでエントリをフィルタリングし、名前、強度、または変更日で並べ替えます。

### 🛠 ツール
*   **パスワード生成**: 長さと文字の種類（大文字、数字、記号）をカスタマイズ可能な、強力でランダムなパスワードを生成します。
*   **強度メーター**: パスワードの強度と推定解読時間に関するリアルタイムのフィードバックを提供します。
*   **TOTP認証**: 2FAコード（時間ベースのワンタイムパスワード）を生成するための組み込みサポート。
*   **漏洩検知**: **Have I Been Pwned** チェックを統合。
    *   **プライバシー保護**: *k-Anonymity* モデルを使用します。パスワードのSHA-1ハッシュの最初の5文字のみがAPIに送信され、完全なハッシュがデバイスから出ることはありません。

### ⚙️ 設定 & データ
*   **インポート/エクスポート**: 保管庫をJSONにバックアップしたり、他のソースからデータをインポートしたりできます。
*   **ダークモード**: ライトテーマとダークテーマを切り替えます。
*   **デフォルトユーザー名**: エントリ作成を高速化するためにデフォルトのユーザー名を設定します。

## セキュリティアーキテクチャ

### ローカルモード (高セキュリティ)
*   **鍵導出**: マスターパスワードは保存されません。暗号化キーは、一意の16バイトのランダムソルトを使用した **PBKDF2** (SHA-256, 100,000回の反復) を使用して導出されます。
*   **暗号化**: データは、保存操作ごとにランダムな12バイトのIV（初期化ベクトル）を使用した **AES-GCM** (256ビット) で暗号化されます。
*   **ストレージ**: 暗号化されたブロブ (IV + 暗号文) はブラウザの `localStorage` に保存されます。

### クラウドモード (デモ実装)
*   **認証**: Firebase Authentication (Google Sign-In) を使用します。
*   **暗号化**: データがFirestoreに送信される前に、クライアント側の暗号化が **AES-GCM** を使用して実行されます。
    *   *注*: このデモバージョンでは、複数デバイス間の鍵交換を簡素化するために、クラウド同期には固定のアプリケーションレベルのキーが使用されています。本番環境では、ユーザー派生キーまたは公開鍵暗号 (ECDH) を実装する必要があります。
*   **通信**: Firebaseへのすべてのデータ転送はHTTPS/TLS経由で保護されています。

## 技術概要

アプリケーションは、暗号化操作にはブラウザネイティブの `window.crypto.subtle` APIを、クラウド機能にはFirebaseを使用しています。

*   **ストレージキー**:
    *   `soul_passwords`: 暗号化された保管庫データ。
    *   `soul_master_auth`: マスターパスワード検証用のソルトとハッシュ。
    *   `soul_theme`: ユーザーインターフェースのテーマ設定。
    *   **Firestore**: ログイン時に暗号化されたパスワードエントリを保存するために使用されます。

### データ構造 (Firestore)

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

## 使用方法

1.  **初期設定**: 初回起動時に、クラウド同期のためにGoogleでログインするか、ローカルストレージ用にマスターパスワードを作成するかを選択できます。
2.  **パスワードの追加**: インターフェースを使用して認証情報を追加します。安全なパスワードを生成し、必要に応じてTOTPシークレットを追加できます。
3.  **管理**: アイテムをクリックして詳細を表示し、パスワード/ユーザー名をクリップボードにコピーしたり、エントリを編集したりします。
4.  **データバックアップ**: 設定の「データ管理」セクションを使用して、暗号化された保管庫をJSONファイルとしてエクスポートします。

## 開発を始める

### 前提条件
*   Node.js (v16以上)
*   npm または yarn
*   Firebase プロジェクト (クラウド同期機能用)

### インストール手順

1.  **リポジトリのクローン**
    ```bash
    git clone https://github.com/yourusername/soul-password-manager.git
    cd soul-password-manager
    ```

2.  **依存関係のインストール**
    ```bash
    npm install
    ```

3.  **設定 (Configuration)**
    ルートディレクトリ (`www/`) に `.env.local` ファイルを作成し、Firebaseの設定キーを追加してください。

    ```env
    VITE_FIREBASE_APIKEY=your_api_key
    VITE_FIREBASE_AUTHDOMAIN=your_project.firebaseapp.com
    VITE_FIREBASE_PROJECTID=your_project_id
    VITE_FIREBASE_STORAGEBUCKET=your_project.appspot.com
    VITE_FIREBASE_MESSAGINGSENDERID=your_sender_id
    VITE_FIREBASE_APPID=your_app_id
    ```

4.  **開発サーバーの起動**
    ```bash
    npm run dev
    ```

## Firebase セキュリティルール

Firestoreのデータを保護するために、Firebaseコンソール（Firestore Database > ルール）で以下のセキュリティルールを適用してください。

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

## ブラウザサポート

このアプリケーションは最新のWeb標準を使用しています。

*   **基本機能**: Chrome, Edge, Firefox, Safari (最新版)。
*   **Passkey (largeBlob)**:
    *   macOS (Touch ID) および Windows (Hello) 上の Chrome / Edge。
    *   *注意*: `largeBlob` 拡張機能のサポート状況は、プラットフォームやブラウザの実装に依存します。

## ディレクトリ構造

```text
www/
├── css/
│   └── style.css       # アプリケーションスタイル
├── docs/
│   ├── README.md       # 英語ドキュメント
│   └── README_JA.md    # 日本語ドキュメント
├── js/
│   └── script.js       # メインアプリケーションロジック (Firebase, Crypto, UI)
├── web/                # ランディングページ
│   ├── index.html
│   └── style.css
├── node_modules/       # サードパーティライブラリ (@m3e components)
├── index.html          # メインエントリポイント
├── package.json        # プロジェクトの依存関係とスクリプト
└── vite.config.js      # Vite設定
```

## 依存関係

アプリケーションは以下の主要なライブラリに依存しています：

*   **Firebase SDK**: 認証、Firestore。
*   **@m3e/components**: UI用のカスタムMaterial Design 3 Webコンポーネント。
*   **zxcvbn**: 現実的なパスワード強度推定のため。
*   **otpauth**: TOTP (2FA) コード生成のため。
*   **DOMPurify**: XSS攻撃を防ぐためにインポートされたデータをサニタイズするため。
