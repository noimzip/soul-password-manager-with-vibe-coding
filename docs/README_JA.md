[English](README.md) | 日本語

# Soul Password Manager

![Status](https://img.shields.io/badge/status-Beta-orange.svg)
![Security](https://img.shields.io/badge/security-E2EE-brightgreen.svg)
![Platform](https://img.shields.io/badge/platform-PWA-blueviolet.svg)

**モダンなWebのための、次世代セキュア・ゼロナレッジ・パスワードマネージャー。**

軍事レベルの暗号化（AES-256-GCM）と次世代認証（Passkeys）を組み合わせ、すべてのデバイスで安全かつシームレスな体験を提供します。

> **[🚀 アプリを起動する](https://noimzip.github.io/soul-password-manager-with-vibe-coding/web/index_ja.html)**

## 機能

### ☁️ クラウド同期 & 認証

- **Googleログイン**: Googleアカウントでサインインして、デバイス間でパスワードを同期します。
- **リアルタイム同期**: データはFirestoreに保存され、開いているセッション間で即座に更新されます。
- **クラウド暗号化**: パスワードはアップロードされる前にクラウド用に暗号化されます。

### 🔒 セキュリティ

- **AES-256暗号化**: すべてのデータは `localStorage` に保存される前に、AES-GCMを使用してローカルで暗号化されます。
- **PBKDF2鍵導出**: マスターパスワードは、一意のソルトを使用したPBKDF2（600,000回の反復）で強化されます。
- **ゼロ知識**: マスターパスワードが平文で保存されることはありません。検証されるのは派生したハッシュのみです。
- **自動ログアウト**: 一定期間操作がない場合、自動的に保管庫をロックします。
- **ログインロックアウト**: パスワードの入力ミスが続いた場合、アカウントを一時的にロックしてブルートフォース攻撃を防ぎます。
- **セッションキー管理**: クラウドモードの暗号化キーは `sessionStorage` に保存され、タブやブラウザを閉じると自動的に破棄されます（共有PCでの安全性向上）。
- **プライバシー保護**: アプリがバックグラウンドに回ると画面にぼかしがかかり、覗き見（ショルダーハッキング）を防ぎます。また、入力フィールドの自動学習やキャッシュは無効化されています。
- **セキュリティアドバイザー（Aura）**: セキュリティアドバイザーが、あなたの保管庫を分析して個別の推奨事項を提供します。Auraに脆弱なパスワード、2FAの状態、またはパスワードの使い回しについて質問して、即座に洞察を得ることができます。
### 🔐 次世代認証 (Passkeys)

- **生体認証ログイン**: **Passkeys (WebAuthn)** のサポートにより、Face ID、Touch ID、またはWindows Helloでのログインが可能です。
- **セキュアな鍵ストレージ**: WebAuthn標準の **`largeBlob`** 拡張機能を利用して、マスターパスワードを認証器内に安全に保存します。これにより、ローカルでのゼロ知識暗号化を維持しながら、シームレスな「パスワードレス」体験が可能になります。
- **フォールバック**: `largeBlob` 非対応デバイスでも、ローカルストレージを用いたフォールバック機能により生体認証を利用可能です（セキュリティレベルは低下します）。

### 🔑 パスワード管理

- **整理**: パスワードをカテゴリ別にグループ化し、重要なアイテムをお気に入りとしてマークします。
- **ドラッグ＆ドロップ**: パスワードリストの順序を簡単に変更できます。
- **履歴追跡**: パスワードエントリの変更履歴を保持し、以前のバージョンを復元できます。
- **検索と並べ替え**: タイトルやウェブサイトでエントリをフィルタリングし、名前、強度、または変更日で並べ替えます。
- **リカバリーキット**: マスターパスワードを忘れた場合に備えて、緊急アクセス用のPDFシートを生成・ダウンロードできます。

### 🛠 ツール

- **パスワード生成**: 長さと文字の種類（大文字、数字、記号）をカスタマイズ可能な、強力でランダムなパスワードを生成します。
- **強度メーター**: パスワードの強度と推定解読時間に関するリアルタイムのフィードバックを提供します。
- **TOTP認証**: 2FAコード（時間ベースのワンタイムパスワード）を生成するための組み込みサポート。
- **漏洩検知**: **Have I Been Pwned** チェックを統合。
  - **プライバシー保護**: _k-Anonymity_ モデルを使用します。パスワードのSHA-1ハッシュの最初の5文字のみがAPIに送信され、完全なハッシュがデバイスから出ることはありません。
- **セキュリティハブ**: 保管庫内の脆弱なパスワード、2FA未設定のアカウント、パスワードの使い回しを分析する総合セキュリティダッシュボード。全体的なセキュリティスコアと実行可能な推奨事項を提供します。
- **セキュリティアドバイザー（Aura）**: 個人的なセキュリティコンサルタントのAuraとチャットして、保管庫のセキュリティに関する即座の回答を得ることができます。「脆弱なパスワードはありますか？」や「どのアカウントに2FAが必要ですか？」などの質問をして、個別化されたコンテキスト対応型のアドバイスを受け取ることができます。

### ⚙️ 設定 & データ

- **インポート/エクスポート**: 保管庫をJSONにバックアップしたり、他のソースからデータをインポートしたりできます。
- **ダークモード**: ライトテーマとダークテーマを切り替えます。
- **デフォルトユーザー名**: エントリ作成を高速化するためにデフォルトのユーザー名を設定します。

## セキュリティアーキテクチャ

### ローカルモード (高セキュリティ)

- **鍵導出**: マスターパスワードは保存されません。暗号化キーは、一意の16バイトのランダムソルトを使用した **PBKDF2** (SHA-256, 100,000回の反復) を使用して導出されます。
- **暗号化**: データは、保存操作ごとにランダムな12バイトのIV（初期化ベクトル）を使用した **AES-GCM** (256ビット) で暗号化されます。
- **ストレージ**: 暗号化されたブロブ (IV + 暗号文) はブラウザの `localStorage` に保存されます。

### クラウドモード (E2EE / ゼロナレッジ)

- **認証**: Firebase Authentication (Google Sign-In) を使用します。
- **ハイブリッド暗号化 (E2EE)**:
  - **データ暗号化**: 各パスワードエントリは、クライアント側で生成されたランダムな **セッションキー (AES-256-GCM)** で暗号化されます。
  - **キーの保護**: セッションキーは、ユーザー固有の **RSA-2048 公開鍵** で暗号化され、データと共に保存されます。
  - **秘密鍵の保護**: RSA秘密鍵は、ユーザーのマスターパスワードから導出された **キー暗号化キー (KEK)** で暗号化され、クラウドに保存されます。
- **ゼロナレッジアーキテクチャ**:
  - **マスターパスワードの秘匿**: マスターパスワードがデバイスの外に出ることはありません。認証や復号はすべてクライアントサイド（ブラウザ内）で行われます。
  - **管理者からの保護**: サーバー（Firebase）には「暗号化されたデータ」と「暗号化された秘密鍵」のみが保存されます。マスターパスワードを知らない限り、開発者やサーバー管理者であってもデータを復号することは数学的に不可能です。
- **通信**: Firebaseへのすべてのデータ転送はHTTPS/TLS経由で保護されています。

## 正直な話：現在の課題と制約

Soulは発展途上のプロジェクトです。透明性を保つため、現在抱えている技術的な制約や依存について包み隠さず公開します。

- **Googleインフラへの依存**: バックエンド（認証・DB）にGoogle Firebaseを使用しています。データの中身はE2EEで保護されGoogleも閲覧できませんが、サービスの稼働はGoogleのインフラに依存しています。
- **ネイティブ統合の限界**: Web技術（PWA）ベースで構築されています。完全な自動入力機能のために、ログインフォームへのパスワード自動入力を可能にするブラウザ拡張機能（Chrome/Edge/Firefox）を提供しています。
- **開発段階（ベータ）**: 現在は「Unstable（不安定）」なバージョンです。機能の追加や変更が頻繁に行われる可能性があり、商用製品のような長期的な安定サポートは保証されていません。

## ブラウザ拡張機能

Soul Password Managerは、シームレスなパスワード自動入力機能を提供するChrome、Edge、Firefox向けのブラウザ拡張機能を提供しています。

### 機能

- 🔍 **フォーム自動検出**: ログインフォームを自動的に検出
- 🔑 **ワンクリック入力**: パスワードフィールドのSoulアイコンをクリックして認証情報を入力
- 🎯 **スマートマッチング**: 現在のURLに基づいて関連するパスワードを自動提案
- 💾 **オフラインキャッシュ**: 高速アクセスのためにパスワードリストをキャッシュ
- 🔒 **セキュア通信**: Soul PWAとの安全な通信

### インストール

1. **Chrome / Edge**: 
   - `chrome://extensions/` を開く
   - 「デベロッパーモード」をONにする
   - 「パッケージ化されていない拡張機能を読み込む」をクリック
   - `extension` フォルダを選択

2. **Firefox**:
   - `about:debugging#/runtime/this-firefox` を開く
   - 「一時的なアドオンを読み込む」をクリック
   - `extension` フォルダ内の `manifest.json` を選択

詳細な手順については、[extension/README.md](../extension/README.md)を参照してください。

## 技術概要

アプリケーションは、暗号化操作にはブラウザネイティブの `window.crypto.subtle` APIを、クラウド機能にはFirebaseを使用しています。

- **ストレージキー**:
  - `soul_passwords`: 暗号化された保管庫データ。
  - `soul_master_auth`: マスターパスワード検証用のソルトとハッシュ。
  - `soul_theme`: ユーザーインターフェースのテーマ設定。
  - **Firestore**: ログイン時に暗号化されたパスワードエントリを保存するために使用されます。
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

- Node.js (v16以上)
- npm または yarn
- Firebase プロジェクト (クラウド同期機能用)

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

## ブラウザサポート

このアプリケーションは最新のWeb標準を使用しています。

- **基本機能**: Chrome, Edge, Firefox, Safari (最新版)。
- **Passkey (largeBlob)**:
  - macOS (Touch ID) および Windows (Hello) 上の Chrome / Edge。
  - _注意_: `largeBlob` 拡張機能のサポート状況は、プラットフォームやブラウザの実装に依存します。

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

- **Firebase SDK**: 認証、Firestore。
- **@m3e/components**: UI用のカスタムMaterial Design 3 Webコンポーネント。
- **zxcvbn**: 現実的なパスワード強度推定のため。
- **otpauth**: TOTP (2FA) コード生成のため。
- **DOMPurify**: XSS攻撃を防ぐためにインポートされたデータをサニタイズするため。
