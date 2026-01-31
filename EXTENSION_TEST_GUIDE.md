# Soul拡張機能 - 通信テストガイド

## 修正内容

拡張機能とSoul PWA間の通信方法を以下のように修正しました：

### 変更点

1. **manifest.json**
   - `tabs` 権限を追加（PWAタブを検索するため）

2. **popup.js**
   - `fetch` APIから `chrome.tabs.sendMessage` に変更
   - PWAが開いているタブを検索
   - 見つかったタブにメッセージを直接送信
   - パスワード入力時に実際のパスワードをPWAから取得

3. **script.js (PWA側)**
   - `chrome.runtime.onMessage` リスナーを追加
   - 拡張機能からのメッセージを直接受信できるように

## テスト手順

### 1. 拡張機能の再読み込み

```bash
# Chromeで以下を開く
chrome://extensions/

# Soul Password Manager拡張機能の「更新」ボタンをクリック
```

### 2. Soul PWAを開く

```bash
# ターミナルで開発サーバーを起動
npm run dev

# または本番環境
https://noimzip.github.io/soul-password-manager-with-vibe-coding/
```

### 3. Soul PWAにログイン

1. マスターパスワードでログイン
2. パスワードが表示されることを確認
3. **このタブは開いたままにする**（重要！）

### 4. テストサイトでパスワード入力をテスト

例：https://www.google.com/accounts

1. Googleのログインページを開く
2. パスワードフィールドに🔑アイコンが表示されることを確認
3. 🔑アイコンをクリック
4. ポップアップが開き、パスワードリストが表示されることを確認
5. パスワードを選択
6. フォームに自動入力されることを確認

## デバッグ方法

### 拡張機能のログを確認

#### Content Script（ページ内）
```
1. テストページ（例：Google）でF12を押す
2. Console タブを開く
3. [Soul AutoFill] で始まるログを探す
```

期待されるログ：
```
[Soul AutoFill] Content script loaded
[Soul AutoFill] Monitoring for login forms
```

#### Popup
```
1. 拡張機能アイコンを右クリック
2. 「検証」または「Inspect」をクリック
3. Console タブを確認
```

期待されるログ：
```
[Soul AutoFill] Popup opened
[Soul AutoFill] Found PWA tab: <tab-id>
[Soul AutoFill] Connected to PWA, loaded X passwords
```

#### Background Script
```
1. chrome://extensions/ を開く
2. Soul Password Manager の「Service Worker」リンクをクリック
3. Console タブを確認
```

### PWA側のログを確認

```
1. Soul PWAのタブでF12を押す
2. Console タブを確認
```

期待されるログ：
```
[Soul PWA] Received message from extension: {action: "soul-get-passwords", ...}
```

## トラブルシューティング

### ポップアップに「Unable to connect」と表示される

**原因**: Soul PWAが開いていない、またはログインしていない

**解決策**:
1. Soul PWAを開く
2. ログインする
3. 拡張機能ポップアップの「Refresh」をクリック

### パスワードリストが空

**原因**: 通信は成功しているが、パスワードが保存されていない

**解決策**:
1. Soul PWAでパスワードを追加
2. 拡張機能ポップアップの「Refresh」をクリック

### 🔑アイコンが表示されない

**原因**: Content scriptが読み込まれていない、またはフォームが検出されていない

**解決策**:
1. ページを再読み込み
2. パスワードフィールドがあることを確認
3. F12 → Consoleで `[Soul AutoFill]` ログを確認

### 「Extension context invalidated」エラー

**原因**: 拡張機能が再読み込みされたが、ページがリロードされていない

**解決策**:
1. 表示された「Reload Page」ボタンをクリック
2. またはページを手動で再読み込み

## 通信フロー

```
┌─────────────────┐
│  Webページ      │
│  (パスワード    │
│   フィールド)    │
└────────┬────────┘
         │ 1. フォーム検出
         │
┌────────▼────────┐
│ Content Script  │
│ (content.js)    │
└────────┬────────┘
         │ 2. ユーザーがアイコンクリック
         │
┌────────▼────────┐
│ Background      │
│ (background.js) │
└────────┬────────┘
         │ 3. ポップアップ表示
         │
┌────────▼────────┐
│ Popup           │◄──┐
│ (popup.js)      │   │ 5. パスワードリスト返信
└────────┬────────┘   │
         │ 4. パスワードリクエスト
         │ (chrome.tabs.sendMessage)
         │             │
┌────────▼────────────▼┐
│ Soul PWA            │
│ (script.js)         │
│ chrome.runtime.     │
│ onMessage           │
└─────────────────────┘
         │ 6. ユーザーが選択
         │
         ▼
     自動入力
```

## よくある質問

### Q: PWAを閉じても動作しますか？

A: 部分的に動作します。一度接続すればパスワードリストはキャッシュされますが、実際のパスワード（パスワードフィールドの値）を取得する際はPWAが開いている必要があります。

### Q: 複数のタブでPWAを開いても大丈夫？

A: はい、拡張機能は最初に見つかったPWAタブと通信します。

### Q: 本番環境と開発環境を同時に開いても大丈夫？

A: はい、拡張機能は両方のURLをサポートしています。最初に見つかった方と通信します。

## 成功の確認

すべてが正しく動作している場合：

✅ Soul PWAでログインできる
✅ テストページで🔑アイコンが表示される
✅ アイコンクリックでポップアップが開く
✅ ポップアップにパスワードリストが表示される
✅ パスワード選択でフォームに自動入力される
✅ コンソールにエラーがない

## 次のステップ

動作が確認できたら：

1. 実際の使用サイト（Gmail、Twitter、GitHubなど）でテスト
2. パスワードの追加・更新が拡張機能に反映されるか確認
3. 異なるブラウザ（Firefox、Edge）でテスト
