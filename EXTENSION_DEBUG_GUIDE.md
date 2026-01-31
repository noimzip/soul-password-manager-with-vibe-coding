# Soul拡張機能 - パスワードが表示されない問題の診断ガイド

## 🔍 診断手順

### ステップ1: デバッグツールを開く

拡張機能フォルダ内の `debug.html` をChromeで開いてください：

```
file:///path/to/extension/debug.html
```

または、拡張機能の管理画面から：
1. `chrome://extensions/` を開く
2. Soul Password Managerの詳細を表示
3. 拡張機能ビューで `chrome-extension://[YOUR-EXTENSION-ID]/debug.html` を開く

### ステップ2: 各テストを実行

#### 1. PWA接続テスト
- 「PWA接続をテスト」ボタンをクリック
- ✅ PWAタブが見つかる → 次へ
- ❌ PWAタブが見つからない → **解決策A**へ

#### 2. パスワード取得テスト
- 「パスワード取得」ボタンをクリック
- ✅ パスワードが取得できる → **問題は解決！**
- ❌ エラーが表示される → **解決策B**へ

#### 3. ログの確認
- 下部の「コンソールログ」セクションを確認
- `[Soul PWA Bridge]` や `[Soul PWA]` のログを探す

---

## 🔧 解決策

### 解決策A: PWAタブが見つからない

**原因**: Soul PWAが開いていないか、正しくないURLで開いている

**手順**:
1. Soul PWAを開く
   - 開発環境: `http://localhost:5173/`
   - 本番環境: `https://noimzip.github.io/soul-password-manager-with-vibe-coding/`

2. ログインする
   - マスターパスワードでログイン
   - パスワードリストが表示されることを確認

3. **このタブを開いたまま**にする

4. 再度「PWA接続をテスト」をクリック

### 解決策B: パスワード取得でエラー

**よくあるエラーと対処法**:

#### エラー1: "Not logged in"
```
原因: PWAでログインしていない
対処: PWAタブでログインする
```

#### エラー2: "Extension context invalidated"
```
原因: 拡張機能が再読み込みされた
対処: PWAタブをリロード（F5）する
```

#### エラー3: "Could not establish connection"
```
原因: pwa-bridge.jsが読み込まれていない
対処: 
1. 拡張機能を再読み込み
2. PWAタブをリロード
3. 再度テスト
```

#### エラー4: "Timeout waiting for PWA response"
```
原因: PWAがメッセージに応答していない
対処:
1. PWAタブのコンソール（F12）を開く
2. 以下のログを確認:
   - [Soul PWA Bridge] Bridge script loaded ← これがあるか？
   - [Soul PWA] Received extension request ← これがあるか？
3. ログがない場合は**解決策C**へ
```

### 解決策C: PWA側でメッセージを受信していない

**手順1**: PWAのコンソールで確認

PWAタブでF12を開き、以下を実行：

```javascript
// 1. Bridge scriptが読み込まれているか確認
console.log('Bridge loaded:', typeof chrome !== 'undefined' && chrome.runtime);

// 2. 手動でテスト
window.postMessage({
  type: 'soul-extension-request',
  action: 'soul-get-passwords',
  source: 'manual-test'
}, '*');

// 3. レスポンスを確認（数秒待つ）
// [Soul PWA] Received extension request というログが出るはず
```

**手順2**: script.jsが最新か確認

PWAのコンソールで：

```javascript
// savedPasswordsが存在するか確認
console.log('Passwords count:', savedPasswords ? savedPasswords.length : 'undefined');

// getPasswordsForExtensionが存在するか確認
console.log('Function exists:', typeof getPasswordsForExtension);
```

**手順3**: ブラウザキャッシュをクリア

1. PWAタブでF12を開く
2. Network タブを開く
3. 「Disable cache」にチェック
4. ページをリロード（Ctrl+Shift+R / Cmd+Shift+R）
5. 拡張機能も再読み込み

---

## 📊 期待されるログの流れ

### 正常な場合のログ:

**1. PWAタブのコンソール（F12）:**
```
[Soul PWA Bridge] Bridge script loaded
[Soul PWA Bridge] Bridge ready
↓ ポップアップ開く
[Soul PWA Bridge] Received from extension: {action: "soul-get-passwords"}
[Soul PWA] Received extension request: {type: "soul-extension-request", action: "soul-get-passwords"}
[Soul PWA] getPasswordsForExtension called
[Soul PWA] appKey: true cloudKey: false
[Soul PWA] savedPasswords count: 5
[Soul PWA] Returning 5 passwords to extension
[Soul PWA] Sending response back to bridge: {passwords: Array(5), count: 5}
[Soul PWA Bridge] Received response from PWA: {type: "soul-extension-response", data: {...}}
```

**2. 拡張機能ポップアップのコンソール（右クリック→検証）:**
```
[Soul AutoFill] Popup opened
[Soul AutoFill] Attempting to connect to PWA...
[Soul AutoFill] Total tabs found: 10
[Soul AutoFill] Found PWA tab: 123 http://localhost:5173/
[Soul AutoFill] Sending message to PWA tab...
[Soul AutoFill] Received response: {passwords: Array(5), count: 5}
[Soul AutoFill] Connected to PWA, loaded 5 passwords
```

---

## 🐛 まだ解決しない場合

### 完全リセット手順:

1. **拡張機能を削除**
   ```
   chrome://extensions/ → Soul Password Manager → 削除
   ```

2. **キャッシュをクリア**
   - PWAタブを閉じる
   - Chromeの設定 → プライバシーとセキュリティ → 閲覧履歴データの削除
   - 「キャッシュされた画像とファイル」をチェック
   - 「データを削除」

3. **拡張機能を再インストール**
   ```
   chrome://extensions/ → デベロッパーモード ON
   → パッケージ化されていない拡張機能を読み込む
   → extensionフォルダを選択
   ```

4. **PWAを開き直す**
   - 新しいタブで開く
   - ログイン
   - F12でコンソール確認

5. **テストを再実行**
   - デバッグツール（debug.html）を使用
   - 各ステップを順番に確認

---

## 💡 よくある質問

### Q: ポップアップは開くがパスワードが空

**A**: 以下を確認：
1. PWAでログインしているか
2. PWAにパスワードが保存されているか
3. PWAとポップアップが同時に開いているか

### Q: 「Unable to connect」と表示される

**A**: PWAタブが見つかっていません：
1. PWAのURLを確認（localhost:5173またはnoimzip.github.io）
2. PWAタブを開いたままにする
3. ポップアップの「Refresh」ボタンをクリック

### Q: 最初は動いたが突然動かなくなった

**A**: 拡張機能が再読み込みされた可能性：
1. PWAタブをリロード（F5）
2. 拡張機能も再読み込み
3. ポップアップを開き直す

---

## 📞 サポート

上記の手順で解決しない場合は、以下の情報を添えて報告してください：

1. **ブラウザバージョン**: `chrome://version/`
2. **PWAのURL**: どのURLで開いているか
3. **エラーログ**: PWAとポップアップの両方のコンソールログ
4. **デバッグツールの結果**: 各テストの結果のスクリーンショット
