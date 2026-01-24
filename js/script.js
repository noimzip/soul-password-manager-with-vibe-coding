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

import zxcvbn from 'zxcvbn';
import * as OTPAuth from 'otpauth';
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

const originalLog = console.log; console.log = (...args) => { captureLog('INFO', args); originalLog.apply(console, args); };
const originalWarn = console.warn; console.warn = (...args) => { captureLog('WARN', args); originalWarn.apply(console, args); };
const originalError = console.error; console.error = (...args) => { captureLog('ERROR', args); originalError.apply(console, args); };
window.addEventListener('error', (e) => captureLog('UNCAUGHT', [e.message, e.filename, e.lineno]));

// Enable Offline Persistence
enableIndexedDbPersistence(db).catch((err) => {
    if (err.code == 'failed-precondition' || err.code == 'unimplemented') {
        console.warn("Firestore persistence could not be enabled:", err.code);
    }
});

// --- Constants & State ---
const CONSTANTS = {
    APP_VERSION: '26.01.10 (Unstable)',
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
        PASSKEY_FALLBACK: 'soul_passkey_fallback'
    }
};

const CRYPTO_CONFIG = {
    PBKDF2_ITERATIONS: 600000,
    SALT_LENGTH: 16,
    IV_LENGTH: 12
};

const FIXED_ENCRYPTION_SECRET = import.meta.env.VITE_ENCRYPTION_SECRET;

const HYBRID_CONFIG = {
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
};

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
let firestoreSyncUnsubscribe = null;
let contextMenuItem = null;

// --- Translations ---
const TRANSLATIONS = {
    ja: {
        app_title: "Soul Password Manager",
        favorites: "お気に入り",
        passwords: "パスワード",
        login_info: "ログイン情報",
        notes: "メモ",
        personal_info: "個人情報",
        pass_generator: "パスワード生成",
        pass_checker: "パスワード安全性チェッカー",
        security_hub: "セキュリティハブ",
        security_score: "セキュリティスコア",
        weak_pass_count: "脆弱なパスワード",
        no_2fa_count: "2FA未設定",
        reused_pass_count: "使い回しのパスワード",
        security_list_weak: "脆弱なパスワード一覧",
        security_list_no_2fa: "2FA未設定のアカウント一覧",
        security_list_reused: "使い回されているパスワード一覧",
        score_breakdown: "スコアの内訳",
        risk_weak: "脆弱",
        risk_medium: "強度不足",
        risk_no_2fa: "2FA未設定",
        risk_reused: "使い回し",
        risk_solution: "解決策",
        advice_weak: "パスワード生成ツールを使用して、より強力なパスワードに変更することをお勧めします。",
        advice_medium: "もう少し長くするか、複雑にすることをお勧めします。",
        advice_no_2fa: "サービスの2段階認証設定を有効にし、シークレットキーをここに保存してください。",
        advice_reused: "他のサービスと同じパスワードが使われています。ユニークなパスワードに変更してください。",
        trash: "ゴミ箱",
        trash_empty: "ゴミ箱は空です",
        empty_trash: "ゴミ箱を空にする",
        selected_count: "{count} 件選択中",
        select_all: "すべて選択",
        delete_selected_confirm: "選択した {count} 件のパスワードを削除してもよろしいですか？",
        restore: "復元",
        delete_permanently: "完全に削除",
        export_json: "JSONファイルでエクスポート",
        import_json: "JSONファイルをインポート",
        settings: "設定",
        auto_make: "パスワードの自動生成",
        length: "長さ",
        uppercase: "大文字",
        numbers: "数字",
        symbols: "記号",
        copy: "コピー",
        regenerate: "再生成",
        gen_history: "生成履歴",
        clear_history: "履歴をクリア",
        close: "とじる",
        pass_check_title: "パスワードの安全性チェック",
        enter_pass: "パスワードを入力してください",
        add_pass_title: "新しいパスワードを追加",
        placeholder_guide: "リストから項目を選択して詳細を表示するか、<br>新しいパスワードを追加してください。",
        service_name: "サービス名",
        category: "カテゴリ (任意)",
        website: "Webサイト URL",
        username: "ユーザー名/メールアドレス",
        password: "パスワード",
        totp_secret_opt: "TOTP 秘密鍵 (任意)",
        cancel: "キャンセル",
        save: "保存",
        detail_title: "パスワード詳細",
        totp_secret: "TOTP 秘密鍵",
        check_breach: "漏洩チェック (Have I Been Pwned)",
        last_modified: "最終更新",
        revision_count: "変更回数",
        show_history: "変更履歴を表示",
        delete: "削除",
        update: "更新",
        general: "全般",
        security: "セキュリティ",
        default_username: "デフォルトユーザー名",
        auto_logout: "自動ログアウト (分)",
        passkey_settings: "Passkey (生体認証) 設定",
        passkey_desc: "デバイスの生体認証を使ってログインできるようにします。<br>※ブラウザやデバイスがPasskeyの「largeBlob」拡張に対応している必要があります。",
        register_passkey: "Passkeyを登録",
        change_master_pass: "マスターパスワードを変更",
        change_master_pass_confirm: "マスターパスワードを変更してもよろしいですか？",
        login_devices: "ログイン中のデバイス",
        current_device: "現在のデバイス",
        last_access: "最終アクセス: ",
        force_logout: "強制ログアウト",
        force_logout_confirm: "このデバイスを強制的にログアウトさせますか？",
        device_revoked: "デバイスをログアウトさせました",
        session_expired: "セッションが有効期限切れか、削除されました。",
        new_login_detected: "新しい端末 ({device}) からのログインを検知しました",
        security_alert: "セキュリティ通知",
        send_feedback: "フィードバックを送信",
        open_guide: "使い方ガイド",
        guide_title: "使い方ガイド",
        guide_step1_title: "1. パスワードの保存",
        guide_step1_desc: "右下の「+」ボタンから「ログイン情報」を選択して、新しいパスワードを追加できます。カテゴリ分けやお気に入り登録も可能です。",
        guide_tip1: "ヒント: タイトルやユーザー名で検索して、すぐに目的のパスワードを見つけられます。",
        guide_step2_title: "2. パスワード生成",
        guide_step2_desc: "「パスワード生成」ツールを使って、推測されにくい強力なパスワードを自動作成できます。",
        guide_tip2: "ヒント: セキュリティのため、12文字以上の長さを推奨します。",
        guide_step3_title: "3. セキュリティチェック",
        guide_step3_desc: "「セキュリティハブ」では、脆弱なパスワードや使い回しを自動的に検出。漏洩チェック機能も利用できます。",
        guide_tip3: "ヒント: スコア80点以上を目指して、定期的に見直しましょう。",
        guide_step4_title: "4. データの管理",
        guide_step4_desc: "データは端末内に暗号化して保存されます。機種変更時などは設定画面からJSON形式でエクスポートしてください。",
        guide_tip4: "ヒント: エクスポートしたファイルは、他人に見られない安全な場所に保管してください。",
        guide_step5_title: "5. 設定とカスタマイズ",
        guide_step5_desc: "言語設定、ダークモード、自動ログアウト時間などを設定画面から変更できます。",
        guide_tip5: "ヒント: 生体認証（Passkey）を有効にすると、素早く安全にログインできます。",
        include_logs: "アプリのログとエラー情報を含める",
        feedback_desc: "ご意見やバグ報告をお聞かせください。",
        feedback_message: "メッセージ",
        feedback_sent: "フィードバックを送信しました。ありがとうございます！",
        unknown_device: "不明なデバイス",
        current_pass: "現在のパスワード",
        new_pass: "新規パスワード",
        confirm_new_pass: "新規パスワードの確認",
        danger_zone: "危険",
        delete_all_desc: "すべてのパスワードと設定を削除し、アプリを初期化します。",
        delete_all_data: "全データを削除",
        setup_title: "初期設定",
        setup_desc: "マスターユーザー名とパスワードを設定してください。",
        master_pass: "マスターパスワード",
        confirm_pass: "マスターパスワードの確認",
        setup_btn: "セットアップ",
        login_title: "ログイン",
        biometric_login: "生体認証でログイン",
        google_login: "Googleでログイン",
        login_btn: "ログイン",
        warning_title: "Ver 26.01.10 (Unstable)",
        warning_h1: "現在のSoulはデモ版です。",
        warning_desc: "開発者向けに設計されていて操作が煩雑な上、期待通りに動作しない可能性が高く、セキュリティやプライバシーも十分ではありません。",
        warning_h2: "はっきり言って使い物になりません。<br><br>他のパスワードマネージャの使用を強く推奨します。",
        warning_rec: "おすすめパスワードマネージャー:Bitwarden, Proton Pass, KeePass",
        warning_not_rec: "おすすめしないパスワードマネージャー:このパスワードマネージャー, 紙で管理するやつ",
        search_placeholder: "検索...",
        select_mode: "選択モード",
        sort: "並び替え",
        toggle_theme: "テーマ切り替え",
        logout: "ログアウト",
        empty_state_title: "パスワードがありません",
        empty_state_desc: "右下の + ボタンから追加してください。",
        fav_added: "お気に入りに追加しました",
        fav_removed: "お気に入りから削除しました",
        copy_password: "パスワードをコピー",
        copy_username: "ユーザー名をコピー",
        edit: "編集",
        decryption_fail: "復号化に失敗しました (マスターパスワードが異なる可能性があります)",
        passkey_fallback_confirm: "このデバイスはPasskeyへのデータ保存(largeBlob)に対応していません。\n代わりに、アプリ内のローカルストレージに認証情報を保存しますか？\n※注意: セキュリティレベルが低下します。",
        passkey_fallback_saved: "Passkey登録完了 (ローカルストレージ保存)",
        passkey_fallback_login: "生体認証でログインしました (ローカルストレージ)",
        passkey_not_supported_cancel: "largeBlob非対応のためキャンセルしました。",
        
        // JS Strings
        weak: "弱いパスワード",
        medium: "中程度のパスワード",
        strong: "強いパスワード",
        crack_time: "解読にかかる推定時間: ",
        instant: "一瞬",
        centuries: "数世紀以上",
        year: "年", day: "日", hour: "時間", minute: "分", second: "秒",
        copy_fail: "コピーに失敗しました",
        pass_copied: "パスワードをコピーしました",
        user_copied: "ユーザー名をコピーしました",
        code_copied: "2FAコードをコピーしました",
        save_fail: "保存に失敗しました",
        delete_fail: "削除に失敗しました",
        discard_changes_confirm: "変更を破棄しますか？",
        login_fail: "ユーザー名またはパスワードが間違っています。",
        google_login_fail: "Googleログインに失敗しました: ",
        logout_confirm: "ログアウトしますか？",
        pass_created: "新しいパスワードを作成しました",
        pass_updated: "パスワードを更新しました",
        delete_confirm: "このパスワードを削除してもよろしいですか？",
        pass_deleted: "パスワードを削除しました",
        checking: "チェック中...",
        error: "エラーが発生しました",
        safe: "漏洩は見つかりませんでした (安全)",
        breach_found: "危険！ {count} 回の漏洩が確認されました",
        clear_hist_confirm: "このパスワードの変更履歴をすべて削除しますか？",
        hist_cleared: "変更履歴をクリアしました",
        clear_gen_confirm: "生成履歴をすべて削除しますか？",
        gen_cleared: "生成履歴をクリアしました",
        settings_saved: "設定を保存しました",
        default_user_filled: "デフォルトユーザー名を入力しました",
        no_default_user: "デフォルトユーザー名が設定されていません",
        list_sorted: "リストを並び替えました",
        data_mgmt: "データ管理",
        export_json: "エクスポート (JSON)",
        import_json: "インポート (JSON)",
        invalid_data: "無効なデータ形式が含まれています。インポートを中止しました。",
        import_confirm: "現在のリストに {count} 件のデータを追加しますか？",
        import_done: "インポートが完了しました。",
        file_error: "ファイルの読み込みに失敗しました。",
        history_empty: "履歴はありません",
        hist_empty_detail: "変更履歴はありません。",
        restore_confirm: "この履歴の内容を入力フォームに反映しますか？",
        sort_placeholder: "並び替え...",
        sort_name_asc: "名前 (A-Z)",
        sort_name_desc: "名前 (Z-A)",
        sort_str_asc: "強度 (弱い順)",
        sort_str_desc: "強度 (強い順)",
        sort_date_desc: "更新日 (新しい順)",
        sort_date_asc: "更新日 (古い順)",
        language: "言語 / Language",
        about: "アプリについて",
        theme_color: "テーマカラー",
        reset: "リセット",
        retry: "再試行",
        require_second_auth: "Googleログイン後に追加認証を要求",
        require_auth_on_delete: "削除時に認証を要求",
        require_auth_on_show_copy: "表示・コピー時に認証を要求",
        send: "送信",
        version: "バージョン",
        yes: "はい",
        no: "いいえ",
        ok: "OK"
    },
    en: {
        app_title: "Soul Password Manager",
        favorites: "Favorites",
        passwords: "Passwords",
        login_info: "Login Info",
        notes: "Notes",
        personal_info: "Personal Info",
        pass_generator: "Password Generator",
        pass_checker: "Password Health Check",
        security_hub: "Security Hub",
        security_score: "Security Score",
        weak_pass_count: "Weak Passwords",
        no_2fa_count: "Missing 2FA",
        reused_pass_count: "Reused Passwords",
        security_list_weak: "Weak Passwords List",
        security_list_no_2fa: "Accounts Missing 2FA",
        security_list_reused: "Reused Passwords List",
        score_breakdown: "Score Breakdown",
        risk_weak: "Weak",
        risk_medium: "Medium Strength",
        risk_no_2fa: "No 2FA",
        risk_reused: "Reused",
        risk_solution: "Solution",
        advice_weak: "We recommend using the generator to create a stronger password.",
        advice_medium: "Consider making it longer or more complex.",
        advice_no_2fa: "Enable 2FA on the service and save the secret key here.",
        advice_reused: "This password is used elsewhere. Change it to a unique one.",
        trash: "Trash",
        trash_empty: "Trash is empty",
        empty_trash: "Empty Trash",
        selected_count: "{count} Selected",
        select_all: "Select All",
        delete_selected_confirm: "Delete {count} items?",
        restore: "Restore",
        delete_permanently: "Delete Permanently",
        export_json: "Export as JSON",
        import_json: "Import JSON",
        settings: "Settings",
        auto_make: "Auto Generate Password",
        length: "Length",
        uppercase: "Uppercase",
        numbers: "Numbers",
        symbols: "Symbols",
        copy: "Copy",
        regenerate: "Regenerate",
        gen_history: "History",
        clear_history: "Clear History",
        close: "Close",
        pass_check_title: "Password Health Check",
        enter_pass: "Enter your password here",
        add_pass_title: "Add New Password",
        placeholder_guide: "Select an item from the list to view details,<br>or add a new password.",
        service_name: "Service Name",
        category: "Category (Optional)",
        website: "Website URL",
        username: "Username / Email",
        password: "Password",
        totp_secret_opt: "TOTP Secret (Optional)",
        cancel: "Cancel",
        save: "Save",
        detail_title: "Password Details",
        totp_secret: "TOTP Secret",
        check_breach: "Check Breach (Have I Been Pwned)",
        last_modified: "Last Modified",
        revision_count: "Revisions",
        show_history: "Show History",
        delete: "Delete",
        update: "Update",
        general: "General",
        security: "Security",
        default_username: "Default Username",
        auto_logout: "Auto Logout (Minutes)",
        passkey_settings: "Passkey (Biometric) Settings",
        passkey_desc: "Enable login using device biometrics.<br>*Requires browser/device support for Passkey 'largeBlob' extension.",
        register_passkey: "Register Passkey",
        change_master_pass: "Change Master Password",
        change_master_pass_confirm: "Are you sure you want to change your master password?",
        login_devices: "Logged-in Devices",
        current_device: "Current Device",
        last_access: "Last Access: ",
        force_logout: "Force Logout",
        force_logout_confirm: "Force logout this device?",
        device_revoked: "Device logged out",
        session_expired: "Session expired or revoked.",
        new_login_detected: "New login detected from {device}",
        security_alert: "Security Alert",
        send_feedback: "Send Feedback",
        open_guide: "User Guide",
        guide_title: "User Guide",
        guide_step1_title: "1. Saving Passwords",
        guide_step1_desc: "Add new passwords via the '+' button. You can also categorize them and mark as favorites.",
        guide_tip1: "Tip: You can search for passwords by title or username.",
        guide_step2_title: "2. Password Generator",
        guide_step2_desc: "Use the 'Password Generator' tool to automatically create strong, hard-to-guess passwords.",
        guide_tip2: "Tip: We recommend 12 characters or more for better security.",
        guide_step3_title: "3. Security Check",
        guide_step3_desc: "The 'Security Hub' detects weak or reused passwords. You can also check for data breaches.",
        guide_tip3: "Tip: Aim for a score of 80 or higher.",
        guide_step4_title: "4. Data Management",
        guide_step4_desc: "Data is encrypted locally. Export as JSON from Settings for backups or device migration.",
        guide_tip4: "Tip: Keep your exported file in a secure location.",
        guide_step5_title: "5. Settings & Customization",
        guide_step5_desc: "Change language, toggle dark mode, and set auto-logout timer from Settings.",
        guide_tip5: "Tip: Enable biometrics for faster and secure access.",
        include_logs: "Include app logs and error info",
        feedback_desc: "Please let us know your thoughts or report bugs.",
        feedback_message: "Message",
        feedback_sent: "Feedback sent. Thank you!",
        unknown_device: "Unknown Device",
        current_pass: "Current Password",
        new_pass: "New Password",
        confirm_new_pass: "Confirm New Password",
        danger_zone: "Danger Zone",
        delete_all_desc: "Delete all passwords and settings, and reset the app.",
        delete_all_data: "Delete All Data",
        setup_title: "Initial Setup",
        setup_desc: "Set your master username and password.",
        master_pass: "Master Password",
        confirm_pass: "Confirm Password",
        setup_btn: "Setup",
        login_title: "Login",
        biometric_login: "Login with Biometrics",
        google_login: "Login with Google",
        login_btn: "Login",
        warning_title: "Ver 26.01.10 (Unstable)",
        warning_h1: "This is a DEMO version.",
        warning_desc: "Designed for developers, it may not work as expected and lacks sufficient security/privacy features.",
        warning_h2: "Honestly, it's not ready for production.<br><br>We strongly recommend other password managers.",
        warning_rec: "Recommended: Bitwarden, Proton Pass, KeePass",
        warning_not_rec: "Not Recommended: This app, Paper",
        search_placeholder: "Search...",
        select_mode: "Selection Mode",
        sort: "Sort",
        toggle_theme: "Toggle Theme",
        logout: "Logout",
        empty_state_title: "No passwords yet",
        empty_state_desc: "Tap the + button to add one.",
        fav_added: "Added to favorites",
        fav_removed: "Removed from favorites",
        copy_password: "Copy Password",
        copy_username: "Copy Username",
        edit: "Edit",
        decryption_fail: "Decryption failed (Master password might be different)",
        passkey_fallback_confirm: "This device does not support saving data to Passkey (largeBlob).\nDo you want to save credentials to local storage instead?\n*Warning: Security level will be reduced.",
        passkey_fallback_saved: "Passkey registered (Saved to Local Storage)",
        passkey_fallback_login: "Logged in with Biometrics (Local Storage)",
        passkey_not_supported_cancel: "Cancelled due to lack of largeBlob support.",

        // JS Strings
        weak: "Weak Password",
        medium: "Medium Password",
        strong: "Strong Password",
        crack_time: "Est. Crack Time: ",
        instant: "Instant",
        centuries: "Centuries+",
        year: "y", day: "d", hour: "h", minute: "m", second: "s",
        copy_fail: "Copy failed",
        pass_copied: "Password copied",
        user_copied: "Username copied",
        code_copied: "2FA code copied",
        save_fail: "Save failed",
        delete_fail: "Delete failed",
        discard_changes_confirm: "Discard changes?",
        login_fail: "Invalid username or password.",
        google_login_fail: "Google login failed: ",
        logout_confirm: "Are you sure you want to logout?",
        pass_created: "New password created",
        pass_updated: "Password updated",
        delete_confirm: "Are you sure you want to delete this password?",
        pass_deleted: "Password deleted",
        checking: "Checking...",
        error: "Error occurred",
        safe: "No breach found (Safe)",
        breach_found: "Danger! Found in {count} breaches",
        clear_hist_confirm: "Delete all history for this password?",
        hist_cleared: "History cleared",
        clear_gen_confirm: "Delete all generation history?",
        gen_cleared: "Generation history cleared",
        settings_saved: "Settings saved",
        default_user_filled: "Default username filled",
        no_default_user: "No default username set",
        list_sorted: "List sorted",
        data_mgmt: "Data Management",
        export_json: "Export (JSON)",
        import_json: "Import (JSON)",
        invalid_data: "Invalid data format. Import cancelled.",
        import_confirm: "Add {count} items to current list?",
        import_done: "Import complete.",
        file_error: "Failed to read file.",
        history_empty: "No history",
        hist_empty_detail: "No modification history.",
        restore_confirm: "Restore this version to the form?",
        sort_placeholder: "Sort by...",
        sort_name_asc: "Name (A-Z)",
        sort_name_desc: "Name (Z-A)",
        sort_str_asc: "Strength (Weakest)",
        sort_str_desc: "Strength (Strongest)",
        sort_date_desc: "Date (Newest)",
        sort_date_asc: "Date (Oldest)",
        language: "Language / 言語",
        about: "About",
        theme_color: "Theme Color",
        reset: "Reset",
        retry: "Retry",
        require_second_auth: "Require extra auth after Google Login",
        require_auth_on_delete: "Require auth on delete",
        require_auth_on_show_copy: "Require auth on show/copy",
        send: "Send",
        version: "Version",
        yes: "Yes",
        no: "No",
        ok: "OK"
    },
    zh: {
        app_title: "Soul Password Manager",
        favorites: "收藏夹",
        passwords: "密码",
        login_info: "登录信息",
        notes: "备注",
        personal_info: "个人信息",
        pass_generator: "密码生成器",
        pass_checker: "密码安全检查",
        security_hub: "安全中心",
        security_score: "安全评分",
        weak_pass_count: "弱密码",
        no_2fa_count: "未设置 2FA",
        reused_pass_count: "重复使用的密码",
        security_list_weak: "弱密码列表",
        security_list_no_2fa: "未设置 2FA 的账户",
        security_list_reused: "重复使用的密码列表",
        score_breakdown: "评分详情",
        risk_weak: "弱密码",
        risk_medium: "强度不足",
        risk_no_2fa: "未设置 2FA",
        risk_reused: "重复使用",
        risk_solution: "解决方案",
        advice_weak: "建议使用生成器创建一个更强的密码。",
        advice_medium: "考虑增加长度或复杂度。",
        advice_no_2fa: "在服务上启用 2FA 并在此处保存密钥。",
        advice_reused: "此密码在其他地方使用。请更改为唯一的密码。",
        trash: "回收站",
        trash_empty: "回收站为空",
        empty_trash: "清空回收站",
        selected_count: "已选择 {count} 项",
        select_all: "全选",
        delete_selected_confirm: "确定要删除选中的 {count} 个项目吗？",
        restore: "恢复",
        delete_permanently: "永久删除",
        export_json: "导出 JSON",
        import_json: "导入 JSON",
        settings: "设置",
        auto_make: "自动生成密码",
        length: "长度",
        uppercase: "大写字母",
        numbers: "数字",
        symbols: "符号",
        copy: "复制",
        regenerate: "重新生成",
        gen_history: "生成历史",
        clear_history: "清除历史",
        close: "关闭",
        pass_check_title: "密码安全检查",
        enter_pass: "请输入密码",
        add_pass_title: "添加新密码",
        placeholder_guide: "从列表中选择一项以查看详细信息，<br>或添加新密码。",
        service_name: "服务名称",
        category: "分类 (可选)",
        website: "网站 URL",
        username: "用户名 / 邮箱",
        password: "密码",
        totp_secret_opt: "TOTP 密钥 (可选)",
        cancel: "取消",
        save: "保存",
        detail_title: "密码详情",
        totp_secret: "TOTP 密钥",
        check_breach: "检查泄露 (Have I Been Pwned)",
        last_modified: "最后修改",
        revision_count: "修改次数",
        show_history: "显示修改历史",
        delete: "删除",
        update: "更新",
        general: "常规",
        security: "安全",
        default_username: "默认用户名",
        auto_logout: "自动注销 (分钟)",
        passkey_settings: "Passkey (生物识别) 设置",
        passkey_desc: "启用设备生物识别登录。<br>*需要浏览器/设备支持 Passkey 'largeBlob' 扩展。",
        register_passkey: "注册 Passkey",
        change_master_pass: "修改主密码",
        change_master_pass_confirm: "确定要更改主密码吗？",
        login_devices: "登录设备",
        current_device: "当前设备",
        last_access: "最后访问: ",
        force_logout: "强制注销",
        force_logout_confirm: "强制注销此设备？",
        device_revoked: "设备已注销",
        session_expired: "会话已过期或被撤销。",
        new_login_detected: "检测到来自 {device} 的新登录",
        security_alert: "安全警报",
        send_feedback: "发送反馈",
        open_guide: "用户指南",
        guide_title: "用户指南",
        guide_step1_title: "1. 保存密码",
        guide_step1_desc: "通过右下角的“+”按钮添加新密码。您还可以对其进行分类并标记为收藏。",
        guide_tip1: "提示：您可以按标题或用户名搜索密码。",
        guide_step2_title: "2. 密码生成器",
        guide_step2_desc: "使用“密码生成器”工具自动创建难以猜测的强密码。",
        guide_tip2: "提示：为了更好的安全性，建议使用 12 个字符或更多。",
        guide_step3_title: "3. 安全检查",
        guide_step3_desc: "“安全中心”会自动检测弱密码或重复使用的密码。您还可以检查数据泄露。",
        guide_tip3: "提示：目标是达到 80 分或更高。",
        guide_step4_title: "4. 数据管理",
        guide_step4_desc: "数据在本地加密存储。建议从设置中导出 JSON 进行备份或迁移。",
        guide_tip4: "提示：请将导出的文件保存在安全的位置。",
        guide_step5_title: "5. 设置与自定义",
        guide_step5_desc: "在设置中更改语言、切换深色模式以及设置自动注销计时器。",
        guide_tip5: "提示：启用生物识别技术以实现更快、更安全的访问。",
        include_logs: "包含应用日志和错误信息",
        feedback_desc: "请告诉我们要改进的地方或报告错误。",
        feedback_message: "消息",
        feedback_sent: "反馈已发送。谢谢！",
        unknown_device: "未知设备",
        current_pass: "当前密码",
        new_pass: "新密码",
        confirm_new_pass: "确认新密码",
        danger_zone: "危险区域",
        delete_all_desc: "删除所有密码和设置，并重置应用。",
        delete_all_data: "删除所有数据",
        setup_title: "初始设置",
        setup_desc: "设置您的主用户名和密码。",
        master_pass: "主密码",
        confirm_pass: "确认密码",
        setup_btn: "设置",
        login_title: "登录",
        biometric_login: "生物识别登录",
        google_login: "Google 登录",
        login_btn: "登录",
        warning_title: "Ver 26.01.10 (Unstable)",
        warning_h1: "这是演示版本。",
        warning_desc: "专为开发者设计，可能无法按预期工作，且缺乏足够的安全/隐私功能。",
        warning_h2: "坦率地说，它尚未准备好用于生产环境。<br><br>我们强烈建议使用其他密码管理器。",
        warning_rec: "推荐: Bitwarden, Proton Pass, KeePass",
        warning_not_rec: "不推荐: 此应用, 纸张",
        search_placeholder: "搜索...",
        select_mode: "选择模式",
        sort: "排序",
        toggle_theme: "切换主题",
        logout: "注销",
        empty_state_title: "暂无密码",
        empty_state_desc: "点击 + 按钮添加一个。",
        fav_added: "已添加到收藏夹",
        fav_removed: "已从收藏夹移除",
        copy_password: "复制密码",
        copy_username: "复制用户名",
        edit: "编辑",
        decryption_fail: "解密失败 (主密码可能不同)",
        passkey_fallback_confirm: "此设备不支持将数据保存到 Passkey (largeBlob)。\n您想将凭据保存到本地存储吗？\n*警告：安全性将降低。",
        passkey_fallback_saved: "Passkey 已注册（保存到本地存储）",
        passkey_fallback_login: "已使用生物识别登录（本地存储）",
        passkey_not_supported_cancel: "由于不支持 largeBlob 已取消。",
        
        // JS Strings
        weak: "弱密码",
        medium: "中等密码",
        strong: "强密码",
        crack_time: "预计破解时间: ",
        instant: "瞬间",
        centuries: "数世纪以上",
        year: "年", day: "天", hour: "小时", minute: "分", second: "秒",
        copy_fail: "复制失败",
        pass_copied: "密码已复制",
        user_copied: "用户名已复制",
        code_copied: "2FA 代码已复制",
        save_fail: "保存失败",
        delete_fail: "删除失败",
        discard_changes_confirm: "放弃更改？",
        login_fail: "用户名或密码无效。",
        google_login_fail: "Google 登录失败: ",
        logout_confirm: "确定要注销吗？",
        pass_created: "新密码已创建",
        pass_updated: "密码已更新",
        delete_confirm: "确定要删除此密码吗？",
        pass_deleted: "密码已删除",
        checking: "检查中...",
        error: "发生错误",
        safe: "未发现泄露 (安全)",
        breach_found: "危险！在 {count} 次泄露中发现",
        clear_hist_confirm: "删除此密码的所有历史记录？",
        hist_cleared: "历史记录已清除",
        clear_gen_confirm: "删除所有生成历史？",
        gen_cleared: "生成历史已清除",
        settings_saved: "设置已保存",
        default_user_filled: "已填充默认用户名",
        no_default_user: "未设置默认用户名",
        list_sorted: "列表已排序",
        data_mgmt: "数据管理",
        export_json: "导出 (JSON)",
        import_json: "导入 (JSON)",
        invalid_data: "数据格式无效。导入已取消。",
        import_confirm: "将 {count} 个项目添加到当前列表？",
        import_done: "导入完成。",
        file_error: "读取文件失败。",
        history_empty: "无历史记录",
        hist_empty_detail: "无修改历史。",
        restore_confirm: "将此版本恢复到表单？",
        sort_placeholder: "排序方式...",
        sort_name_asc: "名称 (A-Z)",
        sort_name_desc: "名称 (Z-A)",
        sort_str_asc: "强度 (最弱)",
        sort_str_desc: "强度 (最强)",
        sort_date_desc: "日期 (最新)",
        sort_date_asc: "日期 (最旧)",
        language: "语言 / Language",
        about: "关于",
        theme_color: "主题颜色",
        reset: "重置",
        retry: "重试",
        require_second_auth: "Google登录后需要额外认证",
        require_auth_on_delete: "删除时需要认证",
        require_auth_on_show_copy: "显示/复制时需要认证",
        send: "发送",
        version: "版本",
        yes: "是",
        no: "否",
        ok: "确定"
    },
    ko: {
        app_title: "Soul Password Manager",
        favorites: "즐겨찾기",
        passwords: "비밀번호",
        login_info: "로그인 정보",
        notes: "메모",
        personal_info: "개인 정보",
        pass_generator: "비밀번호 생성기",
        pass_checker: "비밀번호 안전성 검사",
        security_hub: "보안 허브",
        security_score: "보안 점수",
        weak_pass_count: "취약한 비밀번호",
        no_2fa_count: "2FA 미설정",
        reused_pass_count: "재사용된 비밀번호",
        security_list_weak: "취약한 비밀번호 목록",
        security_list_no_2fa: "2FA 미설정 계정 목록",
        security_list_reused: "재사용된 비밀번호 목록",
        score_breakdown: "점수 내역",
        risk_weak: "취약함",
        risk_medium: "강도 부족",
        risk_no_2fa: "2FA 미설정",
        risk_reused: "재사용됨",
        risk_solution: "해결책",
        advice_weak: "생성기를 사용하여 더 강력한 비밀번호를 만드는 것이 좋습니다.",
        advice_medium: "길이를 늘리거나 복잡하게 만드는 것을 고려하세요.",
        advice_no_2fa: "서비스에서 2FA를 활성화하고 여기에 비밀키를 저장하세요.",
        advice_reused: "이 비밀번호는 다른 곳에서도 사용됩니다. 고유한 비밀번호로 변경하세요.",
        trash: "휴지통",
        trash_empty: "휴지통이 비었습니다",
        empty_trash: "휴지통 비우기",
        selected_count: "{count}개 선택됨",
        select_all: "모두 선택",
        delete_selected_confirm: "선택한 {count}개의 항목을 삭제하시겠습니까?",
        restore: "복원",
        delete_permanently: "영구 삭제",
        export_json: "JSON 내보내기",
        import_json: "JSON 가져오기",
        settings: "설정",
        auto_make: "비밀번호 자동 생성",
        length: "길이",
        uppercase: "대문자",
        numbers: "숫자",
        symbols: "기호",
        copy: "복사",
        regenerate: "재생성",
        gen_history: "생성 기록",
        clear_history: "기록 지우기",
        close: "닫기",
        pass_check_title: "비밀번호 안전성 검사",
        enter_pass: "비밀번호를 입력하세요",
        add_pass_title: "새 비밀번호 추가",
        placeholder_guide: "목록에서 항목을 선택하여 세부 정보를 보거나,<br>새 비밀번호를 추가하세요.",
        service_name: "서비스 이름",
        category: "카테고리 (선택)",
        website: "웹사이트 URL",
        username: "사용자명 / 이메일",
        password: "비밀번호",
        totp_secret_opt: "TOTP 비밀키 (선택)",
        cancel: "취소",
        save: "저장",
        detail_title: "비밀번호 상세",
        totp_secret: "TOTP 비밀키",
        check_breach: "유출 확인 (Have I Been Pwned)",
        last_modified: "최종 수정",
        revision_count: "수정 횟수",
        show_history: "수정 기록 보기",
        delete: "삭제",
        update: "업데이트",
        general: "일반",
        security: "보안",
        default_username: "기본 사용자명",
        auto_logout: "자동 로그아웃 (분)",
        passkey_settings: "Passkey (생체 인증) 설정",
        passkey_desc: "기기 생체 인증을 사용하여 로그인합니다.<br>*브라우저/기기가 Passkey 'largeBlob' 확장을 지원해야 합니다.",
        register_passkey: "Passkey 등록",
        change_master_pass: "마스터 비밀번호 변경",
        change_master_pass_confirm: "마스터 비밀번호를 변경하시겠습니까?",
        login_devices: "로그인된 기기",
        current_device: "현재 기기",
        last_access: "최근 접속: ",
        force_logout: "강제 로그아웃",
        force_logout_confirm: "이 기기를 강제로 로그아웃하시겠습니까?",
        device_revoked: "기기가 로그아웃되었습니다",
        session_expired: "세션이 만료되었거나 취소되었습니다.",
        new_login_detected: "{device}에서 새로운 로그인이 감지되었습니다",
        security_alert: "보안 알림",
        send_feedback: "피드백 보내기",
        open_guide: "사용자 가이드",
        guide_title: "사용자 가이드",
        guide_step1_title: "1. 비밀번호 저장",
        guide_step1_desc: "오른쪽 하단의 '+' 버튼을 통해 새 비밀번호를 추가하세요. 카테고리를 지정하거나 즐겨찾기에 추가할 수도 있습니다.",
        guide_tip1: "팁: 제목이나 사용자 이름으로 비밀번호를 검색할 수 있습니다.",
        guide_step2_title: "2. 비밀번호 생성기",
        guide_step2_desc: "'비밀번호 생성기' 도구를 사용하여 강력하고 추측하기 어려운 비밀번호를 자동으로 생성하세요.",
        guide_tip2: "팁: 보안을 위해 12자 이상을 권장합니다.",
        guide_step3_title: "3. 보안 검사",
        guide_step3_desc: "'보안 허브'는 취약하거나 재사용된 비밀번호를 감지합니다. 데이터 유출 여부도 확인할 수 있습니다.",
        guide_tip3: "팁: 80점 이상을 목표로 하세요.",
        guide_step4_title: "4. 데이터 관리",
        guide_step4_desc: "데이터는 로컬에 암호화되어 저장됩니다. 백업이나 기기 이동을 위해 설정에서 JSON으로 내보내세요.",
        guide_tip4: "팁: 내보낸 파일은 안전한 곳에 보관하세요.",
        guide_step5_title: "5. 설정 및 사용자 지정",
        guide_step5_desc: "설정에서 언어를 변경하고, 다크 모드를 전환하며, 자동 로그아웃 타이머를 설정하세요.",
        guide_tip5: "팁: 더 빠르고 안전한 액세스를 위해 생체 인식을 활성화하세요.",
        include_logs: "앱 로그 및 오류 정보 포함",
        feedback_desc: "의견이나 버그 제보를 보내주세요.",
        feedback_message: "메시지",
        feedback_sent: "피드백이 전송되었습니다. 감사합니다!",
        unknown_device: "알 수 없는 기기",
        current_pass: "현재 비밀번호",
        new_pass: "새 비밀번호",
        confirm_new_pass: "새 비밀번호 확인",
        danger_zone: "위험 구역",
        delete_all_desc: "모든 비밀번호와 설정을 삭제하고 앱을 초기화합니다.",
        delete_all_data: "모든 데이터 삭제",
        setup_title: "초기 설정",
        setup_desc: "마스터 사용자명과 비밀번호를 설정하세요.",
        master_pass: "마스터 비밀번호",
        confirm_pass: "비밀번호 확인",
        setup_btn: "설정",
        login_title: "로그인",
        biometric_login: "생체 인증 로그인",
        google_login: "Google 로그인",
        login_btn: "로그인",
        warning_title: "Ver 26.01.10 (Unstable)",
        warning_h1: "데모 버전입니다.",
        warning_desc: "개발자용으로 설계되었으며, 예상대로 작동하지 않을 수 있고 보안/개인정보 보호 기능이 충분하지 않습니다.",
        warning_h2: "솔직히 말해서, 실사용 준비가 되지 않았습니다.<br><br>다른 비밀번호 관리자를 사용하는 것을 강력히 권장합니다.",
        warning_rec: "추천: Bitwarden, Proton Pass, KeePass",
        warning_not_rec: "비추천: 이 앱, 종이",
        search_placeholder: "검색...",
        select_mode: "선택 모드",
        sort: "정렬",
        toggle_theme: "테마 전환",
        logout: "로그아웃",
        empty_state_title: "비밀번호 없음",
        empty_state_desc: "오른쪽 하단의 + 버튼을 눌러 추가하세요.",
        fav_added: "즐겨찾기에 추가됨",
        fav_removed: "즐겨찾기에서 제거됨",
        copy_password: "비밀번호 복사",
        copy_username: "사용자명 복사",
        edit: "편집",
        decryption_fail: "복호화 실패 (마스터 비밀번호가 다를 수 있음)",
        passkey_fallback_confirm: "이 기기는 Passkey(largeBlob) 데이터 저장을 지원하지 않습니다.\n대신 로컬 스토리지에 자격 증명을 저장하시겠습니까?\n*경고: 보안 수준이 낮아집니다.",
        passkey_fallback_saved: "Passkey 등록됨 (로컬 스토리지에 저장됨)",
        passkey_fallback_login: "생체 인증으로 로그인됨 (로컬 스토리지)",
        passkey_not_supported_cancel: "largeBlob 미지원으로 취소되었습니다.",
        
        // JS Strings
        weak: "약한 비밀번호",
        medium: "보통 비밀번호",
        strong: "강력한 비밀번호",
        crack_time: "예상 해독 시간: ",
        instant: "즉시",
        centuries: "수 세기 이상",
        year: "년", day: "일", hour: "시간", minute: "분", second: "초",
        copy_fail: "복사 실패",
        pass_copied: "비밀번호 복사됨",
        user_copied: "사용자명 복사됨",
        code_copied: "2FA 코드 복사됨",
        save_fail: "저장 실패",
        delete_fail: "삭제 실패",
        discard_changes_confirm: "변경 사항을 취소하시겠습니까?",
        login_fail: "사용자명 또는 비밀번호가 올바르지 않습니다.",
        google_login_fail: "Google 로그인 실패: ",
        logout_confirm: "로그아웃하시겠습니까?",
        pass_created: "새 비밀번호 생성됨",
        pass_updated: "비밀번호 업데이트됨",
        delete_confirm: "이 비밀번호를 삭제하시겠습니까?",
        pass_deleted: "비밀번호 삭제됨",
        checking: "확인 중...",
        error: "오류 발생",
        safe: "유출 발견되지 않음 (안전)",
        breach_found: "위험! {count}건의 유출에서 발견됨",
        clear_hist_confirm: "이 비밀번호의 모든 기록을 삭제하시겠습니까?",
        hist_cleared: "기록 삭제됨",
        clear_gen_confirm: "모든 생성 기록을 삭제하시겠습니까?",
        gen_cleared: "생성 기록 삭제됨",
        settings_saved: "설정 저장됨",
        default_user_filled: "기본 사용자명 입력됨",
        no_default_user: "기본 사용자명이 설정되지 않음",
        list_sorted: "목록 정렬됨",
        data_mgmt: "데이터 관리",
        export_json: "내보내기 (JSON)",
        import_json: "가져오기 (JSON)",
        invalid_data: "잘못된 데이터 형식입니다. 가져오기가 취소되었습니다.",
        import_confirm: "현재 목록에 {count}개 항목을 추가하시겠습니까?",
        import_done: "가져오기 완료.",
        file_error: "파일 읽기 실패.",
        history_empty: "기록 없음",
        hist_empty_detail: "수정 기록이 없습니다.",
        restore_confirm: "이 버전을 폼에 복원하시겠습니까?",
        sort_placeholder: "정렬...",
        sort_name_asc: "이름 (A-Z)",
        sort_name_desc: "이름 (Z-A)",
        sort_str_asc: "강도 (약한 순)",
        sort_str_desc: "강도 (강한 순)",
        sort_date_desc: "날짜 (최신순)",
        sort_date_asc: "날짜 (오래된순)",
        language: "언어 / Language",
        about: "앱 정보",
        theme_color: "테마 색상",
        reset: "초기화",
        retry: "재시도",
        require_second_auth: "Google 로그인 후 추가 인증 필요",
        require_auth_on_delete: "삭제 시 인증 필요",
        require_auth_on_show_copy: "표시/복사 시 인증 필요",
        send: "보내기",
        version: "버전",
        yes: "예",
        no: "아니요",
        ok: "확인"
    },
    de: {
        app_title: "Soul Password Manager",
        favorites: "Favoriten",
        passwords: "Passwörter",
        login_info: "Anmeldedaten",
        notes: "Notizen",
        personal_info: "Persönliche Infos",
        pass_generator: "Passwort-Generator",
        pass_checker: "Passwort-Check",
        security_hub: "Sicherheits-Hub",
        security_score: "Sicherheitsbewertung",
        weak_pass_count: "Schwache Passwörter",
        no_2fa_count: "Fehlende 2FA",
        reused_pass_count: "Wiederverwendete Passwörter",
        security_list_weak: "Liste schwacher Passwörter",
        security_list_no_2fa: "Konten ohne 2FA",
        security_list_reused: "Liste wiederverwendeter Passwörter",
        score_breakdown: "Bewertungsdetails",
        risk_weak: "Schwach",
        risk_medium: "Mittel",
        risk_no_2fa: "Kein 2FA",
        risk_reused: "Wiederverwendet",
        risk_solution: "Lösung",
        advice_weak: "Wir empfehlen, den Generator für ein stärkeres Passwort zu verwenden.",
        advice_medium: "Erwägen Sie, es länger oder komplexer zu machen.",
        advice_no_2fa: "Aktivieren Sie 2FA beim Dienst und speichern Sie das Geheimnis hier.",
        advice_reused: "Dieses Passwort wird woanders verwendet. Ändern Sie es in ein einzigartiges.",
        trash: "Papierkorb",
        trash_empty: "Papierkorb ist leer",
        empty_trash: "Papierkorb leeren",
        selected_count: "{count} ausgewählt",
        select_all: "Alles auswählen",
        delete_selected_confirm: "{count} Elemente löschen?",
        restore: "Wiederherstellen",
        delete_permanently: "Endgültig löschen",
        export_json: "Als JSON exportieren",
        import_json: "JSON importieren",
        settings: "Einstellungen",
        auto_make: "Passwort generieren",
        length: "Länge",
        uppercase: "Großbuchstaben",
        numbers: "Zahlen",
        symbols: "Symbole",
        copy: "Kopieren",
        regenerate: "Neu generieren",
        gen_history: "Verlauf",
        clear_history: "Verlauf löschen",
        close: "Schließen",
        pass_check_title: "Passwort-Sicherheitscheck",
        enter_pass: "Passwort hier eingeben",
        add_pass_title: "Neues Passwort hinzufügen",
        placeholder_guide: "Wählen Sie ein Element aus der Liste aus, um Details anzuzeigen,<br>oder fügen Sie ein neues Passwort hinzu.",
        service_name: "Dienstname",
        category: "Kategorie (Optional)",
        website: "Website-URL",
        username: "Benutzername / E-Mail",
        password: "Passwort",
        totp_secret_opt: "TOTP-Geheimnis (Optional)",
        cancel: "Abbrechen",
        save: "Speichern",
        detail_title: "Passwort-Details",
        totp_secret: "TOTP-Geheimnis",
        check_breach: "Auf Lecks prüfen (HIBP)",
        last_modified: "Zuletzt geändert",
        revision_count: "Änderungen",
        show_history: "Verlauf anzeigen",
        delete: "Löschen",
        update: "Aktualisieren",
        general: "Allgemein",
        security: "Sicherheit",
        default_username: "Standard-Benutzername",
        auto_logout: "Auto-Logout (Minuten)",
        passkey_settings: "Passkey (Biometrie) Einstellungen",
        passkey_desc: "Anmeldung mit Geräte-Biometrie aktivieren.<br>*Erfordert Browser/Geräte-Unterstützung für Passkey 'largeBlob'-Erweiterung.",
        register_passkey: "Passkey registrieren",
        change_master_pass: "Master-Passwort ändern",
        change_master_pass_confirm: "Möchten Sie Ihr Master-Passwort wirklich ändern?",
        login_devices: "Angemeldete Geräte",
        current_device: "Aktuelles Gerät",
        last_access: "Letzter Zugriff: ",
        force_logout: "Zwangabmeldung",
        force_logout_confirm: "Dieses Gerät zwangsweise abmelden?",
        device_revoked: "Gerät abgemeldet",
        session_expired: "Sitzung abgelaufen oder widerrufen.",
        new_login_detected: "Neue Anmeldung von {device} erkannt",
        security_alert: "Sicherheitswarnung",
        send_feedback: "Feedback senden",
        open_guide: "Benutzerhandbuch",
        guide_title: "Benutzerhandbuch",
        guide_step1_title: "1. Passwörter speichern",
        guide_step1_desc: "Fügen Sie neue Passwörter über die Schaltfläche '+' hinzu. Sie können sie auch kategorisieren und als Favoriten markieren.",
        guide_tip1: "Tipp: Sie können nach Titel oder Benutzername suchen.",
        guide_step2_title: "2. Passwort-Generator",
        guide_step2_desc: "Verwenden Sie den 'Passwort-Generator', um automatisch starke, schwer zu erratende Passwörter zu erstellen.",
        guide_tip2: "Tipp: Wir empfehlen 12 Zeichen oder mehr für bessere Sicherheit.",
        guide_step3_title: "3. Sicherheitscheck",
        guide_step3_desc: "Der 'Sicherheits-Hub' erkennt schwache oder wiederverwendete Passwörter. Sie können auch auf Datenlecks prüfen.",
        guide_tip3: "Tipp: Streben Sie eine Punktzahl von 80 oder höher an.",
        guide_step4_title: "4. Datenverwaltung",
        guide_step4_desc: "Daten werden lokal verschlüsselt. Exportieren Sie JSON aus den Einstellungen für Backups oder Migration.",
        guide_tip4: "Tipp: Bewahren Sie Ihre exportierte Datei an einem sicheren Ort auf.",
        guide_step5_title: "5. Einstellungen & Anpassung",
        guide_step5_desc: "Ändern Sie die Sprache, schalten Sie den Dunkelmodus um und stellen Sie den Auto-Logout-Timer in den Einstellungen ein.",
        guide_tip5: "Tipp: Aktivieren Sie Biometrie für schnelleren und sicheren Zugriff.",
        include_logs: "App-Protokolle und Fehlerinfos einschließen",
        feedback_desc: "Bitte teilen Sie uns Ihre Meinung mit oder melden Sie Fehler.",
        feedback_message: "Nachricht",
        feedback_sent: "Feedback gesendet. Danke!",
        unknown_device: "Unbekanntes Gerät",
        current_pass: "Aktuelles Passwort",
        new_pass: "Neues Passwort",
        confirm_new_pass: "Neues Passwort bestätigen",
        danger_zone: "Gefahrenzone",
        delete_all_desc: "Alle Passwörter und Einstellungen löschen und App zurücksetzen.",
        delete_all_data: "Alle Daten löschen",
        setup_title: "Ersteinrichtung",
        setup_desc: "Legen Sie Ihren Master-Benutzernamen und das Passwort fest.",
        master_pass: "Master-Passwort",
        confirm_pass: "Passwort bestätigen",
        setup_btn: "Einrichten",
        login_title: "Anmelden",
        biometric_login: "Mit Biometrie anmelden",
        google_login: "Mit Google anmelden",
        login_btn: "Anmelden",
        warning_title: "Ver 26.01.10 (Unstable)",
        warning_h1: "Dies ist eine DEMO-Version.",
        warning_desc: "Für Entwickler konzipiert, funktioniert möglicherweise nicht wie erwartet und bietet keine ausreichende Sicherheit/Privatsphäre.",
        warning_h2: "Ehrlich gesagt, es ist nicht bereit für den produktiven Einsatz.<br><br>Wir empfehlen dringend andere Passwort-Manager.",
        warning_rec: "Empfohlen: Bitwarden, Proton Pass, KeePass",
        warning_not_rec: "Nicht empfohlen: Diese App, Papier",
        search_placeholder: "Suchen...",
        select_mode: "Auswahlmodus",
        sort: "Sortieren",
        toggle_theme: "Thema umschalten",
        logout: "Abmelden",
        empty_state_title: "Noch keine Passwörter",
        empty_state_desc: "Tippen Sie auf +, um eines hinzuzufügen.",
        fav_added: "Zu Favoriten hinzugefügt",
        fav_removed: "Aus Favoriten entfernt",
        copy_password: "Passwort kopieren",
        copy_username: "Benutzernamen kopieren",
        edit: "Bearbeiten",
        decryption_fail: "Entschlüsselung fehlgeschlagen",
        passkey_fallback_confirm: "Dieses Gerät unterstützt das Speichern von Daten auf Passkey (largeBlob) nicht.\nMöchten Sie die Anmeldeinformationen stattdessen im lokalen Speicher ablegen?\n*Warnung: Die Sicherheit wird verringert.",
        passkey_fallback_saved: "Passkey registriert (Im lokalen Speicher gespeichert)",
        passkey_fallback_login: "Mit Biometrie angemeldet (Lokaler Speicher)",
        passkey_not_supported_cancel: "Abgebrochen wegen fehlender largeBlob-Unterstützung.",
        
        // JS Strings
        weak: "Schwaches Passwort",
        medium: "Mittleres Passwort",
        strong: "Starkes Passwort",
        crack_time: "Geschätzte Knackzeit: ",
        instant: "Sofort",
        centuries: "Jahrhunderte+",
        year: "J", day: "T", hour: "Std", minute: "Min", second: "Sek",
        copy_fail: "Kopieren fehlgeschlagen",
        pass_copied: "Passwort kopiert",
        user_copied: "Benutzername kopiert",
        code_copied: "2FA-Code kopiert",
        save_fail: "Speichern fehlgeschlagen",
        delete_fail: "Löschen fehlgeschlagen",
        discard_changes_confirm: "Änderungen verwerfen?",
        login_fail: "Ungültiger Benutzername oder Passwort.",
        google_login_fail: "Google-Login fehlgeschlagen: ",
        logout_confirm: "Möchten Sie sich wirklich abmelden?",
        pass_created: "Neues Passwort erstellt",
        pass_updated: "Passwort aktualisiert",
        delete_confirm: "Möchten Sie dieses Passwort wirklich löschen?",
        pass_deleted: "Passwort gelöscht",
        checking: "Prüfen...",
        error: "Fehler aufgetreten",
        safe: "Kein Leck gefunden (Sicher)",
        breach_found: "Gefahr! In {count} Lecks gefunden",
        clear_hist_confirm: "Den gesamten Verlauf für dieses Passwort löschen?",
        hist_cleared: "Verlauf gelöscht",
        clear_gen_confirm: "Den gesamten Generierungsverlauf löschen?",
        gen_cleared: "Generierungsverlauf gelöscht",
        settings_saved: "Einstellungen gespeichert",
        default_user_filled: "Standard-Benutzername ausgefüllt",
        no_default_user: "Kein Standard-Benutzername festgelegt",
        list_sorted: "Liste sortiert",
        data_mgmt: "Datenverwaltung",
        export_json: "Export (JSON)",
        import_json: "Import (JSON)",
        invalid_data: "Ungültiges Datenformat. Import abgebrochen.",
        import_confirm: "{count} Elemente zur aktuellen Liste hinzufügen?",
        import_done: "Import abgeschlossen.",
        file_error: "Datei konnte nicht gelesen werden.",
        history_empty: "Kein Verlauf",
        hist_empty_detail: "Kein Änderungsverlauf.",
        restore_confirm: "Diese Version im Formular wiederherstellen?",
        sort_placeholder: "Sortieren nach...",
        sort_name_asc: "Name (A-Z)",
        sort_name_desc: "Name (Z-A)",
        sort_str_asc: "Stärke (Schwächste)",
        sort_str_desc: "Stärke (Stärkste)",
        sort_date_desc: "Datum (Neueste)",
        sort_date_asc: "Datum (Älteste)",
        language: "Sprache / Language",
        about: "Über",
        theme_color: "Themenfarbe",
        reset: "Zurücksetzen",
        retry: "Wiederholen",
        require_second_auth: "Zusätzliche Authentifizierung nach Google-Login",
        require_auth_on_delete: "Authentifizierung beim Löschen erforderlich",
        require_auth_on_show_copy: "Authentifizierung beim Anzeigen/Kopieren erforderlich",
        send: "Senden",
        version: "Version",
        yes: "Ja",
        no: "Nein",
        ok: "OK"
    },
    fr: {
        app_title: "Soul Password Manager",
        favorites: "Favoris",
        passwords: "Mots de passe",
        login_info: "Infos de connexion",
        notes: "Notes",
        personal_info: "Infos personnelles",
        pass_generator: "Générateur de mot de passe",
        pass_checker: "Vérification de sécurité",
        security_hub: "Centre de sécurité",
        security_score: "Score de sécurité",
        weak_pass_count: "Mots de passe faibles",
        no_2fa_count: "2FA manquant",
        reused_pass_count: "Mots de passe réutilisés",
        security_list_weak: "Liste des mots de passe faibles",
        security_list_no_2fa: "Comptes sans 2FA",
        security_list_reused: "Liste des mots de passe réutilisés",
        score_breakdown: "Détails du score",
        risk_weak: "Faible",
        risk_medium: "Moyen",
        risk_no_2fa: "Pas de 2FA",
        risk_reused: "Réutilisé",
        risk_solution: "Solution",
        advice_weak: "Nous recommandons d'utiliser le générateur pour créer un mot de passe plus fort.",
        advice_medium: "Envisagez de le rendre plus long ou plus complexe.",
        advice_no_2fa: "Activez la 2FA sur le service et enregistrez le secret ici.",
        advice_reused: "Ce mot de passe est utilisé ailleurs. Changez-le pour un unique.",
        trash: "Corbeille",
        trash_empty: "La corbeille est vide",
        empty_trash: "Vider la corbeille",
        selected_count: "{count} sélectionné(s)",
        select_all: "Tout sélectionner",
        delete_selected_confirm: "Supprimer {count} éléments ?",
        restore: "Restaurer",
        delete_permanently: "Supprimer définitivement",
        export_json: "Exporter en JSON",
        import_json: "Importer JSON",
        settings: "Paramètres",
        auto_make: "Générer un mot de passe",
        length: "Longueur",
        uppercase: "Majuscules",
        numbers: "Chiffres",
        symbols: "Symboles",
        copy: "Copier",
        regenerate: "Régénérer",
        gen_history: "Historique",
        clear_history: "Effacer l'historique",
        close: "Fermer",
        pass_check_title: "Vérification de sécurité du mot de passe",
        enter_pass: "Entrez votre mot de passe ici",
        add_pass_title: "Ajouter un nouveau mot de passe",
        placeholder_guide: "Sélectionnez un élément dans la liste pour voir les détails,<br>ou ajoutez un nouveau mot de passe.",
        service_name: "Nom du service",
        category: "Catégorie (Optionnel)",
        website: "URL du site web",
        username: "Nom d'utilisateur / Email",
        password: "Mot de passe",
        totp_secret_opt: "Secret TOTP (Optionnel)",
        cancel: "Annuler",
        save: "Enregistrer",
        detail_title: "Détails du mot de passe",
        totp_secret: "Secret TOTP",
        check_breach: "Vérifier les fuites (HIBP)",
        last_modified: "Dernière modification",
        revision_count: "Révisions",
        show_history: "Afficher l'historique",
        delete: "Supprimer",
        update: "Mettre à jour",
        general: "Général",
        security: "Sécurité",
        default_username: "Nom d'utilisateur par défaut",
        auto_logout: "Déconnexion auto (Minutes)",
        passkey_settings: "Paramètres Passkey (Biométrie)",
        passkey_desc: "Activer la connexion via la biométrie de l'appareil.<br>*Nécessite un navigateur/appareil supportant l'extension Passkey 'largeBlob'.",
        register_passkey: "Enregistrer une Passkey",
        change_master_pass: "Changer le mot de passe maître",
        change_master_pass_confirm: "Êtes-vous sûr de vouloir changer votre mot de passe maître ?",
        login_devices: "Appareils connectés",
        current_device: "Appareil actuel",
        last_access: "Dernier accès : ",
        force_logout: "Déconnexion forcée",
        force_logout_confirm: "Forcer la déconnexion de cet appareil ?",
        device_revoked: "Appareil déconnecté",
        session_expired: "Session expirée ou révoquée.",
        new_login_detected: "Nouvelle connexion détectée depuis {device}",
        security_alert: "Alerte de sécurité",
        send_feedback: "Envoyer des commentaires",
        open_guide: "Guide de l'utilisateur",
        guide_title: "Guide de l'utilisateur",
        guide_step1_title: "1. Enregistrer les mots de passe",
        guide_step1_desc: "Ajoutez de nouveaux mots de passe via le bouton '+'. Vous pouvez également les classer et les marquer comme favoris.",
        guide_tip1: "Astuce : Vous pouvez rechercher des mots de passe par titre ou nom d'utilisateur.",
        guide_step2_title: "2. Générateur de mot de passe",
        guide_step2_desc: "Utilisez l'outil 'Générateur de mot de passe' pour créer automatiquement des mots de passe forts.",
        guide_tip2: "Astuce : Nous recommandons 12 caractères ou plus pour une meilleure sécurité.",
        guide_step3_title: "3. Vérification de sécurité",
        guide_step3_desc: "Le 'Centre de sécurité' détecte les mots de passe faibles ou réutilisés. Vous pouvez également vérifier les fuites de données.",
        guide_tip3: "Astuce : Visez un score de 80 ou plus.",
        guide_step4_title: "4. Gestion des données",
        guide_step4_desc: "Les données sont chiffrées localement. Exportez en JSON depuis les paramètres pour les sauvegardes.",
        guide_tip4: "Astuce : Conservez votre fichier exporté dans un endroit sûr.",
        guide_step5_title: "5. Paramètres et personnalisation",
        guide_step5_desc: "Changez la langue, activez le mode sombre et réglez la minuterie de déconnexion automatique dans les paramètres.",
        guide_tip5: "Astuce : Activez la biométrie pour un accès plus rapide et sécurisé.",
        include_logs: "Inclure les journaux et erreurs de l'application",
        feedback_desc: "Faites-nous part de vos commentaires ou signalez des bugs.",
        feedback_message: "Message",
        feedback_sent: "Commentaires envoyés. Merci !",
        unknown_device: "Appareil inconnu",
        current_pass: "Mot de passe actuel",
        new_pass: "Nouveau mot de passe",
        confirm_new_pass: "Confirmer le nouveau mot de passe",
        danger_zone: "Zone de danger",
        delete_all_desc: "Supprimer tous les mots de passe et paramètres, et réinitialiser l'application.",
        delete_all_data: "Supprimer toutes les données",
        setup_title: "Configuration initiale",
        setup_desc: "Définissez votre nom d'utilisateur et mot de passe maître.",
        master_pass: "Mot de passe maître",
        confirm_pass: "Confirmer le mot de passe",
        setup_btn: "Configurer",
        login_title: "Connexion",
        biometric_login: "Connexion biométrique",
        google_login: "Connexion avec Google",
        login_btn: "Connexion",
        warning_title: "Ver 26.01.10 (Unstable)",
        warning_h1: "Ceci est une version de DÉMO.",
        warning_desc: "Conçu pour les développeurs, il peut ne pas fonctionner comme prévu et manque de fonctionnalités de sécurité/confidentialité suffisantes.",
        warning_h2: "Honnêtement, ce n'est pas prêt pour la production.<br><br>Nous recommandons fortement d'autres gestionnaires de mots de passe.",
        warning_rec: "Recommandé : Bitwarden, Proton Pass, KeePass",
        warning_not_rec: "Non recommandé : Cette application, Papier",
        search_placeholder: "Rechercher...",
        select_mode: "Mode sélection",
        sort: "Trier",
        toggle_theme: "Changer de thème",
        logout: "Déconnexion",
        empty_state_title: "Pas encore de mots de passe",
        empty_state_desc: "Appuyez sur le bouton + pour en ajouter un.",
        fav_added: "Ajouté aux favoris",
        fav_removed: "Retiré des favoris",
        copy_password: "Copier le mot de passe",
        copy_username: "Copier le nom d'utilisateur",
        edit: "Modifier",
        decryption_fail: "Échec du déchiffrement",
        passkey_fallback_confirm: "Cet appareil ne prend pas en charge l'enregistrement de données sur Passkey (largeBlob).\nVoulez-vous enregistrer les identifiants dans le stockage local ?\n*Attention : Le niveau de sécurité sera réduit.",
        passkey_fallback_saved: "Passkey enregistré (Sauvegardé dans le stockage local)",
        passkey_fallback_login: "Connexion biométrique réussie (Stockage local)",
        passkey_not_supported_cancel: "Annulé en raison de l'absence de prise en charge de largeBlob.",
        
        // JS Strings
        weak: "Mot de passe faible",
        medium: "Mot de passe moyen",
        strong: "Mot de passe fort",
        crack_time: "Temps de craquage estimé : ",
        instant: "Instantané",
        centuries: "Siècles+",
        year: "an", day: "j", hour: "h", minute: "m", second: "s",
        copy_fail: "Échec de la copie",
        pass_copied: "Mot de passe copié",
        user_copied: "Nom d'utilisateur copié",
        code_copied: "Code 2FA copié",
        save_fail: "Échec de l'enregistrement",
        delete_fail: "Échec de la suppression",
        discard_changes_confirm: "Ignorer les modifications ?",
        login_fail: "Nom d'utilisateur ou mot de passe invalide.",
        google_login_fail: "Échec de la connexion Google : ",
        logout_confirm: "Êtes-vous sûr de vouloir vous déconnecter ?",
        pass_created: "Nouveau mot de passe créé",
        pass_updated: "Mot de passe mis à jour",
        delete_confirm: "Êtes-vous sûr de vouloir supprimer ce mot de passe ?",
        pass_deleted: "Mot de passe supprimé",
        checking: "Vérification...",
        error: "Une erreur est survenue",
        safe: "Aucune fuite trouvée (Sûr)",
        breach_found: "Danger ! Trouvé dans {count} fuites",
        clear_hist_confirm: "Supprimer tout l'historique pour ce mot de passe ?",
        hist_cleared: "Historique effacé",
        clear_gen_confirm: "Supprimer tout l'historique de génération ?",
        gen_cleared: "Historique de génération effacé",
        settings_saved: "Paramètres enregistrés",
        default_user_filled: "Nom d'utilisateur par défaut rempli",
        no_default_user: "Aucun nom d'utilisateur par défaut défini",
        list_sorted: "Liste triée",
        data_mgmt: "Gestion des données",
        export_json: "Exporter (JSON)",
        import_json: "Importer (JSON)",
        invalid_data: "Format de données invalide. Importation annulée.",
        import_confirm: "Ajouter {count} éléments à la liste actuelle ?",
        import_done: "Importation terminée.",
        file_error: "Échec de la lecture du fichier.",
        history_empty: "Aucun historique",
        hist_empty_detail: "Aucun historique de modification.",
        restore_confirm: "Restaurer cette version dans le formulaire ?",
        sort_placeholder: "Trier par...",
        sort_name_asc: "Nom (A-Z)",
        sort_name_desc: "Nom (Z-A)",
        sort_str_asc: "Force (Plus faible)",
        sort_str_desc: "Force (Plus fort)",
        sort_date_desc: "Date (Plus récent)",
        sort_date_asc: "Date (Plus ancien)",
        language: "Langue / Language",
        about: "À propos",
        theme_color: "Couleur du thème",
        reset: "Réinitialiser",
        retry: "Réessayer",
        require_second_auth: "Exiger une auth. supplémentaire après Google",
        require_auth_on_delete: "Exiger une auth. lors de la suppression",
        require_auth_on_show_copy: "Exiger une auth. pour afficher/copier",
        send: "Envoyer",
        version: "Version",
        yes: "Oui",
        no: "Non",
        ok: "OK"
    },
    it: {
        app_title: "Soul Password Manager",
        favorites: "Preferiti",
        passwords: "Password",
        login_info: "Info Accesso",
        notes: "Note",
        personal_info: "Info Personali",
        pass_generator: "Generatore Password",
        pass_checker: "Controllo Sicurezza",
        security_hub: "Hub di Sicurezza",
        security_score: "Punteggio di Sicurezza",
        weak_pass_count: "Password Deboli",
        no_2fa_count: "2FA Mancante",
        reused_pass_count: "Password Riutilizzate",
        security_list_weak: "Lista Password Deboli",
        security_list_no_2fa: "Account Senza 2FA",
        security_list_reused: "Lista Password Riutilizzate",
        score_breakdown: "Dettagli Punteggio",
        risk_weak: "Debole",
        risk_medium: "Media",
        risk_no_2fa: "No 2FA",
        risk_reused: "Riutilizzata",
        risk_solution: "Soluzione",
        advice_weak: "Si consiglia di utilizzare il generatore per creare una password più forte.",
        advice_medium: "Considera di renderla più lunga o complessa.",
        advice_no_2fa: "Abilita 2FA sul servizio e salva il segreto qui.",
        advice_reused: "Questa password è usata altrove. Cambiala con una unica.",
        trash: "Cestino",
        trash_empty: "Il cestino è vuoto",
        empty_trash: "Svuota Cestino",
        selected_count: "{count} Selezionati",
        select_all: "Seleziona Tutto",
        delete_selected_confirm: "Eliminare {count} elementi?",
        restore: "Ripristina",
        delete_permanently: "Elimina Definitivamente",
        export_json: "Esporta come JSON",
        import_json: "Importa JSON",
        settings: "Impostazioni",
        auto_make: "Genera Password",
        length: "Lunghezza",
        uppercase: "Maiuscole",
        numbers: "Numeri",
        symbols: "Simboli",
        copy: "Copia",
        regenerate: "Rigenera",
        gen_history: "Cronologia",
        clear_history: "Cancella Cronologia",
        close: "Chiudi",
        pass_check_title: "Controllo Sicurezza Password",
        enter_pass: "Inserisci qui la tua password",
        add_pass_title: "Aggiungi Nuova Password",
        placeholder_guide: "Seleziona un elemento dall'elenco per visualizzare i dettagli,<br>o aggiungi una nuova password.",
        service_name: "Nome Servizio",
        category: "Categoria (Opzionale)",
        website: "URL Sito Web",
        username: "Nome Utente / Email",
        password: "Password",
        totp_secret_opt: "Segreto TOTP (Opzionale)",
        cancel: "Annulla",
        save: "Salva",
        detail_title: "Dettagli Password",
        totp_secret: "Segreto TOTP",
        check_breach: "Controlla Violazioni (HIBP)",
        last_modified: "Ultima Modifica",
        revision_count: "Revisioni",
        show_history: "Mostra Cronologia",
        delete: "Elimina",
        update: "Aggiorna",
        general: "Generale",
        security: "Sicurezza",
        default_username: "Nome Utente Predefinito",
        auto_logout: "Logout Automatico (Minuti)",
        passkey_settings: "Impostazioni Passkey (Biometria)",
        passkey_desc: "Abilita l'accesso usando la biometria del dispositivo.<br>*Richiede supporto browser/dispositivo per estensione Passkey 'largeBlob'.",
        register_passkey: "Registra Passkey",
        change_master_pass: "Cambia Password Master",
        change_master_pass_confirm: "Sei sicuro di voler cambiare la tua password master?",
        login_devices: "Dispositivi Connessi",
        current_device: "Dispositivo Attuale",
        last_access: "Ultimo Accesso: ",
        force_logout: "Logout Forzato",
        force_logout_confirm: "Forzare il logout di questo dispositivo?",
        device_revoked: "Dispositivo disconnesso",
        session_expired: "Sessione scaduta o revocata.",
        new_login_detected: "Nuovo accesso rilevato da {device}",
        security_alert: "Avviso di sicurezza",
        send_feedback: "Invia Feedback",
        open_guide: "Guida Utente",
        guide_title: "Guida Utente",
        guide_step1_title: "1. Salvare Password",
        guide_step1_desc: "Aggiungi nuove password tramite il pulsante '+'. Puoi anche classificarle e segnarle come preferite.",
        guide_tip1: "Suggerimento: Puoi cercare le password per titolo o nome utente.",
        guide_step2_title: "2. Generatore Password",
        guide_step2_desc: "Usa lo strumento 'Generatore Password' per creare automaticamente password forti e difficili da indovinare.",
        guide_tip2: "Suggerimento: Consigliamo 12 caratteri o più per una maggiore sicurezza.",
        guide_step3_title: "3. Controllo Sicurezza",
        guide_step3_desc: "L'Hub di Sicurezza rileva password deboli o riutilizzate. Puoi anche controllare le violazioni dei dati.",
        guide_tip3: "Suggerimento: Punta a un punteggio di 80 o superiore.",
        guide_step4_title: "4. Gestione Dati",
        guide_step4_desc: "I dati sono crittografati localmente. Esporta come JSON dalle Impostazioni per backup o migrazione.",
        guide_tip4: "Suggerimento: Conserva il file esportato in un luogo sicuro.",
        guide_step5_title: "5. Impostazioni e Personalizzazione",
        guide_step5_desc: "Cambia lingua, attiva la modalità scura e imposta il timer di logout automatico dalle Impostazioni.",
        guide_tip5: "Suggerimento: Abilita la biometria per un accesso più rapido e sicuro.",
        include_logs: "Includi log app e info errori",
        feedback_desc: "Facci sapere cosa ne pensi o segnala bug.",
        feedback_message: "Messaggio",
        feedback_sent: "Feedback inviato. Grazie!",
        unknown_device: "Dispositivo Sconosciuto",
        current_pass: "Password Attuale",
        new_pass: "Nuova Password",
        confirm_new_pass: "Conferma Nuova Password",
        danger_zone: "Zona Pericolosa",
        delete_all_desc: "Elimina tutte le password e impostazioni, e resetta l'app.",
        delete_all_data: "Elimina Tutti i Dati",
        setup_title: "Configurazione Iniziale",
        setup_desc: "Imposta il tuo nome utente e password master.",
        master_pass: "Password Master",
        confirm_pass: "Conferma Password",
        setup_btn: "Configura",
        login_title: "Accedi",
        biometric_login: "Accedi con Biometria",
        google_login: "Accedi con Google",
        login_btn: "Accedi",
        warning_title: "Ver 26.01.10 (Unstable)",
        warning_h1: "Questa è una versione DEMO.",
        warning_desc: "Progettata per sviluppatori, potrebbe non funzionare come previsto e manca di sufficienti funzionalità di sicurezza/privacy.",
        warning_h2: "Onestamente, non è pronta per la produzione.<br><br>Raccomandiamo vivamente altri gestori di password.",
        warning_rec: "Consigliati: Bitwarden, Proton Pass, KeePass",
        warning_not_rec: "Non consigliati: Questa app, Carta",
        search_placeholder: "Cerca...",
        select_mode: "Modalità Selezione",
        sort: "Ordina",
        toggle_theme: "Cambia Tema",
        logout: "Esci",
        empty_state_title: "Nessuna password",
        empty_state_desc: "Tocca il pulsante + per aggiungerne una.",
        fav_added: "Aggiunto ai preferiti",
        fav_removed: "Rimosso dai preferiti",
        copy_password: "Copia Password",
        copy_username: "Copia Nome Utente",
        edit: "Modifica",
        decryption_fail: "Decrittazione fallita",
        passkey_fallback_confirm: "Questo dispositivo non supporta il salvataggio dei dati su Passkey (largeBlob).\nVuoi salvare le credenziali nella memoria locale?\n*Attenzione: Il livello di sicurezza sarà ridotto.",
        passkey_fallback_saved: "Passkey registrata (Salvata nella memoria locale)",
        passkey_fallback_login: "Accesso con biometria (Memoria locale)",
        passkey_not_supported_cancel: "Annullato per mancanza di supporto largeBlob.",
        
        // JS Strings
        weak: "Password Debole",
        medium: "Password Media",
        strong: "Password Forte",
        crack_time: "Tempo Stimato Cracking: ",
        instant: "Istantaneo",
        centuries: "Secoli+",
        year: "a", day: "g", hour: "o", minute: "m", second: "s",
        copy_fail: "Copia fallita",
        pass_copied: "Password copiata",
        user_copied: "Nome utente copiato",
        code_copied: "Codice 2FA copiato",
        save_fail: "Salvataggio fallito",
        delete_fail: "Eliminazione fallita",
        discard_changes_confirm: "Ignorare le modifiche?",
        login_fail: "Nome utente o password non validi.",
        google_login_fail: "Login Google fallito: ",
        logout_confirm: "Sei sicuro di voler uscire?",
        pass_created: "Nuova password creata",
        pass_updated: "Password aggiornata",
        delete_confirm: "Sei sicuro di voler eliminare questa password?",
        pass_deleted: "Password eliminata",
        checking: "Controllo...",
        error: "Errore verificato",
        safe: "Nessuna violazione trovata (Sicuro)",
        breach_found: "Pericolo! Trovata in {count} violazioni",
        clear_hist_confirm: "Eliminare tutta la cronologia per questa password?",
        hist_cleared: "Cronologia cancellata",
        clear_gen_confirm: "Eliminare tutta la cronologia di generazione?",
        gen_cleared: "Cronologia generazione cancellata",
        settings_saved: "Impostazioni salvate",
        default_user_filled: "Nome utente predefinito inserito",
        no_default_user: "Nessun nome utente predefinito impostato",
        list_sorted: "Lista ordinata",
        data_mgmt: "Gestione Dati",
        export_json: "Esporta (JSON)",
        import_json: "Importa (JSON)",
        invalid_data: "Formato dati non valido. Importazione annullata.",
        import_confirm: "Aggiungere {count} elementi alla lista corrente?",
        import_done: "Importazione completata.",
        file_error: "Impossibile leggere il file.",
        history_empty: "Nessuna cronologia",
        hist_empty_detail: "Nessuna cronologia modifiche.",
        restore_confirm: "Ripristinare questa versione nel modulo?",
        sort_placeholder: "Ordina per...",
        sort_name_asc: "Nome (A-Z)",
        sort_name_desc: "Nome (Z-A)",
        sort_str_asc: "Forza (Più debole)",
        sort_str_desc: "Forza (Più forte)",
        sort_date_desc: "Data (Più recente)",
        sort_date_asc: "Data (Più vecchia)",
        language: "Lingua / Language",
        about: "Informazioni",
        theme_color: "Colore Tema",
        reset: "Reimposta",
        retry: "Riprova",
        require_second_auth: "Richiedi auth extra dopo login Google",
        require_auth_on_delete: "Richiedi auth per eliminazione",
        require_auth_on_show_copy: "Richiedi auth per mostra/copia",
        send: "Invia",
        version: "Versione",
        yes: "Sì",
        no: "No",
        ok: "OK"
    }
};

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
        localStorage.setItem(CONSTANTS.STORAGE.CLOUD_KEY, JSON.stringify(exported));
    } catch (e) { console.error("Failed to save key", e); }
}

async function loadCloudKey() {
    try {
        const json = localStorage.getItem(CONSTANTS.STORAGE.CLOUD_KEY);
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
    localStorage.removeItem(CONSTANTS.STORAGE.CLOUD_KEY);
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

async function getHybridKeys(uid) {
    if (hybridKeyPair) return hybridKeyPair;

    const userConfigRef = doc(db, "user_config", uid);
    const snap = await getDoc(userConfigRef);
    
    // KEK derived from Master Password (cloudKey)
    const kek = await getCloudCryptoKey();
    
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
      return t('decryption_fail');
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
      return t('decryption_fail');
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

async function promptForMasterPassword(returnPassword = false, checkUser = null) {
    return new Promise((resolve) => {
        const dialog = document.createElement('m3e-dialog');
        
        const header = document.createElement('span');
        header.slot = 'header';
        header.textContent = t('confirm_pass');
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

function calculatePasswordStrength(password) {
    if (!password) return 0;
    // zxcvbn returns a score from 0 (weak) to 4 (very strong)
    const result = zxcvbn(password);
    return result.score;
}

function getStrengthInfo(password) {
    const strength = calculatePasswordStrength(password);
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

function updateStrengthView(password, resultElId, barElId, crackTimeElId) {
    const info = getStrengthInfo(password);
    
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
        crackTimeEl.textContent = password ? calculateCrackTime(password) : '';
    }
}

function calculateCrackTime(password) {
    if (!password) return '';
    const result = zxcvbn(password);
    // Use offline_slow_hashing_1e4_per_second for a conservative estimate (e.g. master password cracking)
    const seconds = result.crack_times_seconds.offline_slow_hashing_1e4_per_second;

    let timeString = '一瞬';
    if (seconds >= 31536000 * 100) timeString = '数世紀以上';
    else if (seconds >= 31536000) timeString = Math.floor(seconds / 31536000) + t('year');
    else if (seconds >= 86400) timeString = Math.floor(seconds / 86400) + t('day');
    else if (seconds >= 3600) timeString = Math.floor(seconds / 3600) + t('hour');
    else if (seconds >= 60) timeString = Math.floor(seconds / 60) + t('minute');
    else if (seconds >= 1) timeString = Math.floor(seconds) + t('second');

    return t('crack_time') + (timeString === '一瞬' || timeString === '数世紀以上' ? t(timeString === '一瞬' ? 'instant' : 'centuries') : timeString);
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

async function savePasskeyFallback(password) {
    const key = await getFallbackKey();
    const encrypted = await encryptLocal(password, key);
    localStorage.setItem(CONSTANTS.STORAGE.PASSKEY_FALLBACK, encrypted);
}

async function loadPasskeyFallback() {
    const encrypted = localStorage.getItem(CONSTANTS.STORAGE.PASSKEY_FALLBACK);
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
        showAlertDialog("このブラウザはPasskeyをサポートしていません。");
        return;
    }

    // We need the plaintext password to store it in the largeBlob.
    // Since we don't keep it in memory, we must ask the user.
    const password = prompt("Passkeyに保存するため、現在のマスターパスワードを入力してください:");
    if (!password) return;

    // Verify password first
    const masterAuth = JSON.parse(localStorage.getItem(CONSTANTS.STORAGE.MASTER_AUTH));
    if (masterAuth) {
        const hash = await hashPassword(password, masterAuth.salt);
        if (hash !== masterAuth.hash) {
            showAlertDialog("パスワードが間違っています。");
            return;
        }
    }

    try {
        showSnackbar("生体認証/PINを入力して登録してください...");
        
        // 1. Create Credential
        const userId = new Uint8Array(16);
        window.crypto.getRandomValues(userId);

        const publicKeyCredentialCreationOptions = {
            challenge: window.crypto.getRandomValues(new Uint8Array(32)),
            rp: { name: "Soul Password Manager", id: window.location.hostname },
            user: { id: userId, name: masterAuth.username, displayName: masterAuth.username },
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

        // 2. Write Password to Large Blob (requires a separate assertion immediately after creation)
        const passwordBuffer = strToBuffer(password);
        const assertionOptions = {
            challenge: window.crypto.getRandomValues(new Uint8Array(32)),
            rpId: window.location.hostname,
            allowCredentials: [{ id: credential.rawId, type: 'public-key' }],
            userVerification: "required",
            extensions: { largeBlob: { write: passwordBuffer } }
        };

        const assertion = await navigator.credentials.get({ publicKey: assertionOptions });
        const extResults = assertion.getClientExtensionResults();
        if (extResults.largeBlob && extResults.largeBlob.written) {
            showSnackbar("Passkeyを登録しました。");
        } else {
            throw new Error("データの保存に失敗しました (largeBlob not written)");
        }

    } catch (e) {
        console.error(e);
        showAlertDialog("Passkeyの登録に失敗しました: " + e.message);
    }
}

async function loginWithPasskey() {
    if (!window.PublicKeyCredential) return;

    try {
        const assertionOptions = {
            challenge: window.crypto.getRandomValues(new Uint8Array(32)),
            rpId: window.location.hostname,
            userVerification: "required",
            extensions: { largeBlob: { read: true } }
        };

        const assertion = await navigator.credentials.get({ publicKey: assertionOptions });
        const extResults = assertion.getClientExtensionResults();

        if (extResults.largeBlob && extResults.largeBlob.blob) {
            const password = bufferToStr(extResults.largeBlob.blob);
            const masterAuth = JSON.parse(localStorage.getItem(CONSTANTS.STORAGE.MASTER_AUTH));
            
            // Use the retrieved password to login
            appKey = await deriveKey(password, masterAuth.salt);
            document.getElementById('login_dialog').open = false;
            initLocalApp();
            showSnackbar("生体認証でログインしました");
        } else {
            // Try fallback
            const fallbackPassword = await loadPasskeyFallback();
            if (fallbackPassword) {
                const masterAuth = JSON.parse(localStorage.getItem(CONSTANTS.STORAGE.MASTER_AUTH));
                appKey = await deriveKey(fallbackPassword, masterAuth.salt);
                document.getElementById('login_dialog').open = false;
                initLocalApp();
                showSnackbar(t('passkey_fallback_login'));
            } else {
                showAlertDialog("Passkeyからデータを読み取れませんでした。");
            }
        }
    } catch (e) {
        console.error(e);
        showSnackbar("認証キャンセルまたはエラー: " + e.message);
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

function applyThemeColor(color) {
    const root = document.documentElement;
    const rgb = hexToRgb(color);
    if (!rgb) return;

    // Update primary color variables
    root.style.setProperty('--md-sys-color-primary', color);
    
    // Generate container/on-colors (simplified logic for demo)
    // In a real Material 3 implementation, we would use a tonal palette generator.
    // Here we just adjust opacity/lightness for containers.
    
    // Primary Container (Lighter version of primary)
    const containerColor = `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, 0.2)`;
    // On Primary Container (Darker version of primary)
    // For simplicity, we keep using the primary color or a dark variant for text on container
    
    // We need to be careful about dark mode.
    // The CSS variables are redefined in .dark-theme.
    // To support custom colors in both modes properly without a full palette generator,
    // we will just override the main primary color which is the most visible one.
    // More complex theming would require updating all related tokens.
    
    // For this implementation, we will update:
    // --md-sys-color-primary
    // --md-sys-color-primary-container (approx)
    
    // Note: This simple override might not have perfect contrast in all cases.
    
    // Update UI input
    const input = document.getElementById('setting_theme_color');
    const label = document.getElementById('theme_color_value');
    if (input) input.value = color;
    if (label) label.textContent = color;

    // Save
    localStorage.setItem(CONSTANTS.STORAGE.THEME_COLOR, color);
    
    // Update meta theme-color
    document.querySelector('meta[name="theme-color"]').setAttribute('content', color);
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
    if (!currentDetailId) return false;
    const item = savedPasswords.find(p => p.id === currentDetailId);
    if (!item) return false;

    const currentTitle = document.getElementById('detail_pass_title').value;
    const currentCategory = document.getElementById('detail_pass_category').value;
    const currentWebsite = document.getElementById('detail_pass_website').value;
    const currentUsername = document.getElementById('detail_pass_username').value;
    const currentValue = document.getElementById('detail_pass_value').value;
    const currentSecret = document.getElementById('detail_pass_secret').value;
    const isFavorite = document.getElementById('detail_pass_favorite_btn').querySelector('m3e-icon').name === 'star';

    return (
        currentTitle !== (item.title || '') ||
        currentCategory !== (item.category || '') ||
        currentWebsite !== (item.website || '') ||
        currentUsername !== (item.username || '') ||
        currentValue !== (item.password || '') ||
        currentSecret !== (item.secret || '') ||
        isFavorite !== (item.favorite || false)
    );
}

function checkDetailChanges() {
    const updateBtn = document.getElementById('update_password_btn');
    if (updateBtn) updateBtn.disabled = !hasDetailChanges();
}

function openDetailDialog(item) {
    currentDetailId = item.id;
    const dialog = document.getElementById('detail_password_dialog');
    
    document.getElementById('detail_pass_title').value = item.title || '';
    document.getElementById('detail_pass_category').value = item.category || '';
    document.getElementById('detail_pass_website').value = item.website || '';
    document.getElementById('detail_pass_username').value = item.username || '';
    document.getElementById('detail_pass_value').value = item.password || '';
    document.getElementById('detail_pass_secret').value = item.secret || '';
    
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

    updateDetailStrength(item.password || '');
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
            
            div.innerHTML = `
                <div style="display:flex; align-items:center; gap:12px; width:100%;">
                    <m3e-icon name="${iconName}" style="font-size:24px; color:var(--md-sys-color-secondary);"></m3e-icon>
                    <div style="flex:1;">
                        <div class="font-bold" style="display:flex; align-items:center; gap:8px;">
                            ${device.deviceName || t('unknown_device')}
                            ${isCurrent ? `<span class="bg-strong" style="color:white; padding:2px 6px; border-radius:4px; font-size:10px;">${t('current_device')}</span>` : ''}
                        </div>
                        <div class="text-small text-secondary" style="word-break: break-all; display: -webkit-box; -webkit-line-clamp: 1; -webkit-box-orient: vertical; overflow: hidden;">${device.userAgent}</div>
                        <div class="text-small text-secondary">${t('last_access')}${new Date(device.lastLogin).toLocaleString()}</div>
                    </div>
                    ${!isCurrent ? `<m3e-icon-button class="revoke-btn" title="${t('force_logout')}"><m3e-icon name="logout" class="color-error"></m3e-icon></m3e-icon-button>` : ''}
                </div>
            `;
            
            if (!isCurrent) {
                div.querySelector('.revoke-btn').addEventListener('click', () => {
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
            }
            
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

        const strengthClass = getStrengthInfo(item.password).strengthClass;
        if (icon.tagName.toLowerCase() === 'm3e-icon' && icon.name === 'key') {
            icon.classList.add(strengthClass);
        }

        const label = document.createElement('div');
        label.slot = 'label';
        label.className = 'nav-item-label-container';

        const titleSpan = document.createElement('span');
        titleSpan.textContent = item.title;
        titleSpan.className = 'nav-item-title ' + strengthClass;
        label.appendChild(titleSpan);

        if (item.category) {
            const catSpan = document.createElement('span');
            catSpan.className = 'category-badge';
            catSpan.textContent = item.category;
            label.appendChild(catSpan);
        }

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
            await saveOrUpdateItem(item);
        });
        newItem.appendChild(favBtn);

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
        
        div.innerHTML = `
            <div style="flex:1">
                <div class="font-bold">${item.title}</div>
                <div class="text-small text-secondary">${new Date(item.deletedAt).toLocaleString()}</div>
            </div>
            <div style="display:flex; gap:8px;">
                <m3e-icon-button class="restore-btn" title="${t('restore')}"><m3e-icon name="restore_from_trash"></m3e-icon></m3e-icon-button>
                <m3e-icon-button class="delete-forever-btn" title="${t('delete_permanently')}"><m3e-icon name="delete_forever" style="color:var(--md-sys-color-error)"></m3e-icon></m3e-icon-button>
            </div>
        `;

        div.querySelector('.restore-btn').addEventListener('click', () => restoreItem(item.id));
        div.querySelector('.delete-forever-btn').addEventListener('click', () => {
            showConfirmDialog(t('delete_confirm')).then(async res => {
                if (res) {
                    const verified = await verifyDestructiveAction();
                    if (verified) permanentDeleteItem(item.id);
                }
            });
        });

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
    console.log("Sync initialized for user:", user.uid);
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
        console.log("User logged in:", user.email);
        
        const requireSecondAuth = localStorage.getItem(CONSTANTS.STORAGE.REQUIRE_SECOND_AUTH) === 'true';
        
        if (!requireSecondAuth) {
            cloudKey = await loadCloudKey();
        }

        if (!cloudKey) {
            const password = await promptForMasterPassword(true, user);
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

        if (user !== masterAuth.username) {
             showAlertDialog(t('login_fail'));
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
        showAlertDialog(t('login_fail'));
    });

    // Biometric Login
    document.getElementById('biometric_login_btn')?.addEventListener('click', loginWithPasskey);
    document.getElementById('setup_passkey_btn')?.addEventListener('click', registerPasskey);

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
            document.getElementById('add_password_dialog').open = false;
            showSnackbar(t('pass_created'));
        }
    });

    document.getElementById('new_pass_value')?.addEventListener('input', (e) => {
        updateStrengthView(e.target.value, null, 'new_pass_strength_bar', null);
    });

    // Update Password
    document.getElementById('update_password_btn')?.addEventListener('click', async () => {
        if (currentDetailId) {
            const title = document.getElementById('detail_pass_title').value;
            if (title) {
                const oldItem = savedPasswords.find(p => p.id === currentDetailId);
                if (!oldItem) return;

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

                await saveOrUpdateItem(newItem);
                
                if (!isTwoPaneMode) {
                    document.getElementById('detail_password_dialog').open = false;
                }
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
        renderPasswordList(e.target.value);
    });

    // Detail Dialog Events
    document.getElementById('detail_password_dialog')?.addEventListener('closed', () => {
        stopTOTPUpdate();
        if (!isTwoPaneMode) {
            document.getElementById('detail_pass_value').value = '';
            document.getElementById('detail_pass_secret').value = '';
        }
    });

    document.getElementById('add_password_dialog')?.addEventListener('closed', () => {
        // Clear sensitive fields from DOM when dialog closes
        document.getElementById('new_pass_value').value = '';
        document.getElementById('new_pass_secret').value = '';
        updateStrengthView('', null, 'new_pass_strength_bar', null);
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

    document.getElementById('detail_pass_favorite_btn')?.addEventListener('click', function() {
        const icon = this.querySelector('m3e-icon');
        if (icon.name === 'star') {
            icon.name = 'star_border';
            icon.style.color = '';
        } else {
            icon.name = 'star';
            icon.style.color = '#fbc02d';
        }
        checkDetailChanges();
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

    // Update Master Password
    document.getElementById('update_master_pass_btn')?.addEventListener('click', async () => {
        const currentPass = document.getElementById('setting_current_pass').value;
        const newPass = document.getElementById('setting_new_pass').value;
        const confirmPass = document.getElementById('setting_new_pass_confirm').value;

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

                showSnackbar("Updating cloud data...");
                
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
        'login_password', 'setting_current_pass', 'setting_new_pass', 'setting_new_pass_confirm',
        'new_pass_secret', 'detail_pass_secret'
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
                                importedData.forEach(item => {
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

    // Layout handling
    window.addEventListener('resize', updateLayout);
    updateLayout(); // Initial check
});
