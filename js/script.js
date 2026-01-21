// Import Firebase SDKs
import { initializeApp } from "firebase/app";
import { getAuth, signInWithPopup, GoogleAuthProvider, signOut, onAuthStateChanged } from "firebase/auth";
import { getFirestore, collection, addDoc, query, where, onSnapshot, doc, updateDoc, deleteDoc, enableIndexedDbPersistence } from "firebase/firestore";

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
        LANGUAGE: 'soul_language'
    }
};

const CRYPTO_CONFIG = {
    PBKDF2_ITERATIONS: 600000,
    SALT_LENGTH: 16,
    IV_LENGTH: 12
};

let appKey = null; // Session key for Local Mode
let savedPasswords = []; // In-memory list of decrypted passwords
let currentDetailId = null; // ID of currently opened item
let currentUser = null; // Firebase User
let dragSrcEl = null; // For Drag and Drop
let historyDebounceTimer = null; // Timer for debouncing history saves
let autoLogoutTimer = null; // Timer for auto logout
let currentLang = 'ja'; // Default language

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
        restore: "復元",
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
        restore: "Restore",
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
        restore: "恢复",
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
        restore: "복원",
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
        restore: "Wiederherstellen",
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
        restore: "Restaurer",
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
        restore: "Ripristina",
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

// --- Crypto Utilities (Cloud Mode - Demo/Fixed Key) ---
// Uses a fixed salt/key to allow multi-device sync without complex key exchange in this demo.
async function getCloudCryptoKey() {
    let keyMaterial = "SoulPasswordManagerDemoKey";
    if (currentUser && currentUser.uid) {
        keyMaterial += currentUser.uid;
    }
    const rawKey = new TextEncoder().encode(keyMaterial); 
    const keyHash = await window.crypto.subtle.digest('SHA-256', rawKey);
    return window.crypto.subtle.importKey(
      "raw",
      keyHash,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
}

async function encryptCloud(plaintext) {
    if (!plaintext) return "";
    try {
      const key = await getCloudCryptoKey();
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(plaintext);
      const ciphertext = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encoded
      );
      const combined = new Uint8Array(iv.length + ciphertext.byteLength);
      combined.set(iv);
      combined.set(new Uint8Array(ciphertext), iv.length);
      return arrayBufferToBase64(combined);
    } catch (e) {
      console.error("Cloud Encryption failed:", e);
      return plaintext;
    }
}

async function decryptCloud(encryptedBase64) {
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
      return encryptedBase64;
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
            authenticatorSelection: { authenticatorAttachment: "platform", requireResidentKey: true, userVerification: "required" },
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

        await navigator.credentials.get({ publicKey: assertionOptions });
        showSnackbar("Passkeyを登録しました。");

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
            showAlertDialog("Passkeyからデータを読み取れませんでした。");
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

    // Clear lists
    favList.querySelectorAll('m3e-nav-menu-item').forEach(item => item.remove());
    
    // Remove dynamic groups
    const groups = navMenu.querySelectorAll('m3e-nav-menu-item-group:not(#favorite_list)');
    groups.forEach(g => g.remove());

    const categories = {};
    const categoryNames = new Set();

    savedPasswords.forEach((item, index) => {
        if (filterText && !item.title.toLowerCase().includes(filterText.toLowerCase()) && 
            !(item.website || '').toLowerCase().includes(filterText.toLowerCase())) {
            return;
        }

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

    // Create groups
    Object.keys(categories).sort().forEach(catName => {
        const group = document.createElement('m3e-nav-menu-item-group');
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
    
    // Drag and Drop logic (simplified for module)
    newItem.draggable = true;
    newItem.dataset.index = index;
    newItem.addEventListener('dragstart', handleDragStart);
    newItem.addEventListener('dragover', handleDragOver);
    newItem.addEventListener('dragleave', handleDragLeave);
    newItem.addEventListener('drop', handleDrop);
    newItem.addEventListener('dragend', handleDragEnd);
    
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

    const label = document.createElement('span');
    label.slot = 'label';
    label.textContent = item.title;
    label.classList.add(strengthClass);

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
    newItem.addEventListener('click', function() {
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
        dialog.open = true;
    });

    listGroup.appendChild(newItem);
}

// --- Storage Operations (Unified) ---

async function saveOrUpdateItem(item) {
    if (currentUser) {
        // Cloud Mode
        try {
            const encryptedPassword = await encryptCloud(item.password);
            const dataToSave = {
                uid: currentUser.uid,
                title: item.title,
                category: item.category,
                website: item.website,
                username: item.username,
                password: encryptedPassword,
                secret: item.secret,
                favorite: item.favorite,
                lastModified: item.lastModified,
                history: item.history || []
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

async function deleteItem(index) {
    if (currentUser) {
        const item = savedPasswords[index];
        if (item && item.id) {
            try {
                await deleteDoc(doc(db, "passwords", item.id));
                // onSnapshot updates UI
            } catch (e) {
                console.error("Error deleting from cloud:", e);
                showSnackbar(t('delete_fail'));
            }
        }
    } else {
        savedPasswords.splice(index, 1);
        await savePasswordsData();
        renderPasswordList(document.getElementById('fld').value);
    }
}

// --- Initialization & Auth ---

function initFirestoreSync(user) {
    console.log("Sync initialized for user:", user.uid);
    const q = query(collection(db, "passwords"), where("uid", "==", user.uid));
    
    onSnapshot(q, async (querySnapshot) => {
        const newPasswords = [];
        for (const doc of querySnapshot.docs) {
            const data = doc.data();
            const decryptedPassword = await decryptCloud(data.password);
            newPasswords.push({
                id: doc.id,
                ...data,
                password: decryptedPassword
            });
        }
        savedPasswords = newPasswords;
        renderPasswordList(document.getElementById('fld').value);
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
onAuthStateChanged(auth, (user) => {
    if (user) {
        console.log("User logged in:", user.email);
        currentUser = user;
        const loginDialog = document.getElementById('login_dialog');
        if (loginDialog) loginDialog.open = false;
        initFirestoreSync(user);
    } else {
        currentUser = null;
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
    // Password Checker
    const passCheckInput = document.getElementById('pass_check_form');
    if (passCheckInput) {
        passCheckInput.addEventListener('input', (e) => {
            updateStrengthView(e.target.value, 'pass_check_result', 'check_pass_strength_bar', 'pass_crack_time');
        });
    }

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
                document.getElementById('detail_password_dialog').open = false;
                showSnackbar(t('pass_updated'));
            }
        }
    });

    // Delete Password
    document.getElementById('delete_password_btn')?.addEventListener('click', () => {
        if (currentDetailId) {
            showConfirmDialog(t('delete_confirm')).then(async res => {
                if (res) {
                    await deleteItem(currentDetailId);
                    document.getElementById('detail_password_dialog').open = false;
                    showSnackbar(t('pass_deleted'));
                }
            });
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
        // Clear sensitive fields from DOM when dialog closes
        document.getElementById('detail_pass_value').value = '';
        document.getElementById('detail_pass_secret').value = '';
    });

    document.getElementById('add_password_dialog')?.addEventListener('closed', () => {
        // Clear sensitive fields from DOM when dialog closes
        document.getElementById('new_pass_value').value = '';
        document.getElementById('new_pass_secret').value = '';
        updateStrengthView('', null, 'new_pass_strength_bar', null);
    });

    document.getElementById('detail_pass_value')?.addEventListener('input', (e) => updateDetailStrength(e.target.value));
    document.getElementById('open_website_btn')?.addEventListener('click', () => {
        let url = document.getElementById('detail_pass_website').value;
        if (url) {
            if (!/^https?:\/\//i.test(url)) url = 'http://' + url;
            const newWindow = window.open(url, '_blank');
            if (newWindow) newWindow.opener = null;
        }
    });

    document.getElementById('copy_detail_pass_btn')?.addEventListener('click', () => {
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
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                if (el.type === 'password') {
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
        });
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
        
        exportBtn.addEventListener('click', () => {
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
});
