// https://qiita.com/delph/items/7786fadbf71ff45d8162

function generatePassword() {
    //英数字を用意する
    var letters = 'abcdefghijklmnopqrstuvwxyz';
    var numbers = '0123456789';
    var symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    var string = letters;

    var uppercaseInput = document.getElementById('include_uppercase');
    if (uppercaseInput && uppercaseInput.checked) {
        string += letters.toUpperCase();
    }
    var numbersInput = document.getElementById('include_numbers');
    if (numbersInput && numbersInput.checked) {
        string += numbers;
    }
    var symbolsInput = document.getElementById('include_symbols');
    if (symbolsInput && symbolsInput.checked) {
        string += symbols;
    }

    var len = 8;
    var lengthInput = document.getElementById('password_length');
    if (lengthInput) {
        len = parseInt(lengthInput.value);
    }
    var password=''; //文字列が空っぽという定義をする
     

    for (var i = 0; i < len; i++) {
    password += string.charAt(Math.floor(Math.random() * string.length));
    // charAt メソッドを用いて文字列から指定した文字を返す。
    }
      
     console.log(password);
     document.getElementById('auto_make_password').textContent = password;
}

// 初期生成
generatePassword();

     document.getElementById('copy_password_btn').addEventListener('click', function() {
        var passwordText = document.getElementById('auto_make_password').textContent;
        navigator.clipboard.writeText(passwordText).then(function() {
            alert("パスワードをコピーしました");
        });
     });

     document.getElementById('regenerate_password_btn').addEventListener('click', function() {
        generatePassword();
     });

     document.getElementById('password_length').addEventListener('input', function() {
        generatePassword();
     });

     document.getElementById('include_uppercase').addEventListener('change', function() {
        generatePassword();
     });
     document.getElementById('include_numbers').addEventListener('change', function() {
        generatePassword();
     });
     document.getElementById('include_symbols').addEventListener('change', function() {
        generatePassword();
     });

     function calculatePasswordStrength(password) {
        var strength = 0;
        if (!password) return 0;
        if (password.length >= 8) strength++;
        if (password.length >= 12) strength++;
        if (/[A-Z]/.test(password)) strength++;
        if (/[0-9]/.test(password)) strength++;
        if (/[^A-Za-z0-9]/.test(password)) strength++;
        return strength;
     }

     function calculateCrackTime(password) {
        var poolSize = 0;
        if (/[a-z]/.test(password)) poolSize += 26;
        if (/[A-Z]/.test(password)) poolSize += 26;
        if (/[0-9]/.test(password)) poolSize += 10;
        if (/[^a-zA-Z0-9]/.test(password)) poolSize += 33;

        if (poolSize === 0) return '';

        var combinations = Math.pow(poolSize, password.length);
        var seconds = combinations / 1000000000; // 1秒間に10億回試行と仮定

        var timeString = '一瞬';
        if (seconds >= 31536000 * 100) timeString = '数世紀以上';
        else if (seconds >= 31536000) timeString = Math.floor(seconds / 31536000) + '年';
        else if (seconds >= 86400) timeString = Math.floor(seconds / 86400) + '日';
        else if (seconds >= 3600) timeString = Math.floor(seconds / 3600) + '時間';
        else if (seconds >= 60) timeString = Math.floor(seconds / 60) + '分';
        else if (seconds >= 1) timeString = Math.floor(seconds) + '秒';

        return '解読にかかる推定時間: ' + timeString;
     }

     function updateDetailStrength(password) {
        var strength = calculatePasswordStrength(password);
        var resultElement = document.getElementById('detail_pass_strength');
        var crackTimeElement = document.getElementById('detail_pass_crack_time');
        
        if (!password) {
             resultElement.textContent = '';
             if (crackTimeElement) crackTimeElement.textContent = '';
             return;
        }

        if (strength < 2) {
            resultElement.textContent = '弱いパスワード';
            resultElement.style.color = '#d32f2f';
        } else if (strength < 4) {
            resultElement.textContent = '中程度のパスワード';
            resultElement.style.color = '#f57c00';
        } else {
            resultElement.textContent = '強いパスワード';
            resultElement.style.color = '#388e3c';
        }

        if (crackTimeElement) {
            crackTimeElement.textContent = calculateCrackTime(password);
        }
     }

     document.getElementById('pass_check_form').addEventListener('input', function(e) {
        var password = e.target.value;
        var resultElement = document.getElementById('pass_check_result');
        var crackTimeElement = document.getElementById('pass_crack_time');

        if (password.length === 0) {
            resultElement.textContent = '';
            if (crackTimeElement) crackTimeElement.textContent = '';
            return;
        }

        var strength = calculatePasswordStrength(password);

        if (strength < 2) {
            resultElement.textContent = '弱いパスワード';
            resultElement.style.color = '#d32f2f';
        } else if (strength < 4) {
            resultElement.textContent = '中程度のパスワード';
            resultElement.style.color = '#f57c00';
        } else {
            resultElement.textContent = '強いパスワード';
            resultElement.style.color = '#388e3c';
        }

        if (crackTimeElement) {
            crackTimeElement.textContent = calculateCrackTime(password);
        }
     });

     var currentDetailIndex = -1;

     // Base32 decode helper
     function base32ToBuf(str) {
        var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var length = str.length;
        var bits = 0;
        var value = 0;
        var index = 0;
        var output = new Uint8Array((length * 5 / 8) | 0);
        
        for (var i = 0; i < length; i++) {
            var char = str.charAt(i).toUpperCase();
            var val = alphabet.indexOf(char);
            if (val === -1) continue;
            
            value = (value << 5) | val;
            bits += 5;
            
            if (bits >= 8) {
                output[index++] = (value >>> (bits - 8)) & 255;
                bits -= 8;
            }
        }
        return output.slice(0, index);
     }

     async function generateTOTP(secret) {
        if (!secret) return null;
        try {
            // Remove spaces
            secret = secret.replace(/\s/g, '');
            const keyData = base32ToBuf(secret);
            if (keyData.length === 0) return null;

            const key = await window.crypto.subtle.importKey(
                "raw", keyData, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
            );

            const epoch = Math.floor(Date.now() / 1000);
            const timeStep = 30;
            const counter = Math.floor(epoch / timeStep);
            
            const counterBuf = new ArrayBuffer(8);
            const counterView = new DataView(counterBuf);
            counterView.setUint32(4, counter, false);

            const signature = await window.crypto.subtle.sign("HMAC", key, counterBuf);
            const hmac = new Uint8Array(signature);
            
            const offset = hmac[hmac.length - 1] & 0xf;
            const code = ((hmac[offset] & 0x7f) << 24) |
                         ((hmac[offset + 1] & 0xff) << 16) |
                         ((hmac[offset + 2] & 0xff) << 8) |
                         (hmac[offset + 3] & 0xff);
                         
            const strCode = (code % 1000000).toString().padStart(6, '0');
            return { code: strCode, remaining: timeStep - (epoch % timeStep) };
        } catch (e) {
            console.error("TOTP generation failed", e);
            return null;
        }
     }

     var totpInterval = null;

     function startTOTPUpdate(secret) {
        if (totpInterval) clearInterval(totpInterval);
        
        var displayArea = document.getElementById('totp_display_area');
        var codeEl = document.getElementById('totp_code');
        var timerEl = document.getElementById('totp_timer');
        
        if (!secret) {
            displayArea.style.display = 'none';
            return;
        }
        
        displayArea.style.display = 'block';
        
        var update = async function() {
            var result = await generateTOTP(secret);
            if (result) {
                codeEl.textContent = result.code;
                timerEl.textContent = '更新まで: ' + result.remaining + '秒';
            } else {
                codeEl.textContent = 'Invalid Secret';
                timerEl.textContent = '';
            }
        };
        
        update();
        totpInterval = setInterval(update, 1000);
     }

     function stopTOTPUpdate() {
        if (totpInterval) clearInterval(totpInterval);
        totpInterval = null;
     }

     function renderPasswordList(filterText) {
        var listGroup = document.getElementById('password_list');
        // 既存のリストアイテムをクリア（ヘッダー以外）
        var items = listGroup.querySelectorAll('m3e-nav-menu-item');
        items.forEach(function(item) {
            item.remove();
        });

        savedPasswords.forEach(function(item, index) {
            if (!filterText || item.title.toLowerCase().includes(filterText.toLowerCase())) {
                addPasswordToUI(item, index);
            }
        });
     }

     // パスワードリストをUIに追加するヘルパー関数
     function addPasswordToUI(item, index) {
        var listGroup = document.getElementById('password_list');
        var newItem = document.createElement('m3e-nav-menu-item');
        
        var icon = document.createElement('m3e-icon');
        icon.slot = 'icon';
        icon.name = 'key';

        var strength = calculatePasswordStrength(item.password);
        if (strength < 2) {
            icon.style.color = '#d32f2f'; // Red
        } else if (strength < 4) {
            icon.style.color = '#f57c00'; // Orange
        } else {
            icon.style.color = '#388e3c'; // Green
        }
        
        var label = document.createElement('span');
        label.slot = 'label';
        label.textContent = item.title;

        newItem.appendChild(icon);
        newItem.appendChild(label);

        // クリックで詳細ダイアログを開く
        newItem.addEventListener('click', function() {
            currentDetailIndex = index;
            document.getElementById('detail_pass_title').value = item.title;
            document.getElementById('detail_pass_username').value = item.username || '';
            document.getElementById('detail_pass_value').value = item.password || '';
            document.getElementById('detail_pass_secret').value = item.secret || '';
            
            updateDetailStrength(item.password || '');
            startTOTPUpdate(item.secret);
            document.getElementById('detail_password_dialog').open = true;
        });

        listGroup.appendChild(newItem);
     }

     var savedPasswords = [];

     // 認証関連の処理
     var masterAuth = JSON.parse(localStorage.getItem('soul_master_auth'));

     function showSetup() {
        var dialog = document.getElementById('setup_dialog');
        dialog.addEventListener('cancel', function(e) { e.preventDefault(); });
        dialog.open = true;
     }

     function showLogin() {
        var dialog = document.getElementById('login_dialog');
        dialog.addEventListener('cancel', function(e) { e.preventDefault(); });
        dialog.open = true;
     }

     function initApp() {
         savedPasswords = JSON.parse(localStorage.getItem('soul_passwords') || '[]');
         renderPasswordList();
         document.getElementById('warning_dialog').open = true;
     }

     if (!masterAuth) {
        showSetup();
     } else {
        showLogin();
     }

     document.getElementById('setup_btn').addEventListener('click', function() {
        var user = document.getElementById('setup_username').value;
        var pass = document.getElementById('setup_password').value;
        var conf = document.getElementById('setup_password_confirm').value;

        if (user && pass && pass === conf) {
            localStorage.setItem('soul_master_auth', JSON.stringify({ username: user, password: pass }));
            document.getElementById('setup_dialog').open = false;
            initApp();
        } else {
            alert('入力内容を確認してください。');
        }
     });

     document.getElementById('login_btn').addEventListener('click', function() {
        var user = document.getElementById('login_username').value;
        var pass = document.getElementById('login_password').value;

        if (masterAuth && user === masterAuth.username && pass === masterAuth.password) {
            document.getElementById('login_dialog').open = false;
            initApp();
        } else {
            alert('ユーザー名またはパスワードが間違っています。');
        }
     });

     document.getElementById('detail_password_dialog').addEventListener('closed', function() {
        stopTOTPUpdate();
     });

     document.getElementById('detail_pass_value').addEventListener('input', function(e) {
        updateDetailStrength(e.target.value);
     });

     document.getElementById('fld').addEventListener('input', function(e) {
        renderPasswordList(e.target.value);
     });

     document.getElementById('save_new_password_btn').addEventListener('click', function() {
        var title = document.getElementById('new_pass_title').value;
        var username = document.getElementById('new_pass_username').value;
        var password = document.getElementById('new_pass_value').value;
        var secret = document.getElementById('new_pass_secret').value;

        if (title) {
            savedPasswords.push({
                title: title,
                username: username,
                password: password,
                secret: secret
            });
            localStorage.setItem('soul_passwords', JSON.stringify(savedPasswords));
            renderPasswordList();

            // 入力フィールドのクリア
            document.getElementById('new_pass_title').value = '';
            document.getElementById('new_pass_username').value = '';
            document.getElementById('new_pass_value').value = '';
            document.getElementById('new_pass_secret').value = '';
        }
     });

     document.getElementById('delete_password_btn').addEventListener('click', function() {
        if (currentDetailIndex > -1) {
            if (confirm("このパスワードを削除してもよろしいですか？")) {
                savedPasswords.splice(currentDetailIndex, 1);
                localStorage.setItem('soul_passwords', JSON.stringify(savedPasswords));
                renderPasswordList();
                document.getElementById('detail_password_dialog').open = false;
            }
        }
     });

     document.getElementById('export_json_btn').addEventListener('click', function() {
        var data = JSON.stringify(savedPasswords, null, 2);
        var blob = new Blob([data], {type: 'application/json'});
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 'soul_passwords.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
     });

     document.getElementById('import_json_btn').addEventListener('click', function() {
        document.getElementById('import_json_input').click();
     });

     document.getElementById('import_json_input').addEventListener('change', function(e) {
        var file = e.target.files[0];
        if (!file) return;

        var reader = new FileReader();
        reader.onload = function(e) {
            try {
                var importedData = JSON.parse(e.target.result);
                if (Array.isArray(importedData)) {
                    savedPasswords = savedPasswords.concat(importedData);
                    localStorage.setItem('soul_passwords', JSON.stringify(savedPasswords));
                    renderPasswordList();
                    alert('インポートが完了しました。');
                } else {
                    alert('無効なJSONファイル形式です。');
                }
            } catch (error) {
                console.error(error);
                alert('ファイルの読み込みに失敗しました。');
            }
            e.target.value = '';
        };
        reader.readAsText(file);
     });

     document.getElementById('totp_code').addEventListener('click', function() {
        var code = this.textContent;
        if (code && !code.includes('Invalid')) {
            navigator.clipboard.writeText(code).then(function() {
                alert("TOTPコードをコピーしました");
            });
        }
     });

     document.getElementById('update_password_btn').addEventListener('click', function() {
        if (currentDetailIndex > -1) {
            var title = document.getElementById('detail_pass_title').value;
            var username = document.getElementById('detail_pass_username').value;
            var password = document.getElementById('detail_pass_value').value;
            var secret = document.getElementById('detail_pass_secret').value;

            if (title) {
                savedPasswords[currentDetailIndex] = { title: title, username: username, password: password, secret: secret };
                localStorage.setItem('soul_passwords', JSON.stringify(savedPasswords));
                renderPasswordList();
                document.getElementById('detail_password_dialog').open = false;
            }
        }
     });

     document.getElementById('logout_btn').addEventListener('click', function() {
        if (confirm("ログアウトしますか？")) {
            location.reload();
        }
     });

     document.getElementById('update_master_pass_btn').addEventListener('click', function() {
        var currentPass = document.getElementById('setting_current_pass').value;
        var newPass = document.getElementById('setting_new_pass').value;
        var confirmPass = document.getElementById('setting_new_pass_confirm').value;

        if (!masterAuth) return;

        if (currentPass !== masterAuth.password) {
            alert('現在のパスワードが間違っています。');
            return;
        }

        if (newPass !== confirmPass) {
            alert('新しいパスワードが一致しません。');
            return;
        }

        if (!newPass) {
            alert('新しいパスワードを入力してください。');
            return;
        }

        masterAuth.password = newPass;
        localStorage.setItem('soul_master_auth', JSON.stringify(masterAuth));
        alert('マスターパスワードを変更しました。');
        
        document.getElementById('setting_current_pass').value = '';
        document.getElementById('setting_new_pass').value = '';
        document.getElementById('setting_new_pass_confirm').value = '';
     });

     document.getElementById('delete_all_data_btn').addEventListener('click', function() {
        if (confirm("本当にすべてのデータを削除しますか？この操作は取り消せません。")) {
            if (confirm("最終確認です。全てのパスワードデータと設定が失われます。よろしいですか？")) {
                localStorage.removeItem('soul_passwords');
                localStorage.removeItem('soul_master_auth');
                alert('全データを削除しました。初期設定画面に戻ります。');
                location.reload();
            }
        }
     });

     // テーマ切り替え機能
     var themeToggleBtn = document.getElementById('theme_toggle_btn');
     var themeIcon = themeToggleBtn.querySelector('m3e-icon');

     function applyTheme(theme) {
        if (theme === 'dark') {
            document.body.classList.add('dark-theme');
            document.documentElement.style.colorScheme = 'dark';
            themeIcon.name = 'light_mode';
        } else {
            document.body.classList.remove('dark-theme');
            document.documentElement.style.colorScheme = 'light';
            themeIcon.name = 'dark_mode';
        }
        localStorage.setItem('soul_theme', theme);
     }

     var savedTheme = localStorage.getItem('soul_theme');
     if (savedTheme) {
        applyTheme(savedTheme);
     } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        applyTheme('dark');
     }

     themeToggleBtn.addEventListener('click', function() {
        var currentTheme = document.body.classList.contains('dark-theme') ? 'dark' : 'light';
        var newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        applyTheme(newTheme);
     });
