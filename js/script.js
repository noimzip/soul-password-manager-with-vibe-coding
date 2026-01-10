// https://qiita.com/delph/items/7786fadbf71ff45d8162

var CONSTANTS = {
    STORAGE: {
        PASSWORDS: 'soul_passwords',
        MASTER_AUTH: 'soul_master_auth',
        AUTO_LOGOUT: 'soul_auto_logout_minutes',
        DEFAULT_USER: 'soul_default_username',
        THEME: 'soul_theme'
    }
};

function generatePasswordString(length, useUpper, useNumbers, useSymbols) {
    var letters = 'abcdefghijklmnopqrstuvwxyz';
    var numbers = '0123456789';
    var symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    var pool = letters;
    if (useUpper) pool += letters.toUpperCase();
    if (useNumbers) pool += numbers;
    if (useSymbols) pool += symbols;

    var password = '';
    for (var i = 0; i < length; i++) {
        password += pool.charAt(Math.floor(Math.random() * pool.length));
    }
    return password;
}

function copyToClipboard(text, message) {
    if (!text) return;
    navigator.clipboard.writeText(text).then(function() {
        showSnackbar(message);
    }).catch(function(err) {
        console.error('Copy failed', err);
        showSnackbar('コピーに失敗しました');
    });
}

function generatePassword() {
    var len = 8;
    var lengthInput = document.getElementById('password_length');
    if (lengthInput) {
        len = parseInt(lengthInput.value);
    }
    
    var useUpper = document.getElementById('include_uppercase') ? document.getElementById('include_uppercase').checked : true;
    var useNumbers = document.getElementById('include_numbers') ? document.getElementById('include_numbers').checked : true;
    var useSymbols = document.getElementById('include_symbols') ? document.getElementById('include_symbols').checked : false;

    var password = generatePasswordString(len, useUpper, useNumbers, useSymbols);

     console.log(password);
     document.getElementById('auto_make_password').textContent = password;

     // パスワード強度を表示
     var strength = calculatePasswordStrength(password);
     var resultElement = document.getElementById('maker_pass_strength');
     var crackTimeElement = document.getElementById('maker_pass_crack_time');

     if (resultElement) {
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
     }

     if (crackTimeElement) {
         crackTimeElement.textContent = calculateCrackTime(password);
     }
}

// 初期生成
generatePassword();

     function showDialog(message, isConfirm) {
        return new Promise(function(resolve) {
            var dialog = document.createElement('m3e-dialog');
            
            var content = document.createElement('div');
            content.textContent = message;
            content.style.padding = '10px 0';
            dialog.appendChild(content);

            var btnContainer = document.createElement('div');
            btnContainer.style.display = 'flex';
            btnContainer.style.justifyContent = 'flex-end';
            btnContainer.style.marginTop = '10px';
            btnContainer.style.gap = '8px';

            var createBtn = function(text) {
                var btn = document.createElement('button');
                btn.textContent = text;
                btn.style.cssText = 'border:none; background:transparent; color:#2196f3; font-weight:bold; cursor:pointer; padding:8px 16px; font-size:14px;';
                return btn;
            };

            var cancelBtn;
            if (isConfirm) {
                cancelBtn = createBtn('いいえ');
                cancelBtn.addEventListener('click', function() {
                    dialog.open = false;
                    resolve(false);
                    setTimeout(function() { if(dialog.parentNode) dialog.parentNode.removeChild(dialog); }, 500);
                });
                btnContainer.appendChild(cancelBtn);
            }

            var okBtn = createBtn(isConfirm ? 'はい' : 'OK');
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
        var el = document.createElement('div');
        el.textContent = message;
        el.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background-color:#323232;color:white;padding:14px 24px;border-radius:4px;z-index:10000;box-shadow:0 2px 5px rgba(0,0,0,0.2);opacity:0;transition:opacity 0.3s;font-family:sans-serif;pointer-events:none;';
        document.body.appendChild(el);
        requestAnimationFrame(function() { el.style.opacity = '1'; });
        setTimeout(function() {
            el.style.opacity = '0';
            setTimeout(function() { if(el.parentNode) el.parentNode.removeChild(el); }, 300);
        }, 3000);
     }

     document.getElementById('copy_password_btn').addEventListener('click', function() {
        var passwordText = document.getElementById('auto_make_password').textContent;
        copyToClipboard(passwordText, "パスワードをコピーしました");
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

        // 長さの評価
        if (password.length >= 8) strength += 1;
        if (password.length >= 12) strength += 1;
        if (password.length >= 16) strength += 1;

        // 文字種の評価
        var typeCount = 0;
        if (/[a-z]/.test(password)) typeCount++;
        if (/[A-Z]/.test(password)) typeCount++;
        if (/[0-9]/.test(password)) typeCount++;
        if (/[^A-Za-z0-9]/.test(password)) typeCount++;
        strength += typeCount;

        // ペナルティ判定
        if (password.length < 8 || typeCount <= 1) return Math.min(strength, 1); // 弱い
        if (typeCount === 2) return Math.min(strength, 3); // 中程度

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

     var dragSrcEl = null;

     // Inject CSS for drag and drop
     var dndStyle = document.createElement('style');
     dndStyle.innerHTML = 'm3e-nav-menu-item.dragging { opacity: 0.4; } m3e-nav-menu-item.over { border-top: 2px solid #2196f3; }';
     document.head.appendChild(dndStyle);

     function handleDragStart(e) {
        dragSrcEl = this;
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/html', this.innerHTML);
        this.classList.add('dragging');
     }

     function handleDragOver(e) {
        if (e.preventDefault) {
            e.preventDefault();
        }
        e.dataTransfer.dropEffect = 'move';
        return false;
     }

     function handleDragEnter(e) {
        this.classList.add('over');
     }

     function handleDragLeave(e) {
        this.classList.remove('over');
     }

     function handleDrop(e) {
        if (e.stopPropagation) {
            e.stopPropagation();
        }

        if (dragSrcEl && dragSrcEl !== this) {
            var srcIndex = parseInt(dragSrcEl.dataset.index, 10);
            var targetIndex = parseInt(this.dataset.index, 10);

            if (!isNaN(srcIndex) && !isNaN(targetIndex)) {
                var itemToMove = savedPasswords[srcIndex];
                savedPasswords.splice(srcIndex, 1);
                savedPasswords.splice(targetIndex, 0, itemToMove);
                localStorage.setItem(CONSTANTS.STORAGE.PASSWORDS, JSON.stringify(savedPasswords));
                var filterVal = document.getElementById('fld').value;
                renderPasswordList(filterVal);
            }
        }
        return false;
     }

     function handleDragEnd(e) {
        this.classList.remove('dragging');
        var items = document.querySelectorAll('m3e-nav-menu-item');
        items.forEach(function(item) {
            item.classList.remove('over');
        });
     }

     function renderPasswordList(filterText) {
        var favList = document.getElementById('favorite_list');
        var passList = document.getElementById('password_list');

        favList.querySelectorAll('m3e-nav-menu-item').forEach(function(item) { item.remove(); });
        passList.querySelectorAll('m3e-nav-menu-item').forEach(function(item) { item.remove(); });

        savedPasswords.forEach(function(item, index) {
            if (!filterText || item.title.toLowerCase().includes(filterText.toLowerCase())) {
                var targetList = item.favorite ? favList : passList;
                addPasswordToUI(item, index, targetList);
            }
        });
     }

     // パスワードリストをUIに追加するヘルパー関数
     function addPasswordToUI(item, index, listGroup) {
        var newItem = document.createElement('m3e-nav-menu-item');
        newItem.style.position = 'relative';
        
        newItem.draggable = true;
        newItem.dataset.index = index;
        newItem.addEventListener('dragstart', handleDragStart);
        newItem.addEventListener('dragover', handleDragOver);
        newItem.addEventListener('drop', handleDrop);
        newItem.addEventListener('dragenter', handleDragEnter);
        newItem.addEventListener('dragleave', handleDragLeave);
        newItem.addEventListener('dragend', handleDragEnd);
        
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

        // お気に入りボタンの追加
        var favBtn = document.createElement('m3e-icon-button');
        favBtn.style.position = 'absolute';
        favBtn.style.right = '8px';
        favBtn.style.top = '50%';
        favBtn.style.transform = 'translateY(-50%)';
        favBtn.style.zIndex = '2';
        var favIcon = document.createElement('m3e-icon');
        favIcon.name = item.favorite ? 'star' : 'star_border';
        if (item.favorite) favIcon.style.color = '#fbc02d';
        favBtn.appendChild(favIcon);

        favBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            item.favorite = !item.favorite;
            localStorage.setItem(CONSTANTS.STORAGE.PASSWORDS, JSON.stringify(savedPasswords));
            // 検索ボックスの値を取得して再描画
            var filterVal = document.getElementById('fld').value;
            renderPasswordList(filterVal);
        });
        newItem.appendChild(favBtn);

        // クリックで詳細ダイアログを開く
        newItem.addEventListener('click', function() {
            currentDetailIndex = index;
            document.getElementById('detail_pass_title').value = item.title;
            document.getElementById('detail_pass_username').value = item.username || '';
            document.getElementById('detail_pass_value').value = item.password || '';
            document.getElementById('detail_pass_secret').value = item.secret || '';
            
            // お気に入り状態の反映
            var dFavIcon = document.getElementById('detail_pass_favorite_btn').querySelector('m3e-icon');
            dFavIcon.name = item.favorite ? 'star' : 'star_border';
            dFavIcon.style.color = item.favorite ? '#fbc02d' : '';
            
            // 履歴情報の表示
            var lastMod = item.lastModified ? new Date(item.lastModified).toLocaleString() : '-';
            document.getElementById('detail_last_modified').textContent = lastMod;

            var history = item.history || [];
            document.getElementById('detail_revision_count').textContent = history.length;

            var historyList = document.getElementById('detail_history_list');
            historyList.innerHTML = '';
            if (history.length === 0) {
                historyList.textContent = '変更履歴はありません。';
            } else {
                // 新しい順に表示
                history.slice().reverse().forEach(function(h) {
                    var div = document.createElement('div');
                    div.style.borderBottom = '1px solid rgba(128,128,128,0.2)';
                    div.style.padding = '8px 0';
                    div.style.display = 'flex';
                    div.style.justifyContent = 'space-between';
                    div.style.alignItems = 'center';

                    var infoDiv = document.createElement('div');
                    infoDiv.style.flex = '1';
                    var dateStr = new Date(h.date).toLocaleString();
                    infoDiv.innerHTML = '<div style="font-weight:bold; font-size:0.9em;">' + dateStr + '</div>' +
                                    '<div style="opacity: 0.8; font-size: 0.85em;">Title: ' + (h.title || '-') + '</div>' +
                                    '<div style="opacity: 0.8; font-size: 0.85em;">User: ' + (h.username || '-') + '</div>' +
                                    '<div style="opacity: 0.8; font-size: 0.85em;">Pass: ' + (h.password || '-') + '</div>';
                    
                    var restoreBtn = document.createElement('button');
                    restoreBtn.textContent = '復元';
                    restoreBtn.type = 'button';
                    restoreBtn.style.marginLeft = '8px';
                    restoreBtn.style.cursor = 'pointer';
                    
                    restoreBtn.addEventListener('click', function() {
                        showConfirmDialog('この履歴の内容を入力フォームに反映しますか？\n(反映後、「更新」ボタンを押すことで保存されます)').then(function(res) {
                            if (res) {
                                document.getElementById('detail_pass_title').value = h.title || '';
                                document.getElementById('detail_pass_username').value = h.username || '';
                                document.getElementById('detail_pass_value').value = h.password || '';
                                document.getElementById('detail_pass_secret').value = h.secret || '';
                                
                                updateDetailStrength(h.password || '');
                                startTOTPUpdate(h.secret || '');
                            }
                        });
                    });

                    div.appendChild(infoDiv);
                    div.appendChild(restoreBtn);
                    historyList.appendChild(div);
                });
            }

            updateDetailStrength(item.password || '');
            startTOTPUpdate(item.secret);
            document.getElementById('detail_password_dialog').open = true;
        });

        listGroup.appendChild(newItem);
     }

     var savedPasswords = [];

     // 認証関連の処理
     var masterAuth = JSON.parse(localStorage.getItem(CONSTANTS.STORAGE.MASTER_AUTH));

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
         savedPasswords = JSON.parse(localStorage.getItem(CONSTANTS.STORAGE.PASSWORDS) || '[]');
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
            localStorage.setItem(CONSTANTS.STORAGE.MASTER_AUTH, JSON.stringify({ username: user, password: pass }));
            document.getElementById('setup_dialog').open = false;
            initApp();
        } else {
            showAlertDialog('入力内容を確認してください。');
        }
     });

     document.getElementById('login_btn').addEventListener('click', function() {
        var user = document.getElementById('login_username').value;
        var pass = document.getElementById('login_password').value;

        if (masterAuth && user === masterAuth.username && pass === masterAuth.password) {
            document.getElementById('login_dialog').open = false;
            initApp();
        } else {
            showAlertDialog('ユーザー名またはパスワードが間違っています。');
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
                secret: secret,
                favorite: false
            });
            localStorage.setItem(CONSTANTS.STORAGE.PASSWORDS, JSON.stringify(savedPasswords));
            renderPasswordList();

            // 入力フィールドのクリア
            document.getElementById('new_pass_title').value = '';
            document.getElementById('new_pass_username').value = '';
            document.getElementById('new_pass_value').value = '';
            document.getElementById('new_pass_secret').value = '';
            showSnackbar('新しいパスワードを作成しました');
        }
     });

     document.getElementById('generate_new_pass_btn').addEventListener('click', function() {
        var password = generatePasswordString(16, true, true, true);
        document.getElementById('new_pass_value').value = password;
     });

     document.getElementById('generate_detail_pass_btn').addEventListener('click', function() {
        var password = generatePasswordString(16, true, true, true);
        document.getElementById('detail_pass_value').value = password;
        updateDetailStrength(password);
     });

     document.getElementById('delete_password_btn').addEventListener('click', function() {
        if (currentDetailIndex > -1) {
            showConfirmDialog("このパスワードを削除してもよろしいですか？").then(function(res) {
                if (res) {
                    savedPasswords.splice(currentDetailIndex, 1);
                    localStorage.setItem(CONSTANTS.STORAGE.PASSWORDS, JSON.stringify(savedPasswords));
                    renderPasswordList();
                    document.getElementById('detail_password_dialog').open = false;
                    showSnackbar('パスワードを削除しました');
                }
            });
        }
     });

     // 設定画面にインポート/エクスポート機能を統合
     var deleteAllBtn = document.getElementById('delete_all_data_btn');
     if (deleteAllBtn && deleteAllBtn.parentNode) {
        var container = document.createElement('div');
        container.style.marginBottom = '20px';
        container.style.padding = '15px';
        container.style.border = '1px solid #ccc';
        container.style.borderRadius = '4px';
        container.style.backgroundColor = 'rgba(0, 0, 0, 0.02)';

        var title = document.createElement('h4');
        title.textContent = 'データ管理';
        title.style.marginTop = '0';
        title.style.marginBottom = '10px';
        container.appendChild(title);

        var btnContainer = document.createElement('div');
        btnContainer.style.display = 'flex';
        btnContainer.style.gap = '10px';

        var exportBtn = document.createElement('button');
        exportBtn.textContent = 'エクスポート (JSON)';
        exportBtn.type = 'button';
        exportBtn.style.padding = '8px 16px';
        exportBtn.style.cursor = 'pointer';
        
        exportBtn.addEventListener('click', function() {
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

        var importBtn = document.createElement('button');
        importBtn.textContent = 'インポート (JSON)';
        importBtn.type = 'button';
        importBtn.style.padding = '8px 16px';
        importBtn.style.cursor = 'pointer';

        var fileInput = document.createElement('input');
        fileInput.type = 'file';
        fileInput.accept = '.json';
        fileInput.style.display = 'none';

        importBtn.addEventListener('click', function() {
            fileInput.click();
        });

        fileInput.addEventListener('change', function(e) {
            var file = e.target.files[0];
            if (!file) return;

            var reader = new FileReader();
            reader.onload = function(e) {
                try {
                    var importedData = JSON.parse(e.target.result);
                    if (Array.isArray(importedData)) {
                        showConfirmDialog('現在のリストに ' + importedData.length + ' 件のデータを追加しますか？').then(function(res) {
                            if (res) {
                                savedPasswords = savedPasswords.concat(importedData);
                                localStorage.setItem(CONSTANTS.STORAGE.PASSWORDS, JSON.stringify(savedPasswords));
                                renderPasswordList();
                                showAlertDialog('インポートが完了しました。');
                            }
                        });
                    } else {
                        showAlertDialog('無効なJSONファイル形式です。');
                    }
                } catch (error) {
                    console.error(error);
                    showAlertDialog('ファイルの読み込みに失敗しました。');
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

     // 既存のFABボタンを非表示にする
     ['export_json_btn', 'import_json_btn'].forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.style.display = 'none';
     });

     document.getElementById('totp_code').addEventListener('click', function() {
        var code = this.textContent;
        if (code && !code.includes('Invalid')) {
            copyToClipboard(code, "TOTPコードをコピーしました");
        }
     });

     document.getElementById('detail_pass_favorite_btn').addEventListener('click', function() {
        var icon = this.querySelector('m3e-icon');
        if (icon.name === 'star') {
            icon.name = 'star_border';
            icon.style.color = '';
        } else {
            icon.name = 'star';
            icon.style.color = '#fbc02d';
        }
     });

     document.getElementById('update_password_btn').addEventListener('click', function() {
        if (currentDetailIndex > -1) {
            var title = document.getElementById('detail_pass_title').value;
            var username = document.getElementById('detail_pass_username').value;
            var password = document.getElementById('detail_pass_value').value;
            var secret = document.getElementById('detail_pass_secret').value;
            var isFavorite = document.getElementById('detail_pass_favorite_btn').querySelector('m3e-icon').name === 'star';

            if (title) {
                var oldItem = savedPasswords[currentDetailIndex];
                
                // 変更検知
                var hasChanged = (oldItem.title !== title) ||
                                 (oldItem.username !== username) ||
                                 (oldItem.password !== password) ||
                                 (oldItem.secret !== secret);

                var newItem = Object.assign({}, oldItem, {
                    title: title,
                    username: username,
                    password: password,
                    secret: secret,
                    favorite: isFavorite
                });

                if (hasChanged) {
                    var history = oldItem.history || [];
                    // 現在の状態を履歴として保存
                    history.push({
                        date: Date.now(),
                        title: oldItem.title,
                        username: oldItem.username,
                        password: oldItem.password,
                        secret: oldItem.secret
                    });
                    newItem.history = history;
                    newItem.lastModified = Date.now();
                }

                savedPasswords[currentDetailIndex] = newItem;
                localStorage.setItem(CONSTANTS.STORAGE.PASSWORDS, JSON.stringify(savedPasswords));
                renderPasswordList();
                document.getElementById('detail_password_dialog').open = false;
                showSnackbar('パスワードを更新しました');
            }
        }
     });

     // 詳細ダイアログのユーザー名とパスワード欄にコピーボタンを追加
     var detailCopyTargets = [
        { id: 'detail_pass_username', name: 'ユーザー名' },
        { id: 'detail_pass_value', name: 'パスワード' }
     ];

     detailCopyTargets.forEach(function(target) {
        var el = document.getElementById(target.id);
        if (el) {
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.style.background = 'transparent';
            btn.style.border = 'none';
            btn.style.cursor = 'pointer';
            btn.style.padding = '0';
            btn.style.marginLeft = '8px';
            btn.title = target.name + 'をコピー';
            var icon = document.createElement('m3e-icon');
            icon.name = 'content_copy';
            btn.appendChild(icon);
            btn.addEventListener('click', function(e) {
                e.preventDefault();
                copyToClipboard(el.value, target.name + "をコピーしました");
            });
            if (el.parentNode) {
                el.parentNode.insertBefore(btn, el.nextSibling);
            }
        }
     });

     // パスワード表示切り替え機能の追加
     function setupPasswordToggles() {
        var passwordIds = [
            'new_pass_value',
            'detail_pass_value',
            'setup_password',
            'setup_password_confirm',
            'login_password',
            'setting_current_pass',
            'setting_new_pass',
            'setting_new_pass_confirm'
        ];

        passwordIds.forEach(function(id) {
            var el = document.getElementById(id);
            if (el) {
                el.type = 'password'; // デフォルトで非表示

                var btn = document.createElement('button');
                btn.type = 'button';
                btn.style.background = 'transparent';
                btn.style.border = 'none';
                btn.style.cursor = 'pointer';
                btn.style.padding = '0';
                btn.style.marginLeft = '4px';
                btn.title = 'パスワードを表示';
                
                var icon = document.createElement('m3e-icon');
                icon.name = 'visibility';
                btn.appendChild(icon);

                btn.addEventListener('click', function(e) {
                    e.preventDefault();
                    if (el.type === 'password') {
                        el.type = 'text';
                        icon.name = 'visibility_off';
                        btn.title = 'パスワードを隠す';
                    } else {
                        el.type = 'password';
                        icon.name = 'visibility';
                        btn.title = 'パスワードを表示';
                    }
                });

                if (el.parentNode) {
                    el.parentNode.insertBefore(btn, el.nextSibling);
                }
            }
        });
     }
     setupPasswordToggles();

     document.getElementById('logout_btn').addEventListener('click', function() {
        showConfirmDialog("ログアウトしますか？").then(function(res) {
            if (res) {
                location.reload();
            }
        });
     });

     document.getElementById('update_master_pass_btn').addEventListener('click', function() {
        var currentPass = document.getElementById('setting_current_pass').value;
        var newPass = document.getElementById('setting_new_pass').value;
        var confirmPass = document.getElementById('setting_new_pass_confirm').value;

        if (!masterAuth) return;

        if (currentPass !== masterAuth.password) {
            showAlertDialog('現在のパスワードが間違っています。');
            return;
        }

        if (newPass !== confirmPass) {
            showAlertDialog('新しいパスワードが一致しません。');
            return;
        }

        if (!newPass) {
            showAlertDialog('新しいパスワードを入力してください。');
            return;
        }

        masterAuth.password = newPass;
        localStorage.setItem(CONSTANTS.STORAGE.MASTER_AUTH, JSON.stringify(masterAuth));
        showSnackbar('マスターパスワードを変更しました。');
        
        document.getElementById('setting_current_pass').value = '';
        document.getElementById('setting_new_pass').value = '';
        document.getElementById('setting_new_pass_confirm').value = '';
     });

     document.getElementById('delete_all_data_btn').addEventListener('click', function() {
        showConfirmDialog("本当にすべてのデータを削除しますか？この操作は取り消せません。").then(function(res1) {
            if (res1) {
                showConfirmDialog("最終確認です。全てのパスワードデータと設定が失われます。よろしいですか？").then(function(res2) {
                    if (res2) {
                        localStorage.removeItem(CONSTANTS.STORAGE.PASSWORDS);
                        localStorage.removeItem(CONSTANTS.STORAGE.MASTER_AUTH);
                        localStorage.removeItem(CONSTANTS.STORAGE.AUTO_LOGOUT);
                        localStorage.removeItem(CONSTANTS.STORAGE.DEFAULT_USER);
                        showAlertDialog('全データを削除しました。初期設定画面に戻ります。').then(function() {
                            location.reload();
                        });
                    }
                });
            }
        });
     });

     // 自動ログアウト機能
     var autoLogoutTimer = null;

     function performAutoLogout() {
        // ログイン画面やセットアップ画面が表示されている場合は実行しない
        if (document.getElementById('login_dialog').open || document.getElementById('setup_dialog').open) {
            return;
        }
        showAlertDialog('一定時間操作がなかったため、自動ログアウトしました。').then(function() {
            location.reload();
        });
     }

     function resetAutoLogoutTimer() {
        if (autoLogoutTimer) clearTimeout(autoLogoutTimer);
        var minutes = parseInt(localStorage.getItem(CONSTANTS.STORAGE.AUTO_LOGOUT) || '0', 10);
        if (minutes > 0) {
            autoLogoutTimer = setTimeout(performAutoLogout, minutes * 60 * 1000);
        }
     }

     ['mousemove', 'keydown', 'click', 'touchstart', 'scroll'].forEach(function(evt) {
        window.addEventListener(evt, function() {
            resetAutoLogoutTimer();
        }, { passive: true });
     });

     // 設定画面へのUI追加
     var updateMasterPassBtn = document.getElementById('update_master_pass_btn');
     if (updateMasterPassBtn && updateMasterPassBtn.parentNode) {
        var container = document.createElement('div');
        container.style.margin = '16px 0';
        
        var label = document.createElement('label');
        label.textContent = '自動ログアウト: ';
        
        var select = document.createElement('select');
        var options = [
            { val: 0, text: '無効' },
            { val: 1, text: '1分' },
            { val: 5, text: '5分' },
            { val: 10, text: '10分' },
            { val: 30, text: '30分' }
        ];
        var currentVal = parseInt(localStorage.getItem('soul_auto_logout_minutes') || '0', 10);
        options.forEach(function(opt) {
            var o = document.createElement('option');
            o.value = opt.val;
            o.textContent = opt.text;
            if (opt.val === currentVal) o.selected = true;
            select.appendChild(o);
        });
        select.addEventListener('change', function() {
            localStorage.setItem('soul_auto_logout_minutes', this.value);
            resetAutoLogoutTimer();
        });
        
        container.appendChild(label);
        container.appendChild(select);
        updateMasterPassBtn.parentNode.insertBefore(container, updateMasterPassBtn);
     }

     resetAutoLogoutTimer();

     // デフォルトユーザー名機能
     var savedDefaultUser = localStorage.getItem(CONSTANTS.STORAGE.DEFAULT_USER);
     if (savedDefaultUser) {
        var settingInput = document.getElementById('setting_default_username');
        if (settingInput) settingInput.value = savedDefaultUser;
     }

     var saveGeneralSettingsBtn = document.getElementById('save_general_settings_btn');
     if (saveGeneralSettingsBtn) {
        saveGeneralSettingsBtn.addEventListener('click', function() {
            var defaultUser = document.getElementById('setting_default_username').value;
            localStorage.setItem(CONSTANTS.STORAGE.DEFAULT_USER, defaultUser);
            showSnackbar('設定を保存しました');
        });
     }

     var fillNewPassBtn = document.getElementById('fill_new_pass_default_username_btn');
     if (fillNewPassBtn) {
        fillNewPassBtn.addEventListener('click', function() {
            var defaultUser = localStorage.getItem(CONSTANTS.STORAGE.DEFAULT_USER);
            if (defaultUser) {
                document.getElementById('new_pass_username').value = defaultUser;
            } else {
                showSnackbar('デフォルトユーザー名が設定されていません');
            }
        });
     }

     var fillDetailPassBtn = document.getElementById('fill_default_username_btn');
     if (fillDetailPassBtn) {
        fillDetailPassBtn.addEventListener('click', function() {
            var defaultUser = localStorage.getItem(CONSTANTS.STORAGE.DEFAULT_USER);
            if (defaultUser) {
                document.getElementById('detail_pass_username').value = defaultUser;
            } else {
                showSnackbar('デフォルトユーザー名が設定されていません');
            }
        });
     }

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
        localStorage.setItem(CONSTANTS.STORAGE.THEME, theme);
     }

     var savedTheme = localStorage.getItem(CONSTANTS.STORAGE.THEME);
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
