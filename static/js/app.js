document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('textarea').forEach(ta => {
        ta.addEventListener('keydown', function(e) {
            if (e.key === 'Tab') {
                e.preventDefault();
                const start = this.selectionStart;
                const end = this.selectionEnd;
                this.value = this.value.substring(0, start) + '  ' + this.value.substring(end);
                this.selectionStart = this.selectionEnd = start + 2;
            }
        });
    });

    const btnRestart = document.getElementById('btn-server-restart');
    if (btnRestart) {
        btnRestart.addEventListener('click', function() {
            if (!confirm('VM Managerサーバを再起動しますか？\n実行中のVNCコンソール接続は切断されます。')) return;
            const original = btnRestart.innerHTML;
            btnRestart.disabled = true;
            btnRestart.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 再起動中...';
            fetch('/api/server/restart', { method: 'POST' })
                .then(() => {})
                .catch(() => {});
            let attempts = 0;
            const poll = setInterval(async () => {
                attempts++;
                try {
                    await fetch('/', { method: 'GET', cache: 'no-store' });
                    clearInterval(poll);
                    location.reload();
                } catch (e) {
                    if (attempts > 30) {
                        clearInterval(poll);
                        btnRestart.disabled = false;
                        btnRestart.innerHTML = original;
                        alert('再起動完了の確認ができませんでした。ページをリロードしてください。');
                    }
                }
            }, 3000);
        });
    }

    const btnUpdate = document.getElementById('btn-server-update');
    if (btnUpdate) {
        btnUpdate.addEventListener('click', function() {
            if (!confirm('VM Managerを最新版にアップデートしますか？\n完了後、「サーバ再起動」ボタンを押して反映してください。')) return;
            const original = btnUpdate.innerHTML;
            btnUpdate.disabled = true;
            btnUpdate.innerHTML = '<i class="fas fa-spinner fa-spin"></i> アップデート中...';
            fetch('/api/server/update', { method: 'POST' })
                .then(r => r.json().then(d => ({ ok: r.ok, data: d })))
                .then(({ ok, data }) => {
                    if (!ok) {
                        alert('エラー: ' + (data.error || 'アップデートを開始できませんでした'));
                        btnUpdate.disabled = false;
                        btnUpdate.innerHTML = original;
                        return;
                    }
                    const poll = setInterval(async () => {
                        try {
                            const res = await fetch('/api/server/update/status', { cache: 'no-store' });
                            const st = await res.json();
                            if (!st.running) {
                                clearInterval(poll);
                                btnUpdate.disabled = false;
                                btnUpdate.innerHTML = original;
                                if (st.success) {
                                    alert('アップデートが完了しました。「サーバ再起動」ボタンを押してください。');
                                } else {
                                    alert('アップデートに失敗しました:\n' + (st.log || '詳細不明'));
                                }
                            }
                        } catch (e) {}
                    }, 3000);
                })
                .catch(() => {
                    alert('エラー: アップデートを開始できませんでした');
                    btnUpdate.disabled = false;
                    btnUpdate.innerHTML = original;
                });
        });
    }
});
