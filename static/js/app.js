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
});
