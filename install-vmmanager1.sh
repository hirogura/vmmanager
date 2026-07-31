#!/bin/bash
set -e

GIT_REPO="https://github.com/hirogura/vmmanager.git"
GIT_BRANCH="main"
INSTALL_DIR="/opt/vm-manage"
SERVICE_NAME="vm-manage"
PORT=8090

echo "=========================================="
echo " VM Manager Web UI - インストールスクリプト"
echo "=========================================="

if [ "$(id -u)" -ne 0 ]; then
    echo "エラー: このスクリプトは root で実行してください"
    exit 1
fi

echo ""
echo "[1/8] システムパッケージをインストール中..."
apt-get update -qq
apt-get install -y -qq \
    python3 \
    python3-venv \
    python3-pip \
    python3-libvirt \
    libvirt-daemon \
    libvirt-daemon-system \
    libvirt-clients \
    qemu-system-x86 \
    qemu-utils \
    qemu-system-gui \
    qemu-system-modules-spice \
    ovmf \
    novnc \
    python3-websockify \
    usbutils \
    sudo \
    curl

echo "[2/8] libvirtd サービスを有効化中..."
systemctl enable --now libvirtd.service

echo "[3/8] Tailscale をインストール中..."
if ! command -v tailscale >/dev/null 2>&1; then
    curl -fsSL https://tailscale.com/install.sh | sh
fi

echo "[4/8] アプリケーションを GitHub から取得中..."
if [ -d "${INSTALL_DIR}/.git" ]; then
    echo "既存のリポジトリを更新します: ${INSTALL_DIR}"
    git -C "${INSTALL_DIR}" remote set-url origin "${GIT_REPO}"
    git -C "${INSTALL_DIR}" fetch origin
    git -C "${INSTALL_DIR}" reset --hard "origin/${GIT_BRANCH}"
else
    if [ -e "${INSTALL_DIR}" ]; then
        echo "エラー: ${INSTALL_DIR} が存在しますが Git リポジトリではありません。"
        echo "既存のディレクトリを退避してから再実行してください。"
        exit 1
    fi
    git clone -b "${GIT_BRANCH}" "${GIT_REPO}" "${INSTALL_DIR}"
fi

echo "[5/8] Python 仮想環境を作成中..."
if [ -d "${INSTALL_DIR}/venv" ]; then
    rm -rf "${INSTALL_DIR}/venv"
fi
python3 -m venv --system-site-packages "${INSTALL_DIR}/venv"
chmod +x "${INSTALL_DIR}/venv/bin/python"

echo "[6/8] Flask をインストール中..."
"${INSTALL_DIR}/venv/bin/pip" install --quiet --upgrade pip
"${INSTALL_DIR}/venv/bin/pip" install --quiet flask

echo "[7/8] systemd サービスを設定中..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" << 'SVCEOF'
[Unit]
Description=VM Manager Web UI
After=libvirtd.service
Requires=libvirtd.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/vm-manage
ExecStart=/opt/vm-manage/venv/bin/python /opt/vm-manage/app.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SVCEOF
systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}.service"

echo "[8/8] Tailscale serve で HTTPS 公開を設定中..."
echo "  ※ アプリは 127.0.0.1 のみで待ち受け、LAN からは直接アクセスできません。"
echo "  ※ Tailnet 内からのみ HTTPS でアクセスできます。"
tailscale up
tailscale serve --bg --yes --https="${PORT}" "http://127.0.0.1:${PORT}"

echo ""
echo "=========================================="
echo " インストール完了！"
echo "=========================================="
echo ""
echo " サービス状態:"
systemctl is-active "${SERVICE_NAME}.service"
echo ""
FQDN=$(tailscale status --json 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin)['Self']['DNSName'].strip('.'))" 2>/dev/null || true)
if [ -z "${FQDN}" ]; then
    FQDN=$(hostname)
fi
echo " アクセスURL: https://${FQDN}:${PORT}"
echo ""
echo " ※ この URL は Tailnet 内からのみアクセスできます（LAN からはアクセス不可）"
echo ""
