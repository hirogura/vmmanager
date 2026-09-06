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
echo "[1/9] システムパッケージをインストール中..."
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
    curl \
    git

echo "[2/9] libvirtd サービスを有効化中..."
systemctl enable --now libvirtd.service

echo "[3/9] ストレージプールを設定中..."
mkdir -p /opt/vm
chown root:libvirt-qemu /opt/vm 2>/dev/null || true
chmod 775 /opt/vm

# default プールを /opt/vm に向ける（無ければ作成）
DEFAULT_TARGET=""
if virsh pool-info default >/dev/null 2>&1; then
    DEFAULT_TARGET=$(virsh pool-dumpxml default | grep -oP '(?<=<path>)[^<]+' | head -n1)
fi
if [ -z "${DEFAULT_TARGET}" ] || [ "${DEFAULT_TARGET}" != "/opt/vm" ]; then
    if virsh pool-info default >/dev/null 2>&1; then
        virsh pool-destroy default >/dev/null 2>&1 || true
        virsh pool-undefine default >/dev/null 2>&1 || true
    fi
    virsh pool-define-as default dir --target /opt/vm
    virsh pool-autostart default
fi
virsh pool-start default >/dev/null 2>&1 || true
echo "  default プール: /opt/vm"

# /iso があれば iso プールを追加
if [ -d /iso ]; then
    if ! virsh pool-info iso >/dev/null 2>&1; then
        virsh pool-define-as iso dir --target /iso
        virsh pool-autostart iso
        virsh pool-start iso >/dev/null 2>&1 || true
        echo "  iso プール: /iso を追加しました"
    else
        echo "  iso プール: 既に存在します"
    fi
fi

echo "[4/9] Tailscale をインストール中..."
if ! command -v tailscale >/dev/null 2>&1; then
    curl -fsSL https://tailscale.com/install.sh | sh
fi

echo "[5/9] アプリケーションを GitHub から取得中..."
if ! command -v git >/dev/null 2>&1; then
    echo "  git が未インストールのためインストールします..."
    apt-get install -y -qq git
fi
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

echo "[6/9] Python 仮想環境を作成中..."
if [ -d "${INSTALL_DIR}/venv" ]; then
    rm -rf "${INSTALL_DIR}/venv"
fi
python3 -m venv --system-site-packages "${INSTALL_DIR}/venv"
chmod +x "${INSTALL_DIR}/venv/bin/python"

echo "[7/9] Flask をインストール中..."
"${INSTALL_DIR}/venv/bin/pip" install --quiet --upgrade pip
"${INSTALL_DIR}/venv/bin/pip" install --quiet flask flask-sock simple-websocket

echo "[8/9] systemd サービスを設定中..."
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

echo "[9/9] Tailscale serve で HTTPS 公開を設定中..."
echo "  ※ アプリは 127.0.0.1 のみで待ち受け、LAN からは直接アクセスできません。"
echo "  ※ Tailnet 内からのみ HTTPS でアクセスできます。"
tailscale up
tailscale serve --bg --yes --https="${PORT}" "http://127.0.0.1:${PORT}"
tailscale serve --bg --yes --https="${PORT}" --set-path="/websockify" "http://127.0.0.1:6080"

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
