#!/bin/bash
# VM Manager Web UI - 統合インストールスクリプト (Debian/Ubuntu <-> Arch/CachyOS 対応)
# 実行時に OS を判別し、apt / pacman を使い分ける。
# 使い方: sudo ./install-vmmanager.sh
set -e

GIT_REPO="https://github.com/hirogura/vmmanager.git"
GIT_BRANCH="main"
INSTALL_DIR="/opt/vm-manage"
SERVICE_NAME="vm-manage"
PORT=8090
NOVNC_DIR="/usr/share/novnc"
NOVNC_REPO="https://github.com/novnc/noVNC.git"

echo "=========================================="
echo " VM Manager Web UI - インストールスクリプト"
echo "=========================================="

if [ "$(id -u)" -ne 0 ]; then
    echo "エラー: このスクリプトは root で実行してください"
    exit 1
fi

# ---------- OS 判別 ----------
# DISTRO_FAMILY: debian (Debian/Ubuntu系) / arch (Arch/CachyOS系) / unknown
detect_distro() {
    local id="" id_like=""
    if [ -f /etc/os-release ]; then
        id=$(grep -E '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"'"'" | tr '[:upper:]' '[:lower:]')
        id_like=$(grep -E '^ID_LIKE=' /etc/os-release | cut -d= -f2 | tr -d '"'"'" | tr '[:upper:]' '[:lower:]')
    fi
    case " ${id} ${id_like} " in
        *" arch "*|*" cachyos "*|*" manjaro "*|*" endeavouros "*|*" garuda "*)
            echo "arch" ;;
        *" debian "*|*" ubuntu "*|*" linuxmint "*|*" pop "*|*" raspbian "*)
            echo "debian" ;;
        *)
            if [ -f /etc/arch-release ]; then
                echo "arch"
            elif [ -f /etc/debian_version ]; then
                echo "debian"
            elif command -v pacman >/dev/null 2>&1; then
                echo "arch"
            elif command -v apt-get >/dev/null 2>&1; then
                echo "debian"
            else
                echo "unknown"
            fi
            ;;
    esac
}

DISTRO_FAMILY=$(detect_distro)
echo ""
echo " 検出ディストリビューション: ${DISTRO_FAMILY}"
if [ "${DISTRO_FAMILY}" = "unknown" ]; then
    echo "警告: 未対応のディストリビューションです。Debian系として続行しますが動作は保証されません。"
    DISTRO_FAMILY="debian"
fi

echo ""
# CachyOS/Arch: pacman のデータベースロック対策。
# 別プロセスの pacman/pamac/yay/paru が動作中でなければ残留ロックを除去する。
# 「データベースをロックできません」対策 (stale /var/lib/pacman/db.lck)。
wait_for_pacman_lock() {
    local lock="/var/lib/pacman/db.lck"
    local waited=0
    local max_wait=120
    while [ -e "${lock}" ]; do
        if pgrep -x pacman >/dev/null 2>&1 \
            || pgrep -x pamac >/dev/null 2>&1 \
            || pgrep -x yay >/dev/null 2>&1 \
            || pgrep -x paru >/dev/null 2>&1 \
            || pgrep -x packagekitd >/dev/null 2>&1; then
            if [ "${waited}" -ge "${max_wait}" ]; then
                echo "エラー: pacman がロック中です (${lock})。他プロセス終了後に再実行してください"
                echo "  確認: pgrep -a pacman; pgrep -a pamac; ls -l ${lock}"
                exit 1
            fi
            echo "  pacman が使用中のため待機しています... (${waited}s/${max_wait}s)"
            sleep 5
            waited=$((waited + 5))
        else
            echo "  残留ロックを検出: ${lock} (pacman プロセスなしのため削除します)"
            rm -f "${lock}" || {
                echo "エラー: ${lock} を削除できません"
                exit 1
            }
            break
        fi
    done
}
if [ "${DISTRO_FAMILY}" = "arch" ]; then
    echo "[1/9] システムパッケージをインストール中... (pacman)"
    wait_for_pacman_lock
    pacman -Sy --needed --noconfirm \
        python \
        python-pip \
        libvirt \
        libvirt-python \
        qemu-desktop \
        qemu-system-x86 \
        qemu-img \
        edk2-ovmf \
        swtpm \
        dnsmasq \
        iptables \
        usbutils \
        sudo \
        curl \
        git \
        wget \
        psmisc \
        lsof
else
    echo "[1/9] システムパッケージをインストール中... (apt)"
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
fi

echo "[2/9] libvirtd サービスを有効化中..."
systemctl enable --now libvirtd.service
# 既定NATネットワーク (default) のサブネット衝突を回避して自動起動・起動する。
# ネストVM環境では外側の DHCP/NAT (例: 192.168.122.0/24) と virbr0 (既定 192.168.122.1)
# が同サブネット・同IPになり、ゲートウェイ/DNS (192.168.122.1) への経路が壊れる。
# virbr0 以外の NIC/ルートで使用中の /24 と衝突する場合は空きサブネットに付け替える。
ensure_default_net() {
    local candidates="192.168.124.1 192.168.123.1 192.168.125.1 10.20.30.1"
    local cur_ip="" cur_net="" candidate="" net24=""
    if virsh net-dumpxml default >/dev/null 2>&1; then
        cur_ip=$(virsh net-dumpxml default 2>/dev/null | grep -oP "(?<=<ip address=')[^']+" | head -n1)
    fi
    if [ -n "${cur_ip}" ]; then
        cur_net=$(echo "${cur_ip}" | cut -d. -f1-3).0/24
        # virbr0 以外で同サブネットを使っていなければ現状維持
        if ! ip -o route show | grep -v 'virbr0' | grep -q "${cur_net}" \
            && ! ip -o addr show | grep -v 'virbr0' | grep -q "${cur_ip}/"; then
            virsh net-autostart default >/dev/null 2>&1 || true
            virsh net-start default >/dev/null 2>&1 || true
            echo "  default ネットワーク: ${cur_ip} (衝突なし)"
            return 0
        fi
        echo "  警告: default ネット (${cur_ip}/${cur_net}) がホスト側と衝突しています。付け替えます"
    fi
    for candidate in ${candidates}; do
        net24=$(echo "${candidate}" | cut -d. -f1-3).0/24
        if ip -o route show | grep -q "${net24}"; then
            continue
        fi
        if ip -o addr show | grep -q "${candidate}/"; then
            continue
        fi
        # 衝突する既存 default ネットを破棄して作り直す
        virsh net-destroy default >/dev/null 2>&1 || true
        virsh net-undefine default >/dev/null 2>&1 || true
        virsh net-define /dev/stdin <<NETEOF >/dev/null
<network>
  <name>default</name>
  <forward mode='nat'/>
  <bridge name='virbr0' stp='on' delay='0'/>
  <ip address='${candidate}' netmask='255.255.255.0'>
    <dhcp>
      <range start='$(echo "${candidate}" | cut -d. -f1-3).2' end='$(echo "${candidate}" | cut -d. -f1-3).254'/>
    </dhcp>
  </ip>
</network>
NETEOF
        virsh net-autostart default >/dev/null 2>&1 || true
        virsh net-start default >/dev/null 2>&1 || true
        echo "  default ネットワークを ${candidate}/24 に付け替えました"
        return 0
    done
    # 空き候補が無い場合は従来通り起動だけ試みる
    virsh net-autostart default >/dev/null 2>&1 || true
    virsh net-start default >/dev/null 2>&1 || true
}
ensure_default_net

echo "[3/9] ストレージプールを設定中..."
VM_DIR="/opt/vm"
# Btrfs 上では VM イメージ用に /opt/vm をサブボリューム化する (主に CachyOS 想定だが他 distro でも有効)。
# 理由: (1) snapper 等の親スナップショットから除外して肥大化を防ぐ
#       (2) COW/圧縮を無効化して qcow2/raw の断片化・速度低下を防ぐ
# ネストしたサブボリュームは fstab 不要で自動的にマウントされる。
if findmnt -n -o FSTYPE -T /opt 2>/dev/null | grep -qi '^btrfs$' \
    || stat -f -c %T /opt 2>/dev/null | grep -qi btrfs; then
    echo "  Btrfs を検出: ${VM_DIR} をサブボリュームとして用意します"
    if [ -e "${VM_DIR}" ] && ! btrfs subvolume show "${VM_DIR}" >/dev/null 2>&1; then
        if [ -d "${VM_DIR}" ] && [ -z "$(ls -A "${VM_DIR}" 2>/dev/null)" ]; then
            echo "  空の通常ディレクトリをサブボリュームに置き換えます"
            rmdir "${VM_DIR}"
        elif [ -e "${VM_DIR}" ]; then
            BACKUP="${VM_DIR}.bak.$(date +%Y%m%d%H%M%S)"
            echo "  既存の ${VM_DIR} は通常ディレクトリのため ${BACKUP} に退避します"
            # プールが掴んでいると mv/rmdir できないため先に停止する
            virsh pool-destroy default >/dev/null 2>&1 || true
            mv "${VM_DIR}" "${BACKUP}"
            echo "  退避先: ${BACKUP} (内容確認後に手動で戻すか削除してください)"
        fi
    fi
    if [ ! -e "${VM_DIR}" ]; then
        btrfs subvolume create "${VM_DIR}"
    fi
    # VM イメージは COW・圧縮なしが定石。空の状態で NOCOW 継承フラグを付与する。
    # 既存ファイルがある場合も以降の新規ファイルには継承される。
    chattr +C "${VM_DIR}" 2>/dev/null || echo "  警告: chattr +C に失敗しました (COW 無効化をスキップ)"
    btrfs property set "${VM_DIR}" compression none >/dev/null 2>&1 || true
    echo "  サブボリューム確認:"
    btrfs subvolume show "${VM_DIR}" | head -n 8 || true
    lsattr -d "${VM_DIR}" || true
fi
mkdir -p /opt/vm
# Arch では libvirt グループ、Debian 互換で libvirt-qemu も試す
if getent group libvirt >/dev/null 2>&1; then
    chown root:libvirt /opt/vm 2>/dev/null || chown root:libvirt-qemu /opt/vm 2>/dev/null || true
else
    chown root:libvirt-qemu /opt/vm 2>/dev/null || true
fi
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
    if [ "${DISTRO_FAMILY}" = "arch" ]; then
        wait_for_pacman_lock
        pacman -S --needed --noconfirm tailscale
    else
        curl -fsSL https://tailscale.com/install.sh | sh
    fi
fi
systemctl enable --now tailscaled.service >/dev/null 2>&1 || true

echo "[5/9] アプリケーションを GitHub から取得中..."
if ! command -v git >/dev/null 2>&1; then
    echo "  git が未インストールのためインストールします..."
    if [ "${DISTRO_FAMILY}" = "arch" ]; then
        wait_for_pacman_lock
        pacman -S --needed --noconfirm git
    else
        apt-get install -y -qq git
    fi
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
# libvirt の system バインディングを使うため --system-site-packages を付ける
python3 -m venv --system-site-packages "${INSTALL_DIR}/venv"
chmod +x "${INSTALL_DIR}/venv/bin/python"

echo "[7/9] Flask / websockify をインストール中..."
"${INSTALL_DIR}/venv/bin/pip" install --quiet --upgrade pip
"${INSTALL_DIR}/venv/bin/pip" install --quiet flask flask-sock simple-websocket websockify
# systemd から起動した app.py が venv 外からでも websockify を見つけられるよう symlink
ln -sf "${INSTALL_DIR}/venv/bin/websockify" /usr/local/bin/websockify 2>/dev/null || true

if [ "${DISTRO_FAMILY}" = "arch" ]; then
    echo "[7b/9] noVNC を配置中... (${NOVNC_DIR})"
    if [ ! -d "${NOVNC_DIR}/core" ]; then
        rm -rf "${NOVNC_DIR}"
        git clone --depth 1 "${NOVNC_REPO}" "${NOVNC_DIR}"
    else
        echo "  noVNC は既に存在します"
    fi
fi

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
