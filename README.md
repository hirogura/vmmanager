# vmmanager

libvirt / QEMU 上の仮想マシンを Web ブラウザから管理するための Web UI です。

## 概要

- Python (Flask) + libvirt ベースの Web アプリケーション
- systemd サービス (`vm-manage`) として動作
- [Tailscale serve](https://tailscale.com) により HTTPS 化し、**Tailnet 内からのみ**アクセス可能
- アプリは `127.0.0.1:8090` のみで待ち受けるため、**LAN からは直接アクセス不可**

<img width="512" height="371" alt="Image" src="https://github.com/user-attachments/assets/69ae861b-93c6-4417-a901-96af7a467dfa" />

## インストール方法

インストールスクリプトを GitHub からダウンロードして、root で実行します。

```bash
cd ~
curl -fsSL https://raw.githubusercontent.com/hirogura/vmmanager/main/install-vmmanager1.sh -o install-vmmanager1.sh
chmod +x install-vmmanager1.sh
sudo ./install-vmmanager1.sh
```

### インストールスクリプトが行うこと

1. システムパッケージのインストール（Python, libvirt, QEMU, noVNC など）
2. `libvirtd` サービスの有効化
3. Tailscale のインストール（未導入の場合）
4. GitHub リポジトリからアプリ本体を `/opt/vm-manage` に取得
5. Python 仮想環境と Flask のセットアップ
6. systemd サービス (`vm-manage.service`) の作成・起動
7. `tailscale serve` でポート `8090` を HTTPS 公開（Tailnet 内のみ）
   - さらに `/websockify` を VNC コンソール（WebSocket）用に同じ `8090` 上で公開

### アクセス方法

インストール完了時に表示される URL からアクセスします。

```
https://<マシン名>.<テイルネット名>.ts.net:8090
```

例: `https://myhost.my-tailnet.ts.net:8090`

- アクセスできるのは **同じ Tailnet にログインしている端末のみ** です
- HTTPS 証明書は Tailscale が自動で発行します
- Tailscale に未ログインの場合は、初回実行時に `tailscale up` の認証が必要です
  （表示される URL をブラウザで開いてログインしてください）

## アンインストール方法

サービスとアプリ本体を削除します。

```bash
sudo systemctl stop vm-manage.service
sudo systemctl disable vm-manage.service
sudo rm -f /etc/systemd/system/vm-manage.service
sudo systemctl daemon-reload
sudo rm -rf /opt/vm-manage
```

Tailscale serve の公開設定も削除する場合:

```bash
sudo tailscale serve --https=8090 off
sudo tailscale serve --https=8090 --set-path=/websockify off
```

Tailscale 自体をアンインストールする場合:

```bash
sudo tailscale logout
sudo apt remove -y tailscale
```

※ VM 本体（libvirt で管理されている仮想マシンやディスク）は削除されません。仮想マシン自体を削除する場合は別途 `virsh` などを使用してください。

## 開発

```bash
cd /opt/vm-manage
python3 -m venv --system-site-packages venv
venv/bin/pip install flask
venv/bin/python app.py   # http://127.0.0.1:8090
```
<img width="512" height="327" alt="Image" src="https://github.com/user-attachments/assets/0e960f37-8bf6-4561-88c8-f1ab387fa69a" />

## ライセンス

このプロジェクトは [MIT License](LICENSE) の下で公開されています。
