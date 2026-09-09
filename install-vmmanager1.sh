#!/bin/bash
# 互換用シム (v1.3.0 で install-vmmanager.sh に統合)
# 実体: https://github.com/hirogura/vmmanager/blob/main/install-vmmanager.sh
# 旧 URL で取得した場合は統合スクリプトをダウンロードして実行する。
set -e

CANONICAL_URL="https://raw.githubusercontent.com/hirogura/vmmanager/main/install-vmmanager.sh"

if [ "$(id -u)" -ne 0 ]; then
    echo "エラー: このスクリプトは root で実行してください"
    exit 1
fi

echo "旧スクリプト名で実行されました。統合スクリプトを取得して実行します..."
echo "  ${CANONICAL_URL}"
exec bash -c "$(curl -fsSL "${CANONICAL_URL}")" install-vmmanager.sh "$@"
