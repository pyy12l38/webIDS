#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$ROOT_DIR/.venv"
REQ_FILE="$ROOT_DIR/requirements.txt"

if ! command -v python3.11 >/dev/null 2>&1; then
  echo "未找到 python3.11，请先安装 Python 3.11。"
  exit 1
fi

if [[ ! -f "$REQ_FILE" ]]; then
  echo "缺少 requirements.txt，无法重建虚拟环境。"
  exit 1
fi

if [[ -d "$VENV_DIR" ]]; then
  BACKUP_DIR="$ROOT_DIR/.venv.bak.$(date +%Y%m%d_%H%M%S)"
  mv "$VENV_DIR" "$BACKUP_DIR"
  echo "已备份旧虚拟环境到: $BACKUP_DIR"
fi

python3.11 -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel
"$VENV_DIR/bin/pip" install -r "$REQ_FILE"

echo
echo "虚拟环境已重建完成。"
echo "激活命令:"
echo "source .venv/bin/activate"
