#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${PROJECT_DIR}/.venv"

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

if ! need_cmd "${PYTHON_BIN}"; then
  echo "ERROR: ${PYTHON_BIN} not found."
  echo "Install Python 3 first."
  if need_cmd apt-get; then
    echo "Example (Debian/Ubuntu): sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip"
  fi
  exit 1
fi

echo "==> Creating virtual environment: ${VENV_DIR}"
"${PYTHON_BIN}" -m venv "${VENV_DIR}"

echo "==> Installing dependencies"
"${VENV_DIR}/bin/pip" install --upgrade pip
"${VENV_DIR}/bin/pip" install -r "${PROJECT_DIR}/requirements.txt"

echo "==> Running migrations"
(
  cd "${PROJECT_DIR}"
  "${VENV_DIR}/bin/python" manage.py migrate
  "${VENV_DIR}/bin/python" manage.py check
)

echo
echo "Setup complete."
echo "Start server with:"
echo "  ./run-ports-web.sh"
echo
echo "Then configure AMP/OpenWrt from UI:"
echo "  http://127.0.0.1:8001/providers"
