#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8001}"

LAN_IP=""
if command -v ip >/dev/null 2>&1; then
  LAN_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')"
fi
if [[ -z "${LAN_IP}" ]]; then
  LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
fi

echo "Starting AMP Firewall Utility Server"
if [[ "${HOST}" == "0.0.0.0" ]]; then
  echo "Local:   http://127.0.0.1:${PORT}/"
  if [[ -n "${LAN_IP}" ]]; then
    echo "Network: http://${LAN_IP}:${PORT}/"
  fi
else
  echo "URL:     http://${HOST}:${PORT}/"
fi

exec ./.venv/bin/python manage.py runserver "${HOST}:${PORT}"
