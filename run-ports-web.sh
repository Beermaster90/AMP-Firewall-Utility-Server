#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8001}"

exec ./.venv/bin/python manage.py runserver "${HOST}:${PORT}"
