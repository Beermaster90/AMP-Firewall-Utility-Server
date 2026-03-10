#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="arksa-ports-web.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
SERVICE_TEMPLATE="${PROJECT_DIR}/${SERVICE_NAME}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this script as root:"
  echo "  sudo ./install-systemd-service.sh"
  exit 1
fi

if [[ ! -f "${SERVICE_TEMPLATE}" ]]; then
  echo "Missing service template: ${SERVICE_TEMPLATE}"
  exit 1
fi

RUN_USER="${SUDO_USER:-$(stat -c '%U' "${PROJECT_DIR}")}"
if [[ -z "${RUN_USER}" || "${RUN_USER}" == "root" ]]; then
  echo "Could not determine a non-root runtime user."
  echo "Run this with sudo from the intended application user account."
  exit 1
fi

RUN_GROUP="$(id -gn "${RUN_USER}")"

sed \
  -e "s#__RUN_USER__#${RUN_USER}#g" \
  -e "s#__RUN_GROUP__#${RUN_GROUP}#g" \
  -e "s#__PROJECT_DIR__#${PROJECT_DIR}#g" \
  "${SERVICE_TEMPLATE}" > "${SERVICE_PATH}"
chmod 0644 "${SERVICE_PATH}"
systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"

echo
echo "Installed and started ${SERVICE_NAME}"
echo "Runtime user: ${RUN_USER}"
echo "Project dir:   ${PROJECT_DIR}"
echo
systemctl --no-pager --full status "${SERVICE_NAME}" || true
