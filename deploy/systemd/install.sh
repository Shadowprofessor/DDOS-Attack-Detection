#!/usr/bin/env bash
# ==============================================================================
# Bare-Metal Systemd Installation Script for DDoS Attack Detection & Mitigation
# ==============================================================================
set -euo pipefail

INSTALL_DIR="/opt/ddos-defense"
CONFIG_DIR="/etc/ddos-defense"
SERVICE_USER="ddos"

echo "=== Installing DDoS Detection & Mitigation System (Bare-Metal) ==="

# 1. Create dedicated service user and group if not present
if ! id "${SERVICE_USER}" &>/dev/null; then
    echo "Creating system user '${SERVICE_USER}'..."
    useradd -r -s /bin/false -d "${INSTALL_DIR}" "${SERVICE_USER}"
fi

# 2. Create directories
echo "Creating application and configuration directories..."
mkdir -p "${INSTALL_DIR}"
mkdir -p "${CONFIG_DIR}"
mkdir -p "${INSTALL_DIR}/models"
mkdir -p "${INSTALL_DIR}/data"

# 3. Copy application files if installing from current repo
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
echo "Copying source files from ${SCRIPT_DIR} to ${INSTALL_DIR}..."
cp -r "${SCRIPT_DIR}/src" "${INSTALL_DIR}/"
cp -r "${SCRIPT_DIR}/Codes" "${INSTALL_DIR}/"
cp -r "${SCRIPT_DIR}/models" "${INSTALL_DIR}/"
cp -r "${SCRIPT_DIR}/config" "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/requirements.txt" "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/run_ryu.py" "${INSTALL_DIR}/"

# 4. Set up Python virtual environment
echo "Setting up Python virtual environment in ${INSTALL_DIR}/venv..."
python3 -m venv "${INSTALL_DIR}/venv"
"${INSTALL_DIR}/venv/bin/pip" install --upgrade pip
"${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"
"${INSTALL_DIR}/venv/bin/pip" install uvicorn[standard] websockets

# 5. Setup environment configuration
if [ ! -f "${CONFIG_DIR}/ddos-defense.env" ]; then
    echo "Creating default environment file at ${CONFIG_DIR}/ddos-defense.env..."
    cp "${SCRIPT_DIR}/deploy/systemd/ddos-defense.env.example" "${CONFIG_DIR}/ddos-defense.env"
    chmod 600 "${CONFIG_DIR}/ddos-defense.env"
    chown "${SERVICE_USER}:${SERVICE_USER}" "${CONFIG_DIR}/ddos-defense.env"
fi

# 6. Copy systemd units
echo "Installing systemd unit files..."
cp "${SCRIPT_DIR}/deploy/systemd/ddos-scoring.service" /etc/systemd/system/
cp "${SCRIPT_DIR}/deploy/systemd/ddos-controller.service" /etc/systemd/system/

# 7. Configure Nginx if present
if command -v nginx &>/dev/null; then
    echo "Configuring Nginx reverse proxy..."
    cp "${SCRIPT_DIR}/deploy/systemd/nginx-site.conf" /etc/nginx/sites-available/ddos-defense.conf
    ln -sf /etc/nginx/sites-available/ddos-defense.conf /etc/nginx/sites-enabled/
    nginx -t && systemctl reload nginx
fi

# 8. Set permissions
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}"

# 9. Reload systemd daemon
systemctl daemon-reload
echo "=== Installation complete ==="
echo "To start services:"
echo "  sudo systemctl enable --now ddos-scoring.service"
echo "  sudo systemctl enable --now ddos-controller.service"
