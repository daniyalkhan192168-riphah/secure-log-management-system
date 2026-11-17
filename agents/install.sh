#!/usr/bin/env bash
# Installs the SecureLog agent as a systemd service.
#   sudo bash install.sh              (uses agent.conf in this folder)
#   sudo bash install.sh /path/agent.conf
#   sudo bash install.sh --uninstall
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SERVICE=securelog-agent

if [[ $EUID -ne 0 ]]; then
    echo "Please run with sudo:  sudo bash $0 $*"; exit 1
fi

if [[ "${1:-}" == "--uninstall" ]]; then
    systemctl disable --now "$SERVICE" 2>/dev/null || true
    rm -f /etc/systemd/system/$SERVICE.service
    systemctl daemon-reload
    rm -rf /opt/securelog-agent
    echo "Removed the service and program."
    echo "Kept /etc/securelog-agent (config) and /var/lib/securelog-agent (queue + position)."
    echo "Delete them by hand if you no longer need them."
    exit 0
fi

CONF_SRC="${1:-$HERE/agent.conf}"
for f in "$HERE/ubuntu_log_agent.py" "$HERE/$SERVICE.service" "$CONF_SRC"; do
    [[ -f "$f" ]] || { echo "Missing file: $f"; exit 1; }
done
grep -q '^api_key' "$CONF_SRC" || { echo "$CONF_SRC has no api_key line"; exit 1; }

echo "[1/5] creating system user '$SERVICE'"
id "$SERVICE" &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE"

echo "[2/5] installing program to /opt/securelog-agent"
install -d -m 755 /opt/securelog-agent
install -m 755 "$HERE/ubuntu_log_agent.py" /opt/securelog-agent/

echo "[3/5] installing config to /etc/securelog-agent (readable only by root and the agent)"
install -d -m 750 -o root -g "$SERVICE" /etc/securelog-agent
install -m 640 -o root -g "$SERVICE" "$CONF_SRC" /etc/securelog-agent/agent.conf
# the service manages its own state directory
sed -i '/^state_dir/d' /etc/securelog-agent/agent.conf

echo "[4/5] installing systemd service"
install -m 644 "$HERE/$SERVICE.service" /etc/systemd/system/
systemctl daemon-reload

echo "[5/5] starting service (and enabling it at boot)"
systemctl enable --now "$SERVICE"
sleep 2
systemctl --no-pager --lines=8 status "$SERVICE" || true

echo
echo "Done. Useful commands:"
echo "  sudo systemctl status $SERVICE        # is it running?"
echo "  sudo journalctl -u $SERVICE -f        # watch what it does"
echo "  sudo systemctl restart $SERVICE       # after editing /etc/securelog-agent/agent.conf"