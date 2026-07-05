#!/usr/bin/env bash
set -euo pipefail

# Deploy this app to the Tencent Cloud server.
# Defaults match the current production deployment. Override with env vars if needed:
#   HOST=1.2.3.4 REMOTE_USER=ubuntu PORT=8765 ./deploy.sh

HOST="${HOST:-43.143.122.43}"
REMOTE_USER="${REMOTE_USER:-ubuntu}"
PORT="${PORT:-8765}"
REMOTE="${REMOTE_USER}@${HOST}"
REMOTE_APP="${REMOTE_APP:-/home/${REMOTE_USER}/ai-candidate-screener-sqlite}"
REMOTE_PKG="/home/${REMOTE_USER}/ai-candidate-screener-sqlite.tar.gz"
REMOTE_SCRIPT="/home/${REMOTE_USER}/deploy_ai_screener.sh"
SERVICE_NAME="${SERVICE_NAME:-ai-candidate-screener}"
SSH_OPTS=(-o StrictHostKeyChecking=accept-new)

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG="/tmp/ai-candidate-screener-sqlite.tar.gz"
LOCAL_REMOTE_SCRIPT="$(mktemp)"
trap 'rm -f "$LOCAL_REMOTE_SCRIPT"' EXIT

echo "Packaging ${APP_DIR}"
tar \
  --exclude='./data/candidates.sqlite3' \
  --exclude='./server.log' \
  --exclude='./__pycache__' \
  -czf "$PKG" \
  -C "$APP_DIR" .

cat > "$LOCAL_REMOTE_SCRIPT" <<REMOTE_SH
#!/usr/bin/env bash
set -euo pipefail

APP="${REMOTE_APP}"
PKG="${REMOTE_PKG}"
TMP="/home/${REMOTE_USER}/ai-candidate-screener-new"
SERVICE_NAME="${SERVICE_NAME}"
PORT="${PORT}"

rm -rf "\$TMP"
mkdir -p "\$TMP"
tar -xzf "\$PKG" -C "\$TMP"
mkdir -p "\$TMP/data"

if [ -f "\$APP/data/candidates.sqlite3" ]; then
  cp "\$APP/data/candidates.sqlite3" "/home/${REMOTE_USER}/candidates.sqlite3.backup.\$(date +%Y%m%d%H%M%S)"
  cp "\$APP/data/candidates.sqlite3" "\$TMP/data/candidates.sqlite3"
fi

rm -rf "\$APP.prev"
if [ -d "\$APP" ]; then mv "\$APP" "\$APP.prev"; fi
mv "\$TMP" "\$APP"

python3 -m py_compile "\$APP/server.py"

cat > "/tmp/\${SERVICE_NAME}.service" <<UNIT
[Unit]
Description=AI Candidate Screener SQLite Server
After=network.target

[Service]
Type=simple
User=${REMOTE_USER}
WorkingDirectory=\$APP
ExecStart=/usr/bin/python3 \$APP/server.py --host 0.0.0.0 --port \$PORT
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
UNIT

sudo mv "/tmp/\${SERVICE_NAME}.service" "/etc/systemd/system/\${SERVICE_NAME}.service"
sudo systemctl daemon-reload
sudo systemctl enable --now "\$SERVICE_NAME"
sudo systemctl restart "\$SERVICE_NAME"
sleep 1
systemctl is-active "\$SERVICE_NAME"
curl -sS "http://127.0.0.1:\${PORT}/api/health"
REMOTE_SH

echo "Uploading package to ${REMOTE}:${REMOTE_PKG}"
scp "${SSH_OPTS[@]}" "$PKG" "${REMOTE}:${REMOTE_PKG}"

echo "Uploading deploy script to ${REMOTE}:${REMOTE_SCRIPT}"
scp "${SSH_OPTS[@]}" "$LOCAL_REMOTE_SCRIPT" "${REMOTE}:${REMOTE_SCRIPT}"

echo "Running remote deploy"
ssh "${SSH_OPTS[@]}" -t "$REMOTE" "bash '${REMOTE_SCRIPT}'"

echo
echo "Checking public health endpoint"
curl -sS --max-time 10 "http://${HOST}:${PORT}/api/health"
echo
echo "Done: http://${HOST}:${PORT}/"
