#!/bin/bash
# AIKNOCK Linux Installation Script
# Verified: Ubuntu 24.04.4 LTS, Python 3.12.3
# Usage: sudo bash install-linux.sh

set -e

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== AIKNOCK Linux Installer ==="
echo "Repository: $REPO_DIR"

# 1. Create directories
echo "[1/6] Creating directories..."
mkdir -p /etc/aiknock
mkdir -p /var/log/aiknock
mkdir -p /usr/local/lib/aiknock
mkdir -p /run/aiknock

# 2. Copy core Python library
echo "[2/6] Installing core library..."
cp -r "$REPO_DIR/core/"* /usr/local/lib/aiknock/

# 3. Create symlink so 'from core.X import' resolves correctly
echo "[3/6] Creating core symlink..."
ln -sf /usr/local/lib/aiknock /usr/local/lib/core

# 4. Install service binary
echo "[4/6] Installing service binary..."
cp "$REPO_DIR/linux/aiknock-svc.py" /usr/local/bin/aiknock-svc
chmod +x /usr/local/bin/aiknock-svc

# 5. Install systemd unit
echo "[5/6] Installing systemd unit..."
cp "$REPO_DIR/linux/aiknock.service" /etc/systemd/system/aiknock.service
systemctl daemon-reload
systemctl enable aiknock

# 6. Start service
echo "[6/6] Starting service..."
systemctl start aiknock
sleep 2
systemctl status aiknock --no-pager

echo ""
echo "=== Installation complete ==="
echo "Test with:"
echo "  echo '{\"governance_context\":\"test\",\"intent\":\"invoke-ai\",\"policy_id\":\"AIKNOCK-BASE-01\",\"system_state\":\"Linux\"}' | socat - UNIX-CONNECT:/run/aiknock/aiknock.sock"
echo ""
echo "Verify audit chain:"
echo "  sudo python3 -c \""
echo "  import sys; sys.path.insert(0,'/usr/local/lib')"
echo "  from core.audit_chain import AppendOnlyChain, verify_chain"
echo "  from pathlib import Path"
echo "  import glob"
echo "  key = open('/etc/aiknock/audit-hmac-v1.key','rb').read()"
echo "  f = sorted(glob.glob('/var/log/aiknock/audit-*.jsonl'))[-1]"
echo "  n = verify_chain(AppendOnlyChain(path=Path(f), key=key))"
echo "  print(f'CHAIN OK: {n} records')\""
