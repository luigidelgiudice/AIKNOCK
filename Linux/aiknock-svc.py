#!/usr/bin/env python3
"""
AIKNOCK Decision Plane Service — Linux port
============================================
Equivalent of aiknock-svc.exe (Windows Phase 2).

Platform:   Ubuntu 24.04 LTS / any systemd Linux
Transport:  AF_UNIX socket  /run/aiknock/aiknock.sock
Key store:  /etc/aiknock/audit-hmac-v1.key  (root:root 0600)
Audit:      /var/log/aiknock/audit-YYYY-MM-DD.jsonl
Log:        /var/log/aiknock/aiknock-svc.log

Installation:
    sudo cp aiknock-svc.py /usr/local/bin/aiknock-svc
    sudo chmod +x /usr/local/bin/aiknock-svc
    sudo ln -sf /usr/local/lib/aiknock /usr/local/lib/core
    sudo systemctl enable --now aiknock

Verified: Ubuntu 24.04.4 LTS, Python 3.12.3, CHAIN OK: 6 records
"""
import sys
sys.path.insert(0, '/usr/local/lib')

import os
import json
import socket
import signal
import logging
import secrets
import stat
from pathlib import Path
from datetime import date, datetime, timezone

from core.decision_plane import DecisionPlane, PolicyRegistry, DecisionContext
from core.audit_chain import AppendOnlyChain, Decision

SOCKET_PATH = "/run/aiknock/aiknock.sock"
AUDIT_DIR   = "/var/log/aiknock"
KEY_PATH    = "/etc/aiknock/audit-hmac-v1.key"
LOG_PATH    = "/var/log/aiknock/aiknock-svc.log"
POLICY_ID   = "AIKNOCK-BASE-01"

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)
log = logging.getLogger("aiknock-svc")


def load_or_create_key(path: str) -> bytes:
    p = Path(path)
    if p.exists():
        log.info("Key loaded from %s", path)
        return p.read_bytes()
    key = secrets.token_bytes(32)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(key)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    log.info("Key generated at %s", path)
    return key


def base_policy(request: DecisionContext):
    return Decision.ALLOW, ()


def handle_connection(conn: socket.socket, plane: DecisionPlane) -> None:
    try:
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\n" in data:
                break
        if not data:
            return
        req = json.loads(data.decode().strip())
        ctx = DecisionContext(
            system_state=req.get("system_state", "Linux"),
            governance_context=req.get("governance_context",
                                       req.get("context", "")),
            intent=req.get("intent", ""),
            policy_id=req.get("policy_id", POLICY_ID),
        )
        ts = datetime.now(timezone.utc).isoformat()
        result = plane.evaluate(ctx, ts)
        response = {
            "decision":       str(result.decision),
            "constraint_set": list(result.constraint_set),
            "record_hmac":    result.record_hmac,
        }
        conn.sendall((json.dumps(response) + "\n").encode())
        log.info("decision=%s governance_context=%s intent=%s",
                 result.decision, ctx.governance_context, ctx.intent)
    except Exception as e:
        log.error("handler error: %s", e)
        try:
            conn.sendall((json.dumps({
                "decision": "BLOCK",
                "constraint_set": [],
                "record_hmac": "",
            }) + "\n").encode())
        except Exception:
            pass
    finally:
        conn.close()


def main() -> None:
    log.info("AIKNOCK Decision Plane starting")
    key = load_or_create_key(KEY_PATH)
    audit_file = Path(f"{AUDIT_DIR}/audit-{date.today().isoformat()}.jsonl")
    chain = AppendOnlyChain(path=audit_file, key=key)
    registry = PolicyRegistry()
    registry.register(POLICY_ID, base_policy)
    plane = DecisionPlane(registry, chain)
    sock_dir = Path(SOCKET_PATH).parent
    sock_dir.mkdir(parents=True, exist_ok=True)
    if Path(SOCKET_PATH).exists():
        Path(SOCKET_PATH).unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0o666)
    server.listen(10)
    log.info("Listening on %s", SOCKET_PATH)
    print(f"AIKNOCK Decision Plane listening on {SOCKET_PATH}", flush=True)

    def shutdown(signum, frame):
        log.info("AIKNOCK Decision Plane stopping")
        server.close()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    while True:
        try:
            conn, _ = server.accept()
            handle_connection(conn, plane)
        except OSError:
            break


if __name__ == "__main__":
    main()
