# new-network-automation-dashboard/routes/backup_routes.py

from flask import Blueprint, request, jsonify
from services.ssh_utils import fetch_running_config
from services.action_logger import action_logger
from config import BACKUP_DIR
from datetime import datetime
import os, json, yaml

backup_bp = Blueprint("backup", __name__)

@backup_bp.route("/run", methods=["POST"])
def run_backup():
    payload = request.get_json() or {}
    ip = payload.get("ip")
    username = payload.get("username")
    password = payload.get("password")
    secret = payload.get("enable_password") or payload.get("secret")
    device_type = payload.get("device_type", "ovs")   # 👈 default = ovs
    dry_run = bool(payload.get("dry_run", False))

    if not ip or not username or not password:
        return jsonify({"error": "ip, username, password are required"}), 400

    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    backup_base = os.path.join(BACKUP_DIR, f"{ip}_{ts}")
    os.makedirs(backup_base, exist_ok=True)

    if dry_run:
        # Simulate output
        output = f"! DRY RUN OVS backup for {ip} at {ts}\nbridge {ip}\n! end"
        success = True
        engine = "dry_run"
    else:
        success, output, engine = fetch_running_config(
            ip, username, password, secret=secret, device_type=device_type
        )

    if not success:
        action_logger(f"[BACKUP][FAIL] ip={ip} engine={engine}")
        return jsonify({"ok": False, "engine": engine, "error": output}), 500

    cfg_path = os.path.join(backup_base, "running-config.txt")
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write(output)

    meta = {
        "ip": ip,
        "device_type": device_type,
        "timestamp_utc": ts,
        "engine": engine,
        "bytes": len(output),
    }
    with open(os.path.join(backup_base, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    with open(os.path.join(backup_base, "meta.yaml"), "w", encoding="utf-8") as f:
        yaml.safe_dump(meta, f, sort_keys=False)

    action_logger(f"[BACKUP][OK] ip={ip} bytes={len(output)} engine={engine}")
    return jsonify({"ok": True, "engine": engine, "config_path": cfg_path, "meta": meta})
