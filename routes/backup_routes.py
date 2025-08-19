# routes/backup_routes.py

from flask import Blueprint, request, jsonify
from services.ssh_utils import fetch_running_config
from services.action_logger import action_logger
from config import BACKUP_DIR
from datetime import datetime
import os, json, yaml

backup_bp = Blueprint("backup", __name__)

@backup_bp.route("/run", methods=["POST"])
def run_backup():
    try:
        payload = request.get_json() or {}
        print("[DEBUG] Payload received:", payload)

        ip = payload.get("ip", "").strip()
        username = payload.get("username", "").strip()
        password = payload.get("password", "").strip()
        secret = payload.get("enable_password") or payload.get("secret", "").strip()
        device_type = payload.get("device_type", "ovs").lower()
        dry_run = bool(payload.get("dry_run", False))

        print(f"[DEBUG] ip={ip}, username={username}, device_type={device_type}, dry_run={dry_run}")

        if not ip or not username or not password:
            print("[DEBUG] Missing required fields")
            return jsonify({"error": "ip, username, and password are required"}), 400

        valid_device_types = ["ovs", "linux", "cisco"]
        if device_type not in valid_device_types:
            print("[DEBUG] Invalid device_type:", device_type)
            return jsonify({"error": f"Invalid device_type. Must be one of: {', '.join(valid_device_types)}"}), 400

        ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        backup_base = os.path.join(BACKUP_DIR, f"{ip}_{ts}")
        print("[DEBUG] Backup directory path:", backup_base)
        
        try:
            os.makedirs(backup_base, exist_ok=True)
            print("[DEBUG] Backup directory created/existed")
        except OSError as e:
            action_logger(f"[BACKUP][ERROR] Failed to create backup directory: {str(e)}")
            print("[DEBUG] Failed to create backup directory:", str(e))
            return jsonify({"error": f"Failed to create backup directory: {str(e)}"}), 500

        if dry_run:
            print("[DEBUG] Performing dry-run backup")
            if device_type == "ovs":
                output = f"! DRY RUN OVS backup for {ip} at {ts}\nbridge br0\n    Port br0\n        Interface br0\n! end"
            elif device_type == "linux":
                output = f"! DRY RUN Linux backup for {ip} at {ts}\n! ip addr show\n1: lo: <LOOPBACK,UP,LOWER_UP>\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>\n! end"
            else:  # cisco
                output = f"! DRY RUN Cisco backup for {ip} at {ts}\nversion 15.1\nhostname Router\n! end"
            
            success = True
            engine = "dry_run"
        else:
            action_logger(f"[BACKUP][START] ip={ip} type={device_type}")
            print("[DEBUG] Calling fetch_running_config()")
            success, output, engine = fetch_running_config(
                ip, username, password, secret=secret, device_type=device_type
            )
            print(f"[DEBUG] fetch_running_config result: success={success}, engine={engine}, output_length={len(output) if output else 0}")

        if not success:
            action_logger(f"[BACKUP][FAIL] ip={ip} engine={engine} error={output}")
            print("[DEBUG] Backup failed:", output)
            return jsonify({
                "ok": False, 
                "engine": engine, 
                "error": output
            }), 500

        cfg_filename = f"running-config-{device_type}.txt"
        cfg_path = os.path.join(backup_base, cfg_filename)
        print("[DEBUG] Saving config to:", cfg_path)
        
        try:
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(output)
            print("[DEBUG] Config file written successfully")
        except IOError as e:
            action_logger(f"[BACKUP][ERROR] Failed to write config file: {str(e)}")
            print("[DEBUG] Failed to write config file:", str(e))
            return jsonify({"error": f"Failed to write config file: {str(e)}"}), 500

        meta = {
            "ip": ip,
            "device_type": device_type,
            "timestamp_utc": ts,
            "timestamp_iso": datetime.utcnow().isoformat() + "Z",
            "engine": engine,
            "bytes": len(output),
            "lines": output.count('\n') + 1,
            "username": username,
            "dry_run": dry_run,
            "config_filename": cfg_filename
        }
        print("[DEBUG] Metadata prepared:", meta)
        
        try:
            with open(os.path.join(backup_base, "meta.json"), "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)
            
            with open(os.path.join(backup_base, "meta.yaml"), "w", encoding="utf-8") as f:
                yaml.safe_dump(meta, f, sort_keys=False, default_flow_style=False)
            print("[DEBUG] Metadata files written successfully")
        except Exception as e:
            action_logger(f"[BACKUP][WARN] Failed to write metadata: {str(e)}")
            print("[DEBUG] Failed to write metadata files:", str(e))

        action_logger(f"[BACKUP][OK] ip={ip} bytes={len(output)} lines={meta['lines']} engine={engine}")
        print("[DEBUG] Backup successful")

        return jsonify({
            "ok": True,
            "engine": engine,
            "config_path": cfg_path,
            "backup_dir": backup_base,
            "meta": meta
        })

    except Exception as e:
        action_logger(f"[BACKUP][ERROR] Unexpected error: {str(e)}")
        print("[DEBUG] Unexpected error:", str(e))
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@backup_bp.route("/list", methods=["GET"])
def list_backups():
    """List all available backups"""
    try:
        if not os.path.exists(BACKUP_DIR):
            return jsonify({"backups": []})
        
        backups = []
        for item in os.listdir(BACKUP_DIR):
            backup_path = os.path.join(BACKUP_DIR, item)
            if os.path.isdir(backup_path):
                meta_file = os.path.join(backup_path, "meta.json")
                if os.path.exists(meta_file):
                    try:
                        with open(meta_file, "r", encoding="utf-8") as f:
                            meta = json.load(f)
                        backups.append({
                            "directory": item,
                            "path": backup_path,
                            **meta
                        })
                    except Exception as e:
                        # Include directories even if metadata is missing/corrupt
                        backups.append({
                            "directory": item,
                            "path": backup_path,
                            "error": f"Failed to read metadata: {str(e)}"
                        })
        
        # Sort by timestamp (newest first)
        backups.sort(key=lambda x: x.get("timestamp_utc", ""), reverse=True)
        
        return jsonify({"backups": backups, "count": len(backups)})
        
    except Exception as e:
        action_logger(f"[BACKUP][ERROR] Failed to list backups: {str(e)}")
        return jsonify({"error": f"Failed to list backups: {str(e)}"}), 500

@backup_bp.route("/download/<backup_id>", methods=["GET"])
def download_backup(backup_id):
    """Download a specific backup configuration"""
    try:
        backup_path = os.path.join(BACKUP_DIR, backup_id)
        
        if not os.path.exists(backup_path) or not os.path.isdir(backup_path):
            return jsonify({"error": "Backup not found"}), 404
        
        # Find the config file
        config_files = [f for f in os.listdir(backup_path) if f.startswith("running-config")]
        if not config_files:
            return jsonify({"error": "Configuration file not found in backup"}), 404
        
        config_path = os.path.join(backup_path, config_files[0])
        
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        return jsonify({
            "backup_id": backup_id,
            "filename": config_files[0],
            "content": content,
            "size": len(content)
        })
        
    except Exception as e:
        action_logger(f"[BACKUP][ERROR] Failed to download backup {backup_id}: {str(e)}")
        return jsonify({"error": f"Failed to download backup: {str(e)}"}), 500

@backup_bp.route("/delete/<backup_id>", methods=["DELETE"])
def delete_backup(backup_id):
    """Delete a specific backup"""
    try:
        backup_path = os.path.join(BACKUP_DIR, backup_id)
        
        if not os.path.exists(backup_path) or not os.path.isdir(backup_path):
            return jsonify({"error": "Backup not found"}), 404
        
        # Remove the entire backup directory
        import shutil
        shutil.rmtree(backup_path)
        
        action_logger(f"[BACKUP][DELETE] Removed backup {backup_id}")
        return jsonify({"ok": True, "message": "Backup deleted successfully"})
        
    except Exception as e:
        action_logger(f"[BACKUP][ERROR] Failed to delete backup {backup_id}: {str(e)}")
        return jsonify({"error": f"Failed to delete backup: {str(e)}"}), 500

@backup_bp.route("/cleanup", methods=["POST"])
def cleanup_old_backups():
    """Clean up old backups (keep only the most recent N backups per device)"""
    try:
        payload = request.get_json() or {}
        keep_count = int(payload.get("keep_count", 5))
        
        if keep_count < 1:
            return jsonify({"error": "keep_count must be at least 1"}), 400
        
        # Get all backups grouped by IP
        backups_by_ip = {}
        
        if os.path.exists(BACKUP_DIR):
            for item in os.listdir(BACKUP_DIR):
                backup_path = os.path.join(BACKUP_DIR, item)
                if os.path.isdir(backup_path):
                    # Extract IP from directory name (format: ip_timestamp)
                    parts = item.split('_')
                    if len(parts) >= 2:
                        ip = '_'.join(parts[:-1])  # Handle IPs with underscores
                        if ip not in backups_by_ip:
                            backups_by_ip[ip] = []
                        backups_by_ip[ip].append({
                            "directory": item,
                            "path": backup_path,
                            "timestamp": parts[-1]
                        })
        
        deleted_count = 0
        
        # Clean up each IP's backups
        for ip, backups in backups_by_ip.items():
            # Sort by timestamp (newest first)
            backups.sort(key=lambda x: x["timestamp"], reverse=True)
            
            # Delete old backups (keep only the most recent keep_count)
            for backup in backups[keep_count:]:
                try:
                    import shutil
                    shutil.rmtree(backup["path"])
                    deleted_count += 1
                    action_logger(f"[BACKUP][CLEANUP] Deleted old backup for {ip}: {backup['directory']}")
                except Exception as e:
                    action_logger(f"[BACKUP][CLEANUP][ERROR] Failed to delete {backup['directory']}: {str(e)}")
        
        return jsonify({
            "ok": True,
            "deleted_count": deleted_count,
            "message": f"Cleanup complete: {deleted_count} old backups deleted"
        })
        
    except Exception as e:
        action_logger(f"[BACKUP][CLEANUP][ERROR] {str(e)}")
        return jsonify({"error": f"Cleanup failed: {str(e)}"}), 500