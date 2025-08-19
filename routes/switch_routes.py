# routes/switch_routes.py

from flask import Blueprint, request, jsonify
from config import SWITCH_DB
from services.action_logger import action_logger
import json, os, time

switch_bp = Blueprint("switch", __name__)

def _load_db():
    """Load the switch database from JSON file"""
    if not os.path.exists(SWITCH_DB):
        with open(SWITCH_DB, "w", encoding="utf-8") as f:
            json.dump([], f)
    try:
        with open(SWITCH_DB, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        # Handle corrupted JSON file
        action_logger("[SWITCH] Warning: Corrupted database file, creating new one")
        with open(SWITCH_DB, "w", encoding="utf-8") as f:
            json.dump([], f)
        return []

def _save_db(data):
    """Save the switch database to JSON file"""
    try:
        # Create backup before saving
        if os.path.exists(SWITCH_DB):
            backup_path = f"{SWITCH_DB}.backup"
            with open(SWITCH_DB, "r", encoding="utf-8") as src:
                with open(backup_path, "w", encoding="utf-8") as dst:
                    dst.write(src.read())
        
        with open(SWITCH_DB, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        action_logger(f"[SWITCH] Error saving database: {str(e)}")
        raise

@switch_bp.route("/", methods=["GET"])
def list_switches():
    """List all known switches"""
    try:
        switches = _load_db()
        return jsonify(switches)
    except Exception as e:
        action_logger(f"[SWITCH] Error listing switches: {str(e)}")
        return jsonify({"error": "Failed to load switches"}), 500

@switch_bp.route("/", methods=["POST"])
def add_or_update_switch():
    """
    Add or update a switch entry.
    Required: hostname, ip, role
    Optional: status, device_type
    """
    try:
        payload = request.get_json() or {}
        required = ["hostname", "ip", "role"]
        
        # Validate required fields
        for field in required:
            if field not in payload or not payload[field].strip():
                return jsonify({"error": f"Missing or empty field: {field}"}), 400

        # Validate IP format (basic validation)
        ip = payload["ip"].strip()
        ip_parts = ip.split('.')
        if len(ip_parts) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in ip_parts):
            return jsonify({"error": "Invalid IP address format"}), 400

        # Validate role
        valid_roles = ["core", "distribution", "access"]
        if payload["role"] not in valid_roles:
            return jsonify({"error": f"Invalid role. Must be one of: {', '.join(valid_roles)}"}), 400

        # Load database
        db = _load_db()
        found = False
        current_time = time.time()

        # Check if switch already exists (by IP)
        for sw in db:
            if sw.get("ip") == ip:
                # Update existing switch
                sw.update({
                    "hostname": payload["hostname"].strip(),
                    "role": payload["role"],
                    "status": payload.get("status", sw.get("status", "unknown")),
                    "device_type": payload.get("device_type", sw.get("device_type", "ovs")),
                    "updated_at": current_time
                })
                found = True
                action_logger(f"[SWITCH] Updated {ip}: {payload['hostname']}")
                break

        if not found:
            # Add new switch
            new_switch = {
                "hostname": payload["hostname"].strip(),
                "ip": ip,
                "role": payload["role"],
                "status": payload.get("status", "unknown"),
                "device_type": payload.get("device_type", "ovs"),
                "created_at": current_time,
                "updated_at": current_time
            }
            db.append(new_switch)
            action_logger(f"[SWITCH] Added new switch {ip}: {payload['hostname']}")

        _save_db(db)
        return jsonify({"ok": True, "message": "Switch saved successfully"})

    except Exception as e:
        action_logger(f"[SWITCH] Error adding/updating switch: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@switch_bp.route("/auto", methods=["POST"])
def auto_add_switch():
    """
    Quickly add a switch from scan results (only IP required).
    Hostname defaults to 'switch-<ip>'.
    Role defaults to 'access'.
    Device type defaults to 'ovs'.
    """
    try:
        payload = request.get_json() or {}
        ip = payload.get("ip", "").strip()
        
        if not ip:
            return jsonify({"error": "Missing ip"}), 400

        # Validate IP format
        ip_parts = ip.split('.')
        if len(ip_parts) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in ip_parts):
            return jsonify({"error": "Invalid IP address format"}), 400

        db = _load_db()
        
        # Check if switch already exists
        if any(sw.get("ip") == ip for sw in db):
            return jsonify({"ok": True, "message": "Switch already exists"})

        # Add new switch with auto-generated values
        new_switch = {
            "hostname": payload.get("hostname", f"switch-{ip.replace('.', '-')}"),
            "ip": ip,
            "role": payload.get("role", "access"),
            "status": payload.get("status", "unknown"),
            "device_type": payload.get("device_type", "ovs"),
            "created_at": time.time(),
            "updated_at": time.time()
        }
        
        db.append(new_switch)
        _save_db(db)
        
        action_logger(f"[SWITCH] Auto-added {ip} as {new_switch['hostname']}")
        return jsonify({"ok": True, "message": "Switch auto-added successfully"})

    except Exception as e:
        action_logger(f"[SWITCH] Error auto-adding switch: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@switch_bp.route("/<ip>", methods=["GET"])
def get_switch(ip):
    """Get details for one switch by IP"""
    try:
        switches = _load_db()
        for sw in switches:
            if sw.get("ip") == ip:
                return jsonify(sw)
        return jsonify({"error": "Switch not found"}), 404
    except Exception as e:
        action_logger(f"[SWITCH] Error getting switch {ip}: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@switch_bp.route("/<ip>", methods=["DELETE"])
def delete_switch(ip):
    """Delete switch by IP"""
    try:
        db = _load_db()
        original_count = len(db)
        
        # Filter out the switch with matching IP
        new_db = [s for s in db if s.get("ip") != ip]
        
        if len(new_db) == original_count:
            return jsonify({"error": "Switch not found"}), 404
        
        _save_db(new_db)
        action_logger(f"[SWITCH] Deleted switch {ip}")
        return jsonify({"ok": True, "message": "Switch deleted successfully"})

    except Exception as e:
        action_logger(f"[SWITCH] Error deleting switch {ip}: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@switch_bp.route("/bulk", methods=["POST"])
def bulk_import():
    """Bulk import switches from JSON data"""
    try:
        payload = request.get_json() or {}
        switches_data = payload.get("switches", [])
        
        if not isinstance(switches_data, list):
            return jsonify({"error": "switches must be an array"}), 400
        
        db = _load_db()
        added_count = 0
        updated_count = 0
        errors = []
        
        for switch_data in switches_data:
            try:
                # Validate required fields
                required = ["hostname", "ip", "role"]
                for field in required:
                    if field not in switch_data:
                        errors.append(f"Missing field {field} in switch data")
                        continue
                
                ip = switch_data["ip"]
                found = False
                
                # Check if exists
                for sw in db:
                    if sw.get("ip") == ip:
                        sw.update(switch_data)
                        sw["updated_at"] = time.time()
                        updated_count += 1
                        found = True
                        break
                
                if not found:
                    switch_data.setdefault("status", "unknown")
                    switch_data.setdefault("device_type", "ovs")
                    switch_data["created_at"] = time.time()
                    switch_data["updated_at"] = time.time()
                    db.append(switch_data)
                    added_count += 1
                    
            except Exception as e:
                errors.append(f"Error processing switch {switch_data.get('ip', 'unknown')}: {str(e)}")
        
        _save_db(db)
        action_logger(f"[SWITCH] Bulk import: {added_count} added, {updated_count} updated")
        
        return jsonify({
            "ok": True,
            "added": added_count,
            "updated": updated_count,
            "errors": errors
        })
        
    except Exception as e:
        action_logger(f"[SWITCH] Error in bulk import: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@switch_bp.route("/export", methods=["GET"])
def export_switches():
    """Export all switches as JSON"""
    try:
        switches = _load_db()
        return jsonify({
            "timestamp": time.time(),
            "count": len(switches),
            "switches": switches
        })
    except Exception as e:
        action_logger(f"[SWITCH] Error exporting switches: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500