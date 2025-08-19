# new-network-automation-dashboard/routes/switch_routes.py

from flask import Blueprint, request, jsonify
from config import SWITCH_DB
from services.action_logger import action_logger
import json, os, time

switch_bp = Blueprint("switch", __name__)

def _load_db():
    if not os.path.exists(SWITCH_DB):
        with open(SWITCH_DB, "w", encoding="utf-8") as f:
            json.dump([], f)
    with open(SWITCH_DB, "r", encoding="utf-8") as f:
        return json.load(f)

def _save_db(data):
    with open(SWITCH_DB, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

@switch_bp.route("/", methods=["GET"])
def list_switches():
    """List all known switches"""
    return jsonify(_load_db())

@switch_bp.route("/", methods=["POST"])
def add_or_update_switch():
    """
    Add or update a switch entry.
    Required: hostname, ip, role
    Optional: status
    """
    payload = request.get_json() or {}
    required = ["hostname", "ip", "role"]
    for r in required:
        if r not in payload:
            return jsonify({"error": f"Missing field: {r}"}), 400

    db = _load_db()
    found = False
    for sw in db:
        if sw.get("ip") == payload["ip"]:
            sw.update(payload)
            sw["updated_at"] = time.time()
            found = True
            break

    if not found:
        payload.setdefault("status", "unknown")
        payload["created_at"] = time.time()
        db.append(payload)

    _save_db(db)
    action_logger(f"[SWITCH] upsert ip={payload['ip']} hostname={payload['hostname']} role={payload['role']}")
    return jsonify({"ok": True})

@switch_bp.route("/auto", methods=["POST"])
def auto_add_switch():
    """
    Quickly add a switch from scan results (only IP required).
    Hostname defaults to 'switch-<ip>'.
    Role defaults to 'access'.
    """
    payload = request.get_json() or {}
    ip = payload.get("ip")
    if not ip:
        return jsonify({"error": "Missing ip"}), 400

    db = _load_db()
    if not any(sw.get("ip") == ip for sw in db):
        db.append({
            "hostname": f"switch-{ip.replace('.', '-')}",
            "ip": ip,
            "role": payload.get("role", "access"),
            "status": "unknown",
            "created_at": time.time()
        })
        _save_db(db)
        action_logger(f"[SWITCH] auto-added {ip}")

    return jsonify({"ok": True})
    

@switch_bp.route("/<ip>", methods=["GET"])
def get_switch(ip):
    """Get details for one switch"""
    for sw in _load_db():
        if sw.get("ip") == ip:
            return jsonify(sw)
    return jsonify({"error": "Not found"}), 404

@switch_bp.route("/<ip>", methods=["DELETE"])
def delete_switch(ip):
    """Delete switch by IP"""
    db = _load_db()
    new_db = [s for s in db if s.get("ip") != ip]
    _save_db(new_db)
    action_logger(f"[SWITCH] delete ip={ip}")
    return jsonify({"ok": True})
