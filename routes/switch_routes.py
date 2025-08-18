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
    return jsonify(_load_db())

@switch_bp.route("/", methods=["POST"])
def add_or_update_switch():
    payload = request.get_json() or {}
    required = ["hostname", "ip", "role"]
    for r in required:
        if r not in payload:
            return jsonify({"error": f"Missing field: {r}"}), 400
    db = _load_db()
    # upsert by ip
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

@switch_bp.route("/<ip>", methods=["GET"])
def get_switch(ip):
    for sw in _load_db():
        if sw.get("ip") == ip:
            return jsonify(sw)
    return jsonify({"error": "Not found"}), 404

@switch_bp.route("/<ip>", methods=["DELETE"])
def delete_switch(ip):
    db = _load_db()
    new_db = [s for s in db if s.get("ip") != ip]
    _save_db(new_db)
    action_logger(f"[SWITCH] delete ip={ip}")
    return jsonify({"ok": True})
