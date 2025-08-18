from flask import Blueprint, request, jsonify
from services.net_scan import scan_hosts
from services.action_logger import action_logger

scan_bp = Blueprint("scan", __name__)

@scan_bp.route("/", methods=["POST"])
def scan_network():
    data = request.get_json(silent=True) or {}
    network_range = data.get("network")
    ports = data.get("ports")
    results, used_engine = scan_hosts(network_range=network_range, ports=ports)
    action_logger(f"[SCAN] range={network_range or 'default'} engine={used_engine} found={len(results)}")
    return jsonify({"results": results, "engine": used_engine})
