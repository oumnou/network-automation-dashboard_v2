# new-network-automation-dashboard/routes/scan_routes.py
from flask import Blueprint, request, jsonify
from services.net_scan import scan_hosts
from services.action_logger import action_logger

scan_bp = Blueprint("scan", __name__)

@scan_bp.route("/", methods=["POST"])
def scan_network():
    data = request.get_json(silent=True) or {}
    network_range = data.get("network")

    # Run Nmap scan (only port 22, SSH)
    results = scan_hosts(network_range)

    # Log the scan event
    action_logger(f"[SCAN] range={network_range or 'default'} found={len(results)}")

    # Return JSON results to frontend
    return jsonify({"results": results})
