# routes/scan_routes.py - Cisco Integration
from flask import Blueprint, request, jsonify
from services.net_scan import scan_hosts, scan_known_cisco_devices, validate_cisco_topology
from services.action_logger import action_logger
import time

scan_bp = Blueprint("scan", __name__)

@scan_bp.route("/", methods=["POST"])
def scan_network():
    """
    Main network scanning endpoint - supports both full network scan and targeted Cisco scan.
    """
    data = request.get_json(silent=True) or {}
    network_range = data.get("network")
    scan_type = data.get("scan_type", "auto")  # auto, full, known_only
    
    start_time = time.time()
    action_logger(f"[SCAN] Starting scan: type={scan_type}, range={network_range or 'default'}")
    
    try:
        if scan_type == "known_only" or (not network_range and scan_type == "auto"):
            # Scan only known Cisco device IPs for faster results
            action_logger("[SCAN] Using targeted scan of known Cisco devices")
            results = scan_known_cisco_devices()
            
            # Validate topology
            if results:
                validation = validate_cisco_topology(results)
                action_logger(f"[SCAN] Topology validation: {validation['found_count']}/{validation['expected_count']} devices found")
                
                if validation["missing_devices"]:
                    action_logger(f"[SCAN] Missing devices: {', '.join(validation['missing_devices'])}")
        else:
            # Full network scan
            action_logger(f"[SCAN] Running full network scan on {network_range}")
            results = scan_hosts(network_range)
        
        scan_duration = time.time() - start_time
        
        # Format results for frontend
        formatted_results = []
        for device in results:
            formatted_device = {
                "ip": device["ip"],
                "status": device.get("status", "unknown"),
                "open_ports": device.get("open_ports", []),
                "bridge": device.get("bridge", "unknown"),
                "device_type": device.get("device_type", "unknown"),
                "hostname": device.get("hostname", "unknown"),
                "role_hint": device.get("role_hint", "access"),
                "model": device.get("model", "unknown"),
                "ios_version": device.get("ios_version", "unknown"),
                "authenticated": device.get("authenticated", False),
                "interface_count": device.get("interface_count", 0),
                "uptime": device.get("uptime", "unknown")
            }
            formatted_results.append(formatted_device)
        
        # Log summary
        success_count = len([d for d in results if d.get("authenticated", False)])
        action_logger(f"[SCAN] Complete: {len(results)} devices found, {success_count} authenticated ({scan_duration:.1f}s)")
        
        return jsonify({
            "results": formatted_results,
            "scan_info": {
                "duration": round(scan_duration, 2),
                "total_found": len(results),
                "authenticated_count": success_count,
                "scan_type": scan_type,
                "network_range": network_range,
                "timestamp": time.time()
            }
        })
        
    except Exception as e:
        action_logger(f"[SCAN] Error: {str(e)}")
        return jsonify({
            "error": f"Scan failed: {str(e)}",
            "results": []
        }), 500

@scan_bp.route("/known", methods=["POST"])
def scan_known_devices():
    """
    Endpoint specifically for scanning known Cisco device IPs.
    Faster than full network scan for testing.
    """
    action_logger("[SCAN] Scanning known Cisco devices only")
    
    try:
        start_time = time.time()
        results = scan_known_cisco_devices()
        scan_duration = time.time() - start_time
        
        # Validate topology
        validation = validate_cisco_topology(results)
        
        success_count = len([d for d in results if d.get("authenticated", False)])
        action_logger(f"[SCAN] Known devices scan complete: {success_count}/7 devices accessible")
        
        return jsonify({
            "results": results,
            "validation": validation,
            "scan_info": {
                "duration": round(scan_duration, 2),
                "total_found": len(results),
                "authenticated_count": success_count,
                "scan_type": "known_only",
                "timestamp": time.time()
            }
        })
        
    except Exception as e:
        action_logger(f"[SCAN] Known devices scan error: {str(e)}")
        return jsonify({
            "error": f"Known devices scan failed: {str(e)}",
            "results": []
        }), 500

@scan_bp.route("/single", methods=["POST"])
def scan_single_device():
    """
    Scan a single device for detailed information.
    """
    data = request.get_json() or {}
    ip = data.get("ip")
    
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    
    action_logger(f"[SCAN] Single device scan: {ip}")
    
    try:
        from services.net_scan import scan_single_device
        result = scan_single_device(ip)
        
        if result.get("authenticated"):
            action_logger(f"[SCAN] Single scan success: {ip} -> {result['hostname']}")
        else:
            action_logger(f"[SCAN] Single scan failed: {ip} -> {result.get('error', 'Unknown error')}")
        
        return jsonify({
            "result": result,
            "timestamp": time.time()
        })
        
    except Exception as e:
        action_logger(f"[SCAN] Single device scan error for {ip}: {str(e)}")
        return jsonify({
            "error": f"Single device scan failed: {str(e)}",
            "result": {}
        }), 500

@scan_bp.route("/topology/validate", methods=["GET"])
def validate_topology():
    """
    Validate current topology against expected Cisco sandbox layout.
    """
    try:
        action_logger("[SCAN] Validating topology")
        
        # Quick scan of known devices
        results = scan_known_cisco_devices()
        validation = validate_cisco_topology(results)
        
        action_logger(f"[SCAN] Topology validation: {validation['found_count']}/7 devices found")
        
        return jsonify({
            "validation": validation,
            "devices": results,
            "timestamp": time.time()
        })
        
    except Exception as e:
        action_logger(f"[SCAN] Topology validation error: {str(e)}")
        return jsonify({
            "error": f"Topology validation failed: {str(e)}"
        }), 500

@scan_bp.route("/status", methods=["GET"])
def scan_status():
    """
    Get scanning configuration and status information.
    """
    from config import (
        DEFAULT_SCAN_RANGE, DEFAULT_CISCO_USERNAME, 
        SCAN_THREADS, SCAN_TIMEOUT
    )
    from services.net_scan import get_known_cisco_ips
    
    return jsonify({
        "config": {
            "default_range": DEFAULT_SCAN_RANGE,
            "username": DEFAULT_CISCO_USERNAME,
            "scan_threads": SCAN_THREADS,
            "scan_timeout": SCAN_TIMEOUT,
            "known_cisco_ips": get_known_cisco_ips()
        },
        "timestamp": time.time()
    })