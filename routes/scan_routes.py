# routes/scan_routes.py - Enhanced Cisco Integration
from flask import Blueprint, request, jsonify
from services.net_scan import (
    scan_hosts, scan_known_cisco_devices, scan_single_device,
    validate_cisco_topology, get_scan_statistics, get_device_priority
)
from services.action_logger import action_logger
import time

scan_bp = Blueprint("scan", __name__)

@scan_bp.route("/", methods=["POST"])
def scan_network():
    """
    Enhanced network scanning with intelligent scan type detection.
    """
    data = request.get_json(silent=True) or {}
    network_range = data.get("network", "").strip()
    scan_type = data.get("scan_type", "auto")
    
    start_time = time.time()
    
    # Determine the best scan approach
    if not network_range or network_range == "10.10.20.0/24":
        actual_scan_type = "known_only"
        action_logger(f"[SCAN] Auto-selected known device scan (efficient for your 7 Cisco devices)")
    elif scan_type == "known_only":
        actual_scan_type = "known_only"
        action_logger(f"[SCAN] Known device scan requested")
    elif _is_single_ip(network_range):
        actual_scan_type = "single"
        action_logger(f"[SCAN] Single device scan: {network_range}")
    else:
        actual_scan_type = "full"
        action_logger(f"[SCAN] Full network scan: {network_range}")
    
    try:
        # Execute the appropriate scan type
        if actual_scan_type == "known_only":
            results = scan_known_cisco_devices()
            topology_validation = validate_cisco_topology(results)
            
        elif actual_scan_type == "single":
            single_result = scan_single_device(network_range)
            results = [single_result] if single_result.get("authenticated") else []
            topology_validation = None
            
        else:  # full scan
            results = scan_hosts(network_range)
            topology_validation = validate_cisco_topology(results) if results else None
        
        scan_duration = time.time() - start_time
        
        # Sort results by priority (most important devices first)
        results.sort(key=get_device_priority, reverse=True)
        
        # Enhanced result formatting
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
                "reachable": device.get("reachable", False),
                "interface_count": device.get("interface_count", 0),
                "uptime": device.get("uptime", "unknown"),
                "priority": get_device_priority(device),
                "error": device.get("error")
            }
            formatted_results.append(formatted_device)
        
        # Generate scan summary
        total_found = len(results)
        authenticated_count = len([d for d in results if d.get("authenticated", False)])
        success_rate = round((authenticated_count / total_found * 100) if total_found > 0 else 0, 1)
        
        action_logger(f"[SCAN] Complete: {authenticated_count}/{total_found} devices accessible "
                     f"({success_rate}% success rate, {scan_duration:.1f}s)")
        
        response_data = {
            "results": formatted_results,
            "scan_info": {
                "duration": round(scan_duration, 2),
                "total_found": total_found,
                "authenticated_count": authenticated_count,
                "success_rate": success_rate,
                "scan_type": actual_scan_type,
                "network_range": network_range or "known devices",
                "timestamp": time.time()
            }
        }
        
        # Add topology validation if available
        if topology_validation:
            response_data["validation"] = topology_validation
            
            if topology_validation["recommendations"]:
                for rec in topology_validation["recommendations"]:
                    action_logger(f"[SCAN] Recommendation: {rec}")
        
        return jsonify(response_data)
        
    except Exception as e:
        scan_duration = time.time() - start_time
        error_msg = str(e)
        action_logger(f"[SCAN] Error after {scan_duration:.1f}s: {error_msg}")
        
        return jsonify({
            "error": f"Scan failed: {error_msg}",
            "results": [],
            "scan_info": {
                "duration": round(scan_duration, 2),
                "total_found": 0,
                "authenticated_count": 0,
                "success_rate": 0,
                "scan_type": actual_scan_type,
                "error": error_msg,
                "timestamp": time.time()
            }
        }), 500

@scan_bp.route("/known", methods=["POST"])
def scan_known_devices():
    """
    Optimized endpoint for scanning your 7 known Cisco devices.
    Much faster than full network scanning.
    """
    action_logger("[SCAN] Quick scan of 7 known Cisco devices")
    
    try:
        start_time = time.time()
        results = scan_known_cisco_devices()
        scan_duration = time.time() - start_time
        
        # Enhanced validation with recommendations
        validation = validate_cisco_topology(results)
        
        authenticated_count = len([d for d in results if d.get("authenticated", False)])
        success_rate = round((authenticated_count / 7 * 100), 1)
        
        action_logger(f"[SCAN] Known devices: {authenticated_count}/7 accessible ({success_rate}%)")
        
        # Log any issues found
        if validation["missing_devices"]:
            action_logger(f"[SCAN] Missing: {', '.join(validation['missing_devices'])}")
        
        if not validation["topology_valid"]:
            action_logger("[SCAN] ⚠️  Topology validation failed - check device connectivity")
        
        return jsonify({
            "results": results,
            "validation": validation,
            "scan_info": {
                "duration": round(scan_duration, 2),
                "total_found": len(results),
                "authenticated_count": authenticated_count,
                "success_rate": success_rate,
                "scan_type": "known_only",
                "expected_devices": 7,
                "topology_valid": validation["topology_valid"],
                "timestamp": time.time()
            }
        })
        
    except Exception as e:
        action_logger(f"[SCAN] Known devices scan error: {str(e)}")
        return jsonify({
            "error": f"Known devices scan failed: {str(e)}",
            "results": [],
            "scan_info": {
                "scan_type": "known_only",
                "error": str(e),
                "timestamp": time.time()
            }
        }), 500

@scan_bp.route("/single", methods=["POST"])
def scan_single_device_endpoint():
    """
    Enhanced single device scanning with detailed diagnostics.
    """
    data = request.get_json() or {}
    ip = data.get("ip", "").strip()
    
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    
    if not _is_valid_ip(ip):
        return jsonify({"error": "Invalid IP address format"}), 400
    
    action_logger(f"[SCAN] Single device detailed scan: {ip}")
    
    try:
        start_time = time.time()
        result = scan_single_device(ip)
        scan_duration = time.time() - start_time
        
        # Enhanced logging based on result
        if result.get("authenticated"):
            hostname = result.get("hostname", "unknown")
            model = result.get("model", "unknown")
            role = result.get("role_hint", "access")
            action_logger(f"[SCAN] ✅ {ip}: {hostname} ({model}, {role})")
        else:
            error = result.get("error", "Unknown error")
            action_logger(f"[SCAN] ❌ {ip}: {error}")
        
        # Check if this is a known device
        from services.net_scan import get_known_cisco_ips
        is_known_device = ip in get_known_cisco_ips()
        
        return jsonify({
            "result": result,
            "scan_info": {
                "duration": round(scan_duration, 2),
                "scan_type": "single",
                "is_known_device": is_known_device,
                "authenticated": result.get("authenticated", False),
                "timestamp": time.time()
            }
        })
        
    except Exception as e:
        action_logger(f"[SCAN] Single device error for {ip}: {str(e)}")
        return jsonify({
            "error": f"Single device scan failed: {str(e)}",
            "result": {
                "ip": ip,
                "error": str(e),
                "authenticated": False,
                "reachable": False
            }
        }), 500

@scan_bp.route("/topology/validate", methods=["GET"])
def validate_topology():
    """
    Validate current topology against your expected Cisco sandbox layout.
    """
    try:
        action_logger("[SCAN] Validating Cisco topology configuration")
        
        # Quick scan of known devices for validation
        start_time = time.time()
        results = scan_known_cisco_devices()
        validation = validate_cisco_topology(results)
        duration = time.time() - start_time
        
        # Enhanced status reporting
        status_summary = {
            "healthy": 0,
            "warning": 0,
            "critical": 0
        }
        
        for ip, status_info in validation["device_status"].items():
            if status_info["status"] == "ok":
                status_summary["healthy"] += 1
            elif status_info["status"] in ["hostname_mismatch", "role_mismatch"]:
                status_summary["warning"] += 1
            else:
                status_summary["critical"] += 1
        
        action_logger(f"[SCAN] Topology validation: "
                     f"{validation['found_count']}/7 devices, "
                     f"{status_summary['healthy']} healthy, "
                     f"{status_summary['warning']} warnings, "
                     f"{status_summary['critical']} critical")
        
        return jsonify({
            "validation": validation,
            "devices": results,
            "summary": {
                "duration": round(duration, 2),
                "total_expected": 7,
                "total_found": validation["found_count"],
                "topology_valid": validation["topology_valid"],
                "status_summary": status_summary,
                "timestamp": time.time()
            }
        })
        
    except Exception as e:
        action_logger(f"[SCAN] Topology validation error: {str(e)}")
        return jsonify({
            "error": f"Topology validation failed: {str(e)}",
            "validation": {
                "topology_valid": False,
                "error": str(e)
            }
        }), 500

@scan_bp.route("/status", methods=["GET"])
def scan_status():
    """
    Enhanced scanning status and configuration information.
    """
    try:
        stats = get_scan_statistics()
        
        # Add runtime information
        stats["runtime"] = {
            "last_scan_timestamp": time.time(),
            "server_uptime": "unknown",  # Could be enhanced
            "active_connections": 0      # Could track active SSH sessions
        }
        
        return jsonify(stats)
        
    except Exception as e:
        action_logger(f"[SCAN] Status request error: {str(e)}")
        return jsonify({
            "error": f"Failed to get scan status: {str(e)}"
        }), 500

@scan_bp.route("/test-connectivity/<ip>", methods=["POST"])
def test_device_connectivity(ip):
    """
    Test connectivity to a specific device with detailed diagnostics.
    """
    if not _is_valid_ip(ip):
        return jsonify({"error": "Invalid IP address"}), 400
    
    action_logger(f"[SCAN] Testing connectivity to {ip}")
    
    try:
        # Comprehensive connectivity test
        result = scan_single_device(ip)
        
        # Additional diagnostics
        diagnostics = {
            "tcp_22_open": 22 in result.get("open_ports", []),
            "tcp_23_open": 23 in result.get("open_ports", []),
            "ssh_auth_success": result.get("authenticated", False),
            "device_responsive": result.get("reachable", False),
            "cisco_ios_detected": result.get("device_type") == "cisco_ios"
        }
        
        return jsonify({
            "ip": ip,
            "connectivity": {
                "reachable": result.get("reachable", False),
                "authenticated": result.get("authenticated", False),
                "error": result.get("error")
            },
            "device_info": {
                "hostname": result.get("hostname", "unknown"),
                "model": result.get("model", "unknown"),
                "ios_version": result.get("ios_version", "unknown"),
                "role_hint": result.get("role_hint", "access")
            },
            "diagnostics": diagnostics,
            "timestamp": time.time()
        })
        
    except Exception as e:
        action_logger(f"[SCAN] Connectivity test error for {ip}: {str(e)}")
        return jsonify({
            "ip": ip,
            "connectivity": {
                "reachable": False,
                "authenticated": False,
                "error": str(e)
            },
            "diagnostics": {
                "tcp_22_open": False,
                "tcp_23_open": False,
                "ssh_auth_success": False,
                "device_responsive": False,
                "cisco_ios_detected": False
            },
            "timestamp": time.time()
        }), 500

# Utility functions
def _is_single_ip(network_str: str) -> bool:
    """Check if input is a single IP address."""
    try:
        import ipaddress
        ipaddress.ip_address(network_str)
        return True
    except ValueError:
        return False

def _is_valid_ip(ip_str: str) -> bool:
    """Validate IP address format."""
    try:
        import ipaddress
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False