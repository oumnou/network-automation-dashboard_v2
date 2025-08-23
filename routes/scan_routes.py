# routes/scan_routes.py - Enhanced Cisco Network Discovery Routes
"""
Enhanced scan routes with comprehensive Cisco device discovery.

This module provides REST API endpoints for network scanning with advanced
Cisco device identification, Nmap integration, and detailed device analysis.
"""

from flask import Blueprint, request, jsonify
from services.net_scan import scan_hosts, scan_single_device, validate_cisco_device, CiscoNetworkDiscovery
from services.action_logger import action_logger
import ipaddress
import time
from config import (
    DEFAULT_SCAN_RANGE, NMAP_ENABLED, MAX_SCAN_DEVICES, 
    CISCO_CREDENTIAL_SETS, ALLOWED_SCAN_RANGES, BLOCKED_SCAN_RANGES
)

scan_bp = Blueprint("scan", __name__)

@scan_bp.route("/", methods=["POST"])
def scan_network():
    """
    Enhanced network scanning with comprehensive Cisco device discovery.
    
    Request body:
    {
        "network": "192.168.1.0/24",     # Optional - network range to scan
        "quick_scan": false,             # Optional - quick vs comprehensive scan
        "validate_cisco": true,          # Optional - perform SSH validation
        "credentials": {                 # Optional - custom credentials
            "username": "admin",
            "password": "admin"
        }
    }
    
    Returns:
    {
        "results": [...],               # List of discovered devices
        "summary": {...},               # Scan statistics
        "scan_info": {...}              # Scan metadata
    }
    """
    try:
        data = request.get_json(silent=True) or {}
        network_range = data.get("network", DEFAULT_SCAN_RANGE)
        quick_scan = data.get("quick_scan", False)
        validate_cisco = data.get("validate_cisco", True)
        custom_credentials = data.get("credentials", {})
        
        # Validate network range
        if not _is_valid_scan_range(network_range):
            return jsonify({
                "error": "Invalid or prohibited network range",
                "range": network_range
            }), 400
        
        # Log scan initiation
        scan_type = "quick" if quick_scan else "comprehensive"
        action_logger(f"[SCAN] Starting {scan_type} scan of {network_range}")
        
        start_time = time.time()
        
        # Initialize enhanced scanner
        cisco_scanner = CiscoNetworkDiscovery()
        
        # Perform the scan
        if quick_scan:
            results = cisco_scanner.scan_network_for_cisco_devices(network_range, quick_scan=True)
        else:
            results = cisco_scanner.scan_network_for_cisco_devices(network_range, quick_scan=False)
        
        # Enhanced Cisco validation if requested
        if validate_cisco and custom_credentials:
            results = _enhance_with_custom_credentials(results, custom_credentials)
        
        # Generate scan summary
        scan_time = time.time() - start_time
        summary = _generate_scan_summary(results, scan_time)
        
        # Log results
        cisco_count = len([r for r in results if r.get("device_type") == "cisco"])
        action_logger(f"[SCAN] {scan_type.title()} scan completed: {len(results)} devices "
                     f"({cisco_count} Cisco) in {scan_time:.1f}s")
        
        return jsonify({
            "results": results,
            "summary": summary,
            "scan_info": {
                "network": network_range,
                "scan_type": scan_type,
                "duration": round(scan_time, 2),
                "nmap_enabled": NMAP_ENABLED,
                "timestamp": time.time()
            }
        })
        
    except Exception as e:
        error_msg = f"Scan failed: {str(e)}"
        action_logger(f"[SCAN][ERROR] {error_msg}")
        return jsonify({"error": error_msg}), 500

@scan_bp.route("/single", methods=["POST"])
def scan_single():
    """
    Detailed scan of a single device with comprehensive Cisco analysis.
    
    Request body:
    {
        "ip": "192.168.1.1",           # Required - IP address to scan
        "username": "admin",           # Optional - SSH username
        "password": "admin",           # Optional - SSH password
        "enable_password": "admin"     # Optional - Cisco enable password
    }
    """
    try:
        data = request.get_json() or {}
        ip = data.get("ip", "").strip()
        username = data.get("username", "admin")
        password = data.get("password", "admin")
        enable_password = data.get("enable_password")
        
        if not ip:
            return jsonify({"error": "IP address is required"}), 400
        
        # Validate IP format
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"error": "Invalid IP address format"}), 400
        
        action_logger(f"[SINGLE-SCAN] Detailed scan requested for {ip}")
        
        # Perform detailed single device scan
        result = scan_single_device(ip, username, password)
        
        # Enhanced validation if it's a potential Cisco device
        if result.get("device_type") == "cisco" or "cisco" in result.get("bridge", "").lower():
            validation = validate_cisco_device(ip, username, password, enable_password)
            result["validation"] = validation
        
        action_logger(f"[SINGLE-SCAN] Completed scan for {ip}: {result.get('bridge', 'unknown')}")
        
        return jsonify({
            "result": result,
            "timestamp": time.time()
        })
        
    except Exception as e:
        error_msg = f"Single device scan failed: {str(e)}"
        action_logger(f"[SINGLE-SCAN][ERROR] {error_msg}")
        return jsonify({"error": error_msg}), 500

@scan_bp.route("/validate", methods=["POST"])
def validate_cisco():
    """
    Validate and gather comprehensive information about a Cisco device.
    
    Request body:
    {
        "ip": "192.168.1.1",           # Required - IP address
        "username": "admin",           # Required - SSH username  
        "password": "admin",           # Required - SSH password
        "enable_password": "admin"     # Optional - Enable password
    }
    """
    try:
        data = request.get_json() or {}
        ip = data.get("ip", "").strip()
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()
        enable_password = data.get("enable_password", "").strip() or None
        
        # Validation
        if not all([ip, username, password]):
            return jsonify({"error": "IP, username, and password are required"}), 400
        
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"error": "Invalid IP address format"}), 400
        
        action_logger(f"[VALIDATE] Cisco device validation requested for {ip}")
        
        # Perform comprehensive validation
        validation_result = validate_cisco_device(ip, username, password, enable_password)
        
        # Log validation outcome
        if validation_result.get("valid"):
            device_info = validation_result.get("device_info", {})
            hostname = device_info.get("hostname", "unknown")
            model = device_info.get("model", "unknown")
            action_logger(f"[VALIDATE] Success: {ip} is {hostname} ({model})")
        else:
            errors = validation_result.get("errors", ["Unknown error"])
            action_logger(f"[VALIDATE] Failed: {ip} - {'; '.join(errors)}")
        
        return jsonify(validation_result)
        
    except Exception as e:
        error_msg = f"Device validation failed: {str(e)}"
        action_logger(f"[VALIDATE][ERROR] {error_msg}")
        return jsonify({"error": error_msg}), 500

@scan_bp.route("/credentials/test", methods=["POST"])
def test_credentials():
    """
    Test multiple credential sets against a device to find working authentication.
    
    Request body:
    {
        "ip": "192.168.1.1",           # Required - IP address
        "credential_sets": [           # Optional - custom credential sets
            {
                "username": "admin",
                "password": "admin",
                "enable_password": "admin"
            }
        ],
        "use_default_sets": true       # Optional - try default credential sets
    }
    """
    try:
        data = request.get_json() or {}
        ip = data.get("ip", "").strip()
        custom_credentials = data.get("credential_sets", [])
        use_defaults = data.get("use_default_sets", True)
        
        if not ip:
            return jsonify({"error": "IP address is required"}), 400
        
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"error": "Invalid IP address format"}), 400
        
        action_logger(f"[CRED-TEST] Testing credentials for {ip}")
        
        # Build credential sets to test
        credential_sets = []
        
        if custom_credentials:
            credential_sets.extend(custom_credentials)
        
        if use_defaults:
            # Convert default credential tuples to dictionaries
            for username, password, enable_password in CISCO_CREDENTIAL_SETS:
                credential_sets.append({
                    "username": username,
                    "password": password,
                    "enable_password": enable_password
                })
        
        if not credential_sets:
            return jsonify({"error": "No credentials provided to test"}), 400
        
        # Test each credential set
        test_results = []
        working_credentials = None
        
        for i, creds in enumerate(credential_sets):
            username = creds.get("username", "")
            password = creds.get("password", "")
            enable_password = creds.get("enable_password")
            
            action_logger(f"[CRED-TEST] Testing set {i+1}: {username}/***")
            
            try:
                validation = validate_cisco_device(ip, username, password, enable_password)
                
                result = {
                    "set_index": i,
                    "username": username,
                    "password": "***",  # Don't return actual passwords
                    "success": validation.get("valid", False),
                    "error": None if validation.get("valid") else validation.get("errors", [])
                }
                
                if validation.get("valid"):
                    working_credentials = {
                        "username": username,
                        "password": password,  # Include actual password for internal use
                        "enable_password": enable_password,
                        "device_info": validation.get("device_info", {})
                    }
                    result["device_info"] = validation.get("device_info", {})
                    action_logger(f"[CRED-TEST] Success with set {i+1}")
                
                test_results.append(result)
                
                # Stop testing if we found working credentials
                if working_credentials:
                    break
                    
            except Exception as e:
                test_results.append({
                    "set_index": i,
                    "username": username,
                    "password": "***",
                    "success": False,
                    "error": str(e)
                })
        
        success_count = len([r for r in test_results if r.get("success")])
        action_logger(f"[CRED-TEST] Completed: {success_count}/{len(test_results)} successful")
        
        return jsonify({
            "ip": ip,
            "total_sets_tested": len(test_results),
            "successful_sets": success_count,
            "working_credentials": working_credentials is not None,
            "test_results": test_results,
            "recommended_credentials": {
                "username": working_credentials.get("username") if working_credentials else None,
                "enable_required": bool(working_credentials.get("enable_password")) if working_credentials else False
            } if working_credentials else None
        })
        
    except Exception as e:
        error_msg = f"Credential testing failed: {str(e)}"
        action_logger(f"[CRED-TEST][ERROR] {error_msg}")
        return jsonify({"error": error_msg}), 500

@scan_bp.route("/range/validate", methods=["POST"])
def validate_scan_range():
    """
    Validate a network range before scanning to ensure it's safe and allowed.
    
    Request body:
    {
        "network": "192.168.1.0/24"    # Required - network range to validate
    }
    """
    try:
        data = request.get_json() or {}
        network_range = data.get("network", "").strip()
        
        if not network_range:
            return jsonify({"error": "Network range is required"}), 400
        
        validation_result = {
            "network": network_range,
            "valid": False,
            "estimated_hosts": 0,
            "warnings": [],
            "recommendations": []
        }
        
        # Validate network format
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            validation_result["valid"] = True
            validation_result["network_address"] = str(network.network_address)
            validation_result["broadcast_address"] = str(network.broadcast_address)
            validation_result["estimated_hosts"] = network.num_addresses - 2  # Subtract network and broadcast
            
        except ValueError as e:
            validation_result["error"] = f"Invalid network format: {str(e)}"
            return jsonify(validation_result), 400
        
        # Check against allowed ranges
        is_allowed = False
        for allowed_range in ALLOWED_SCAN_RANGES:
            try:
                allowed_net = ipaddress.ip_network(allowed_range)
                if network.subnet_of(allowed_net) or network == allowed_net:
                    is_allowed = True
                    break
            except ValueError:
                continue
        
        if not is_allowed:
            validation_result["valid"] = False
            validation_result["error"] = "Network range not in allowed ranges"
            validation_result["allowed_ranges"] = ALLOWED_SCAN_RANGES
            return jsonify(validation_result), 403
        
        # Check against blocked ranges
        for blocked_range in BLOCKED_SCAN_RANGES:
            try:
                blocked_net = ipaddress.ip_network(blocked_range)
                if network.overlaps(blocked_net):
                    validation_result["valid"] = False
                    validation_result["error"] = f"Network range overlaps with blocked range: {blocked_range}"
                    return jsonify(validation_result), 403
            except ValueError:
                continue
        
        # Size warnings
        if validation_result["estimated_hosts"] > MAX_SCAN_DEVICES:
            validation_result["warnings"].append(
                f"Large scan range ({validation_result['estimated_hosts']} hosts) - "
                f"consider smaller subnets for better performance"
            )
        
        if validation_result["estimated_hosts"] > 1000:
            validation_result["warnings"].append(
                "Very large scan range may take significant time to complete"
            )
        
        # Recommendations
        if validation_result["estimated_hosts"] <= 50:
            validation_result["recommendations"].append("Small range - comprehensive scan recommended")
        elif validation_result["estimated_hosts"] <= 254:
            validation_result["recommendations"].append("Medium range - quick scan for discovery, comprehensive for details")
        else:
            validation_result["recommendations"].append("Large range - quick scan strongly recommended")
        
        return jsonify(validation_result)
        
    except Exception as e:
        error_msg = f"Range validation failed: {str(e)}"
        action_logger(f"[RANGE-VALIDATE][ERROR] {error_msg}")
        return jsonify({"error": error_msg}), 500

@scan_bp.route("/config", methods=["GET"])
def get_scan_config():
    """
    Get current scanning configuration and capabilities.
    
    Returns information about scanning limits, enabled features, and default settings.
    """
    try:
        import shutil
        
        config_info = {
            "default_scan_range": DEFAULT_SCAN_RANGE,
            "nmap_enabled": NMAP_ENABLED,
            "nmap_available": bool(shutil.which("nmap")),
            "max_scan_devices": MAX_SCAN_DEVICES,
            "allowed_ranges": ALLOWED_SCAN_RANGES,
            "default_credentials": {
                "username": CISCO_CREDENTIAL_SETS[0][0],
                "password_set": bool(CISCO_CREDENTIAL_SETS[0][1])
            },
            "scan_capabilities": {
                "quick_scan": True,
                "comprehensive_scan": NMAP_ENABLED and bool(shutil.which("nmap")),
                "cisco_validation": True,
                "credential_testing": True,
                "single_device_scan": True
            },
            "supported_device_types": [
                "cisco_ios", "cisco_nexus", "cisco_iosxr", 
                "linux", "generic_network_device"
            ]
        }
        
        # Add Nmap version if available
        if config_info["nmap_available"]:
            try:
                from config import get_nmap_version
                config_info["nmap_version"] = get_nmap_version()
            except:
                config_info["nmap_version"] = "Available (version unknown)"
        
        return jsonify(config_info)
        
    except Exception as e:
        error_msg = f"Failed to get scan config: {str(e)}"
        action_logger(f"[CONFIG][ERROR] {error_msg}")
        return jsonify({"error": error_msg}), 500

# Helper functions

def _is_valid_scan_range(network_range: str) -> bool:
    """
    Validate that a network range is properly formatted and allowed for scanning.
    """
    try:
        network = ipaddress.ip_network(network_range, strict=False)
        
        # Check against blocked ranges
        for blocked_range in BLOCKED_SCAN_RANGES:
            try:
                blocked_net = ipaddress.ip_network(blocked_range)
                if network.overlaps(blocked_net):
                    return False
            except ValueError:
                continue
        
        # Check against allowed ranges
        for allowed_range in ALLOWED_SCAN_RANGES:
            try:
                allowed_net = ipaddress.ip_network(allowed_range)
                if network.subnet_of(allowed_net) or network == allowed_net:
                    return True
            except ValueError:
                continue
        
        return False  # Not in any allowed range
        
    except ValueError:
        return False  # Invalid format

def _enhance_with_custom_credentials(results: list, credentials: dict) -> list:
    """
    Enhance scan results with custom credential validation for potential Cisco devices.
    """
    username = credentials.get("username")
    password = credentials.get("password")
    enable_password = credentials.get("enable_password")
    
    if not (username and password):
        return results
    
    enhanced_results = []
    
    for device in results:
        # Only enhance devices that might be Cisco and have SSH
        if (device.get("device_priority", 0) >= 70 and 
            22 in device.get("open_ports", []) and
            not device.get("ssh_validated")):
            
            try:
                validation = validate_cisco_device(
                    device["ip"], username, password, enable_password
                )
                
                if validation.get("valid"):
                    device.update({
                        "device_type": "cisco",
                        "ssh_validated": True,
                        "custom_credentials_work": True,
                        "device_details": validation.get("device_info", {})
                    })
                    
                    # Update bridge info with more details
                    device_info = validation.get("device_info", {})
                    hostname = device_info.get("hostname", "unknown")
                    if hostname != "unknown":
                        device["bridge"] = f"Cisco-{hostname}"
                        device["hostname"] = hostname
                
            except Exception as e:
                device["custom_credential_error"] = str(e)
        
        enhanced_results.append(device)
    
    return enhanced_results

def _generate_scan_summary(results: list, scan_time: float) -> dict:
    """
    Generate comprehensive summary statistics from scan results.
    """
    if not results:
        return {
            "total_devices": 0,
            "scan_time": round(scan_time, 2),
            "message": "No devices found"
        }
    
    # Count devices by type
    cisco_devices = [r for r in results if r.get("device_type") == "cisco"]
    linux_devices = [r for r in results if r.get("device_type") == "linux"]
    unknown_devices = [r for r in results if r.get("device_type") == "unknown"]
    
    # Count by priority level
    high_priority = [r for r in results if r.get("device_priority", 0) >= 90]
    medium_priority = [r for r in results if 50 <= r.get("device_priority", 0) < 90]
    low_priority = [r for r in results if r.get("device_priority", 0) < 50]
    
    # Most common ports
    port_counts = {}
    for device in results:
        for port in device.get("open_ports", []):
            port_counts[port] = port_counts.get(port, 0) + 1
    
    common_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    
    # SSH accessible devices
    ssh_devices = [r for r in results if 22 in r.get("open_ports", [])]
    
    summary = {
        "total_devices": len(results),
        "scan_time": round(scan_time, 2),
        "device_breakdown": {
            "cisco": len(cisco_devices),
            "linux": len(linux_devices),
            "unknown": len(unknown_devices)
        },
        "priority_breakdown": {
            "high": len(high_priority),
            "medium": len(medium_priority), 
            "low": len(low_priority)
        },
        "connectivity": {
            "ssh_accessible": len(ssh_devices),
            "total_responsive": len(results)
        },
        "common_ports": [{"port": port, "count": count} for port, count in common_ports],
        "scan_efficiency": {
            "devices_per_second": round(len(results) / scan_time, 2) if scan_time > 0 else 0,
            "average_time_per_device": round(scan_time / len(results), 2) if results else 0
        }
    }
    
    return summary