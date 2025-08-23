# services/net_scan.py - Enhanced Cisco Scanner
from typing import List, Dict, Optional
import socket
import concurrent.futures
import time
import ipaddress
from config import (
    DEFAULT_SCAN_RANGE, SCAN_THREADS, SCAN_TIMEOUT,
    DEFAULT_CISCO_USERNAME, DEFAULT_CISCO_PASSWORD,
    MANAGEMENT_PORTS
)
from services.ssh_utils import test_cisco_connectivity

def scan_hosts(network_range: Optional[str] = None) -> List[Dict]:
    """
    Enhanced scan that prioritizes known Cisco devices and limits full scans.
    """
    network = network_range or DEFAULT_SCAN_RANGE
    print(f"[SCAN] Starting enhanced Cisco scan of {network}")
    
    # Check if this looks like a single IP
    if _is_single_ip(network):
        print(f"[SCAN] Single IP scan detected: {network}")
        return [scan_single_device(network)]
    
    # Check if this is our default range - use known devices for efficiency
    if network == DEFAULT_SCAN_RANGE or network == "10.10.20.0/24":
        print("[SCAN] Default range detected - using known Cisco devices for speed")
        return scan_known_cisco_devices()
    
    try:
        # Parse network range
        net = ipaddress.ip_network(network, strict=False)
        hosts = list(net.hosts())
        
        # Limit hosts for performance (especially in sandbox environments)
        if len(hosts) > 50:
            print(f"[SCAN] Large network detected ({len(hosts)} hosts) - limiting to first 50")
            hosts = hosts[:50]
            
    except ValueError as e:
        print(f"[SCAN] Invalid network range {network}: {e}")
        return []
    
    print(f"[SCAN] Full network scan of {len(hosts)} hosts...")
    
    # Enhanced two-phase scanning
    results = []
    
    # Phase 1: Quick port scan to find devices with management ports
    print("[SCAN] Phase 1: Port scanning for management services...")
    reachable_hosts = _enhanced_port_scan(hosts)
    print(f"[SCAN] Phase 1 complete: {len(reachable_hosts)} hosts with management ports")
    
    # Phase 2: Cisco device detection on promising hosts
    if reachable_hosts:
        print("[SCAN] Phase 2: Cisco device identification...")
        cisco_devices = _detailed_cisco_scan(reachable_hosts)
        results.extend(cisco_devices)
    
    print(f"[SCAN] Scan complete: {len(results)} Cisco devices found")
    return results

def _is_single_ip(network_str: str) -> bool:
    """Check if the input is a single IP address rather than a network range."""
    try:
        ipaddress.ip_address(network_str)
        return True
    except ValueError:
        return False

def _enhanced_port_scan(hosts: List[ipaddress.IPv4Address]) -> List[Dict]:
    """
    Enhanced port scan that's more efficient and prioritizes Cisco-relevant ports.
    """
    reachable_hosts = []
    
    def scan_host_ports(host_ip: str) -> Optional[Dict]:
        # Cisco management ports in order of priority
        priority_ports = [22, 23, 443, 80, 161]  # SSH, Telnet, HTTPS, HTTP, SNMP
        open_ports = []
        priority_score = 0
        
        for port in priority_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)  # Reduced timeout for faster scanning
            
            try:
                result = sock.connect_ex((host_ip, port))
                if result == 0:
                    open_ports.append(port)
                    # Calculate priority score
                    if port == 22:
                        priority_score += 50  # SSH is highest priority
                    elif port == 23:
                        priority_score += 40  # Telnet often indicates Cisco
                    elif port == 161:
                        priority_score += 30  # SNMP for network devices
                    else:
                        priority_score += 10
            except socket.error:
                pass
            finally:
                sock.close()
        
        if open_ports:
            return {
                "ip": host_ip,
                "open_ports": open_ports,
                "priority_score": priority_score,
                "has_ssh": 22 in open_ports,
                "likely_cisco": (22 in open_ports and 23 in open_ports) or priority_score >= 50
            }
        return None
    
    # Use conservative threading to avoid overwhelming devices
    max_workers = min(SCAN_THREADS, 12)  # Limit concurrent connections
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        host_strings = [str(host) for host in hosts]
        futures = {executor.submit(scan_host_ports, host): host for host in host_strings}
        
        for future in concurrent.futures.as_completed(futures, timeout=45):
            try:
                result = future.result(timeout=8)
                if result:
                    reachable_hosts.append(result)
            except (concurrent.futures.TimeoutError, Exception) as e:
                print(f"[SCAN] Port scan timeout/error for {futures[future]}: {e}")
    
    # Sort by priority score and Cisco likelihood
    reachable_hosts.sort(key=lambda x: (x["likely_cisco"], x["priority_score"]), reverse=True)
    
    # Limit to most promising candidates to avoid timeouts
    if len(reachable_hosts) > 20:
        print(f"[SCAN] Limiting detailed scan to top 20 candidates from {len(reachable_hosts)} found")
        reachable_hosts = reachable_hosts[:20]
    
    return reachable_hosts

def _detailed_cisco_scan(hosts: List[Dict]) -> List[Dict]:
    """
    Enhanced Cisco device detection with better error handling and performance.
    """
    cisco_devices = []
    
    def scan_cisco_device(host_info: Dict) -> Optional[Dict]:
        ip = host_info["ip"]
        
        # Skip if no SSH (required for Cisco authentication)
        if not host_info.get("has_ssh"):
            print(f"[SCAN] Skipping {ip} - no SSH service")
            return None
        
        print(f"[SCAN] Testing Cisco device {ip} (priority: {host_info['priority_score']})...")
        
        try:
            # Test Cisco connectivity with timeout
            device_info = test_cisco_connectivity(
                ip=ip,
                username=DEFAULT_CISCO_USERNAME,
                password=DEFAULT_CISCO_PASSWORD,
                timeout=12  # Reasonable timeout for sandbox environment
            )
            
            # Only proceed if we have a confirmed Cisco device
            if device_info["authenticated"] and device_info["device_type"] == "cisco_ios":
                result = {
                    "ip": ip,
                    "status": device_info["status"],
                    "open_ports": host_info["open_ports"],
                    "bridge": _format_bridge_info(device_info),
                    "device_type": "cisco",
                    "hostname": device_info["hostname"],
                    "model": device_info["model"],
                    "ios_version": device_info["ios_version"],
                    "role_hint": device_info["role_hint"],
                    "interface_count": device_info["interface_count"],
                    "uptime": device_info["uptime"],
                    "authenticated": True,
                    "reachable": True,
                    "device_priority": 100,
                    "last_scan": int(time.time()),
                    "scan_details": device_info
                }
                
                print(f"[SCAN] ✅ Cisco device confirmed: {device_info['hostname']} ({ip}) - {device_info['role_hint']}")
                return result
            else:
                print(f"[SCAN] ❌ {ip}: Not a Cisco device or auth failed - {device_info.get('error', 'Unknown')}")
                return None
                
        except Exception as e:
            print(f"[SCAN] Error scanning {ip}: {e}")
            return None
    
    # Sequential scanning to avoid overwhelming Cisco devices
    # (Parallel SSH connections can cause issues with some Cisco devices)
    for host_info in hosts:
        try:
            result = scan_cisco_device(host_info)
            if result:
                cisco_devices.append(result)
            
            # Small delay between devices to be respectful to the network
            time.sleep(0.5)
            
        except Exception as e:
            print(f"[SCAN] Unexpected error scanning {host_info['ip']}: {e}")
    
    return cisco_devices

def scan_known_cisco_devices() -> List[Dict]:
    """
    Optimized scan of your specific Cisco sandbox devices.
    This is much faster than scanning the entire subnet.
    """
    print("[SCAN] Quick scan of known Cisco devices...")
    
    # Your specific Cisco device IPs with expected roles
    known_devices = {
        "10.10.20.3": {"expected_hostname": "Core1", "expected_role": "core"},
        "10.10.20.4": {"expected_hostname": "Dist1", "expected_role": "distribution"},
        "10.10.20.5": {"expected_hostname": "Dist2", "expected_role": "distribution"},
        "10.10.20.10": {"expected_hostname": "End1", "expected_role": "access"},
        "10.10.20.11": {"expected_hostname": "End2", "expected_role": "access"},
        "10.10.20.12": {"expected_hostname": "End3", "expected_role": "access"},
        "10.10.20.13": {"expected_hostname": "End4", "expected_role": "access"}
    }
    
    results = []
    
    for ip, expected in known_devices.items():
        print(f"[SCAN] Testing known device {ip} (expected: {expected['expected_hostname']})...")
        
        try:
            device_info = scan_single_device(ip)
            
            if device_info["authenticated"]:
                # Validate that we got what we expected
                actual_hostname = device_info.get("hostname", "unknown")
                expected_hostname = expected["expected_hostname"]
                
                if expected_hostname.lower() in actual_hostname.lower():
                    print(f"[SCAN] ✅ {ip}: {actual_hostname} matches expected {expected_hostname}")
                else:
                    print(f"[SCAN] ⚠️  {ip}: Found {actual_hostname}, expected {expected_hostname}")
                
                results.append(device_info)
            else:
                error_msg = device_info.get("error", "Authentication failed")
                print(f"[SCAN] ❌ {ip}: {error_msg}")
                
        except Exception as e:
            print(f"[SCAN] Error testing {ip}: {e}")
        
        # Brief pause between devices
        time.sleep(0.3)
    
    success_count = len(results)
    total_count = len(known_devices)
    print(f"[SCAN] Known device scan complete: {success_count}/{total_count} devices accessible")
    
    return results

def scan_single_device(ip: str, username: str = None, password: str = None) -> Dict:
    """
    Enhanced single device scan with better error reporting.
    """
    username = username or DEFAULT_CISCO_USERNAME
    password = password or DEFAULT_CISCO_PASSWORD
    
    print(f"[SCAN] Detailed scan of device {ip}")
    
    # Quick connectivity check first
    connectivity_ok = False
    open_ports = []
    
    for port in [22, 23, 80, 443]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
                if port == 22:
                    connectivity_ok = True
        except:
            pass
        finally:
            sock.close()
    
    if not connectivity_ok:
        return {
            "ip": ip,
            "status": "unreachable",
            "error": "SSH port (22) not accessible",
            "open_ports": open_ports,
            "device_type": "unknown",
            "authenticated": False,
            "reachable": False
        }
    
    # Get detailed Cisco information
    device_info = test_cisco_connectivity(ip, username, password, timeout=15)
    
    # Enhanced result formatting
    result = {
        "ip": ip,
        "status": device_info["status"],
        "open_ports": open_ports,
        "device_type": device_info.get("device_type", "unknown"),
        "hostname": device_info.get("hostname", "unknown"),
        "model": device_info.get("model", "unknown"),
        "ios_version": device_info.get("ios_version", "unknown"),
        "role_hint": device_info.get("role_hint", "access"),
        "interface_count": device_info.get("interface_count", 0),
        "uptime": device_info.get("uptime", "unknown"),
        "bridge": _format_bridge_info(device_info),
        "authenticated": device_info.get("authenticated", False),
        "reachable": device_info.get("reachable", False),
        "error": device_info.get("error"),
        "scan_timestamp": int(time.time()),
        "detailed": True
    }
    
    status_icon = "✅" if result["authenticated"] else "❌"
    print(f"[SCAN] {status_icon} Single device scan: {ip} -> {result.get('hostname', 'unknown')} ({result.get('model', 'unknown')})")
    
    return result

def _format_bridge_info(device_info: Dict) -> str:
    """
    Enhanced bridge info formatting for better dashboard display.
    """
    hostname = device_info.get("hostname", "unknown")
    role = device_info.get("role_hint", "access").title()
    model = device_info.get("model", "unknown")
    
    if hostname != "unknown" and hostname.lower() != "unknown":
        if model != "unknown" and model.lower() != "unknown":
            return f"Cisco-{role} ({hostname}, {model})"
        else:
            return f"Cisco-{role} ({hostname})"
    else:
        if model != "unknown":
            return f"Cisco-{role} ({model})"
        else:
            return f"Cisco-{role} Device"

def get_known_cisco_ips() -> List[str]:
    """
    Your specific Cisco sandbox device IPs.
    """
    return [
        "10.10.20.3",   # Core1
        "10.10.20.4",   # Dist1  
        "10.10.20.5",   # Dist2
        "10.10.20.10",  # End1
        "10.10.20.11",  # End2
        "10.10.20.12",  # End3
        "10.10.20.13"   # End4
    ]

def validate_cisco_topology(devices: List[Dict]) -> Dict:
    """
    Enhanced topology validation for your specific Cisco setup.
    """
    validation = {
        "expected_count": 7,
        "found_count": len(devices),
        "missing_devices": [],
        "unexpected_devices": [],
        "role_distribution": {"core": 0, "distribution": 0, "access": 0},
        "topology_valid": False,
        "device_status": {},
        "recommendations": []
    }
    
    # Expected device mapping
    expected_devices = {
        "10.10.20.3": {"hostname": "Core1", "role": "core"},
        "10.10.20.4": {"hostname": "Dist1", "role": "distribution"},
        "10.10.20.5": {"hostname": "Dist2", "role": "distribution"},
        "10.10.20.10": {"hostname": "End1", "role": "access"},
        "10.10.20.11": {"hostname": "End2", "role": "access"},
        "10.10.20.12": {"hostname": "End3", "role": "access"},
        "10.10.20.13": {"hostname": "End4", "role": "access"}
    }
    
    known_ips = set(expected_devices.keys())
    found_ips = set(device["ip"] for device in devices)
    
    # Check for missing and unexpected devices
    validation["missing_devices"] = list(known_ips - found_ips)
    validation["unexpected_devices"] = list(found_ips - known_ips)
    
    # Analyze found devices
    for device in devices:
        ip = device["ip"]
        role = device.get("role_hint", "access")
        hostname = device.get("hostname", "unknown")
        
        # Count by role
        if role in validation["role_distribution"]:
            validation["role_distribution"][role] += 1
        
        # Check device status
        validation["device_status"][ip] = {
            "expected": expected_devices.get(ip, {}),
            "actual": {
                "hostname": hostname,
                "role": role,
                "model": device.get("model", "unknown"),
                "ios_version": device.get("ios_version", "unknown")
            },
            "status": "ok" if ip in expected_devices else "unexpected"
        }
        
        # Validate against expected configuration
        if ip in expected_devices:
            expected = expected_devices[ip]
            if expected["hostname"].lower() not in hostname.lower():
                validation["device_status"][ip]["status"] = "hostname_mismatch"
            elif expected["role"] != role:
                validation["device_status"][ip]["status"] = "role_mismatch"
    
    # Check if topology matches expectations (1 core, 2 dist, 4 access)
    expected_roles = {"core": 1, "distribution": 2, "access": 4}
    validation["topology_valid"] = (
        validation["role_distribution"] == expected_roles and
        len(validation["missing_devices"]) == 0 and
        len(validation["unexpected_devices"]) == 0
    )
    
    # Generate recommendations
    if validation["missing_devices"]:
        validation["recommendations"].append(
            f"Missing devices detected: {', '.join(validation['missing_devices'])}. Check network connectivity and credentials."
        )
    
    if validation["role_distribution"]["core"] == 0:
        validation["recommendations"].append(
            "No core switches found. This may impact network connectivity."
        )
    
    if validation["role_distribution"]["distribution"] < 2:
        validation["recommendations"].append(
            f"Expected 2 distribution switches, found {validation['role_distribution']['distribution']}."
        )
    
    # Check for mismatched devices
    mismatched = [ip for ip, status in validation["device_status"].items() 
                 if status["status"] in ["hostname_mismatch", "role_mismatch"]]
    if mismatched:
        validation["recommendations"].append(
            f"Device configuration mismatches detected: {', '.join(mismatched)}"
        )
    
    return validation

def get_scan_statistics() -> Dict:
    """
    Get scanning configuration and performance statistics.
    """
    from config import (
        DEFAULT_SCAN_RANGE, DEFAULT_CISCO_USERNAME, 
        SCAN_THREADS, SCAN_TIMEOUT
    )
    
    return {
        "config": {
            "default_range": DEFAULT_SCAN_RANGE,
            "username": DEFAULT_CISCO_USERNAME,
            "scan_threads": SCAN_THREADS,
            "scan_timeout": SCAN_TIMEOUT,
            "known_cisco_ips": get_known_cisco_ips(),
            "total_known_devices": len(get_known_cisco_ips())
        },
        "capabilities": {
            "supports_single_ip": True,
            "supports_network_range": True,
            "supports_known_devices": True,
            "supports_topology_validation": True,
            "cisco_optimized": True
        },
        "recommendations": {
            "preferred_scan_type": "known_devices",
            "max_network_size": 50,
            "optimal_timeout": 15,
            "suggested_threads": min(8, SCAN_THREADS)
        }
    }

# Utility functions for enhanced scanning
def ping_host(ip: str, timeout: int = 3) -> bool:
    """
    Simple ping test using socket connection to port 22.
    More reliable than ICMP in some network environments.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, 22))
        sock.close()
        return result == 0
    except:
        return False

def get_device_priority(device_info: Dict) -> int:
    """
    Calculate device priority for sorting scan results.
    Higher priority = more important/likely to be managed.
    """
    priority = 0
    
    # Authenticated devices get highest priority
    if device_info.get("authenticated"):
        priority += 100
    
    # Role-based priority
    role = device_info.get("role_hint", "access")
    if role == "core":
        priority += 50
    elif role == "distribution":
        priority += 30
    elif role == "access":
        priority += 10
    
    # Known IP bonus
    if device_info.get("ip") in get_known_cisco_ips():
        priority += 25
    
    # Model/version information bonus
    if device_info.get("model", "unknown") != "unknown":
        priority += 5
    if device_info.get("ios_version", "unknown") != "unknown":
        priority += 5
    
    return priority