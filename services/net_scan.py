# services/net_scan.py - Cisco Optimized Scanner
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
    Scan network range for Cisco devices and return detailed information.
    Optimized for Cisco sandbox environment.
    """
    network = network_range or DEFAULT_SCAN_RANGE
    print(f"[SCAN] Starting Cisco device scan of {network}")
    
    try:
        # Parse network range
        net = ipaddress.ip_network(network, strict=False)
        hosts = list(net.hosts())
        
        # Limit hosts for sandbox environment
        if len(hosts) > 50:
            print(f"[SCAN] Limiting scan to first 50 hosts of {len(hosts)} total")
            hosts = hosts[:50]
            
    except ValueError as e:
        print(f"[SCAN] Invalid network range {network}: {e}")
        return []
    
    print(f"[SCAN] Scanning {len(hosts)} hosts for Cisco devices...")
    
    # Step 1: Quick port scan to find devices with management ports open
    reachable_hosts = _quick_port_scan(hosts)
    print(f"[SCAN] Found {len(reachable_hosts)} hosts with management ports open")
    
    # Step 2: Detailed Cisco device detection
    cisco_devices = _detailed_cisco_scan(reachable_hosts)
    print(f"[SCAN] Identified {len(cisco_devices)} Cisco devices")
    
    return cisco_devices

def _quick_port_scan(hosts: List[ipaddress.IPv4Address]) -> List[Dict]:
    """
    Quick parallel scan to identify hosts with management ports open.
    """
    reachable_hosts = []
    
    def scan_single_host(host_ip: str) -> Optional[Dict]:
        open_ports = []
        
        # Check common Cisco management ports
        management_ports = [22, 23, 80, 443, 161]
        
        for port in management_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(SCAN_TIMEOUT)
            
            try:
                result = sock.connect_ex((host_ip, port))
                if result == 0:
                    open_ports.append(port)
            except socket.error:
                pass
            finally:
                sock.close()
        
        if open_ports:
            return {
                "ip": host_ip,
                "open_ports": open_ports,
                "scan_priority": _calculate_scan_priority(open_ports)
            }
        return None
    
    # Use thread pool for parallel scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=SCAN_THREADS) as executor:
        host_strings = [str(host) for host in hosts]
        futures = {executor.submit(scan_single_host, host): host for host in host_strings}
        
        for future in concurrent.futures.as_completed(futures, timeout=60):
            try:
                result = future.result(timeout=10)
                if result:
                    reachable_hosts.append(result)
            except (concurrent.futures.TimeoutError, Exception) as e:
                print(f"[SCAN] Error scanning {futures[future]}: {e}")
    
    # Sort by scan priority (SSH + other management ports = higher priority)
    reachable_hosts.sort(key=lambda x: x["scan_priority"], reverse=True)
    return reachable_hosts

def _calculate_scan_priority(open_ports: List[int]) -> int:
    """
    Calculate scanning priority based on open ports.
    Higher score = more likely to be a network device.
    """
    score = 0
    
    if 22 in open_ports:  # SSH
        score += 50
    if 23 in open_ports:  # Telnet (often Cisco)
        score += 40
    if 161 in open_ports:  # SNMP (network management)
        score += 30
    if 443 in open_ports:  # HTTPS (web management)
        score += 20
    if 80 in open_ports:  # HTTP (web management)
        score += 10
    
    # Bonus for multiple management ports
    if len(open_ports) >= 3:
        score += 20
    
    return score

def _detailed_cisco_scan(hosts: List[Dict]) -> List[Dict]:
    """
    Perform detailed Cisco device identification and information gathering.
    """
    cisco_devices = []
    
    def scan_cisco_device(host_info: Dict) -> Optional[Dict]:
        ip = host_info["ip"]
        
        # Only proceed if SSH is available (required for Cisco detection)
        if 22 not in host_info["open_ports"]:
            return None
        
        print(f"[SCAN] Testing Cisco connectivity for {ip}...")
        
        # Test Cisco connectivity and get device information
        device_info = test_cisco_connectivity(
            ip=ip,
            username=DEFAULT_CISCO_USERNAME,
            password=DEFAULT_CISCO_PASSWORD
        )
        
        # Only return if we successfully authenticated and identified a Cisco device
        if device_info["authenticated"] and device_info["device_type"] == "cisco_ios":
            # Format for dashboard compatibility
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
                "device_priority": 100,  # Highest priority for authenticated Cisco devices
                "last_scan": int(time.time()),
                "scan_details": device_info
            }
            
            print(f"[SCAN] ✅ Found Cisco device: {device_info['hostname']} ({ip}) - {device_info['role_hint']}")
            return result
        else:
            print(f"[SCAN] ❌ Device at {ip} is not a reachable Cisco device: {device_info.get('error', 'Unknown error')}")
            return None
    
    # Scan devices sequentially to avoid overwhelming the sandbox
    # (Parallel scanning can cause connection issues with Cisco devices)
    for host_info in hosts:
        try:
            result = scan_cisco_device(host_info)
            if result:
                cisco_devices.append(result)
        except Exception as e:
            print(f"[SCAN] Error scanning {host_info['ip']}: {e}")
        
        # Small delay between scans to be nice to the sandbox
        time.sleep(1)
    
    return cisco_devices

def _format_bridge_info(device_info: Dict) -> str:
    """
    Format device information for bridge display in the dashboard.
    """
    hostname = device_info.get("hostname", "unknown")
    role = device_info.get("role_hint", "access").title()
    model = device_info.get("model", "")
    
    if hostname != "unknown":
        if model and model != "unknown":
            return f"Cisco-{role} ({hostname}, {model})"
        else:
            return f"Cisco-{role} ({hostname})"
    else:
        return f"Cisco-{role} (Unknown Device)"

def scan_single_device(ip: str, username: str = None, password: str = None) -> Dict:
    """
    Perform detailed scan of a single Cisco device.
    """
    username = username or DEFAULT_CISCO_USERNAME
    password = password or DEFAULT_CISCO_PASSWORD
    
    print(f"[SCAN] Detailed scan of Cisco device {ip}")
    
    # First check basic connectivity
    open_ports = []
    for port in [22, 23, 80, 443, 161]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
        except:
            pass
        finally:
            sock.close()
    
    if not open_ports:
        return {
            "ip": ip,
            "status": "unreachable",
            "error": "No management ports responding",
            "open_ports": [],
            "device_type": "unknown"
        }
    
    # Get detailed Cisco information
    device_info = test_cisco_connectivity(ip, username, password)
    
    result = {
        "ip": ip,
        "status": device_info["status"],
        "open_ports": open_ports,
        "device_type": device_info["device_type"],
        "hostname": device_info["hostname"],
        "model": device_info["model"],
        "ios_version": device_info["ios_version"],
        "role_hint": device_info["role_hint"],
        "interface_count": device_info["interface_count"],
        "uptime": device_info["uptime"],
        "bridge": _format_bridge_info(device_info),
        "authenticated": device_info["authenticated"],
        "reachable": device_info["reachable"],
        "error": device_info.get("error"),
        "scan_timestamp": int(time.time()),
        "detailed": True
    }
    
    print(f"[SCAN] Single device scan complete for {ip}: {result['bridge']}")
    return result

def get_known_cisco_ips() -> List[str]:
    """
    Return list of known Cisco device IPs from your sandbox topology.
    Useful for targeted scanning.
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

def scan_known_cisco_devices() -> List[Dict]:
    """
    Scan only the known Cisco device IPs for faster results.
    This is more efficient than scanning the entire subnet.
    """
    print("[SCAN] Scanning known Cisco device IPs...")
    
    known_ips = get_known_cisco_ips()
    results = []
    
    for ip in known_ips:
        print(f"[SCAN] Testing known Cisco device {ip}...")
        try:
            device_info = scan_single_device(ip)
            if device_info["authenticated"]:
                results.append(device_info)
                print(f"[SCAN] ✅ {ip}: {device_info['hostname']} ({device_info['role_hint']})")
            else:
                print(f"[SCAN] ❌ {ip}: {device_info.get('error', 'Not accessible')}")
        except Exception as e:
            print(f"[SCAN] Error scanning {ip}: {e}")
        
        # Brief pause between devices
        time.sleep(0.5)
    
    print(f"[SCAN] Known device scan complete: {len(results)}/{len(known_ips)} devices accessible")
    return results

def validate_cisco_topology(devices: List[Dict]) -> Dict:
    """
    Validate that discovered devices match expected topology.
    """
    validation = {
        "expected_count": 7,
        "found_count": len(devices),
        "missing_devices": [],
        "unexpected_devices": [],
        "role_distribution": {"core": 0, "distribution": 0, "access": 0},
        "topology_valid": False
    }
    
    known_ips = set(get_known_cisco_ips())
    found_ips = set(device["ip"] for device in devices)
    
    # Check for missing devices
    validation["missing_devices"] = list(known_ips - found_ips)
    
    # Check for unexpected devices (shouldn't happen with targeted scan)
    validation["unexpected_devices"] = list(found_ips - known_ips)
    
    # Count devices by role
    for device in devices:
        role = device.get("role_hint", "access")
        if role in validation["role_distribution"]:
            validation["role_distribution"][role] += 1
    
    # Check if topology matches expectations
    expected_roles = {"core": 1, "distribution": 2, "access": 4}
    validation["topology_valid"] = validation["role_distribution"] == expected_roles
    
    return validation