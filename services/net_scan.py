# services/net_scan.py - Production-Enhanced Scanner
from typing import List, Dict, Optional
import socket
import concurrent.futures
import time
import ipaddress
from config import (
    DEFAULT_SCAN_RANGE, SCAN_THREADS, SCAN_TIMEOUT,
    CISCO_CREDENTIAL_SETS, MANAGEMENT_PORTS, AUTO_DISCOVER_NETWORK
)
from services.ssh_utils import test_cisco_connectivity_multi_cred

def scan_hosts(network_range: Optional[str] = None, smart_scan: bool = True) -> List[Dict]:
    """
    Production-enhanced network scanner with auto-discovery and credential cycling.
    """
    network = network_range or DEFAULT_SCAN_RANGE
    print(f"[SCAN] Starting production network scan of {network}")
    
    # Handle different input types
    if _is_single_ip(network):
        print(f"[SCAN] Single IP detected: {network}")
        return [scan_single_device_multi_cred(network)]
    
    # Use smart scanning for efficiency
    if smart_scan:
        print("[SCAN] Using smart scanning (port scan → device identification)")
        return _smart_network_scan(network)
    else:
        print("[SCAN] Using comprehensive scanning")
        return _comprehensive_network_scan(network)

def _smart_network_scan(network: str) -> List[Dict]:
    """
    Smart two-phase scanning: quick port scan, then detailed device identification.
    """
    try:
        net = ipaddress.ip_network(network, strict=False)
        hosts = list(net.hosts())
        
        if len(hosts) > 254:
            print(f"[SCAN] Large network ({len(hosts)} hosts) - limiting to manageable size")
            hosts = hosts[:254]  # Limit for performance
            
    except ValueError as e:
        print(f"[SCAN] Invalid network range: {e}")
        return []
    
    results = []
    
    # Phase 1: Quick port scan
    print(f"[SCAN] Phase 1: Port scanning {len(hosts)} hosts...")
    promising_hosts = _enhanced_port_scan_production(hosts)
    
    if not promising_hosts:
        print("[SCAN] No hosts with management ports found")
        return []
    
    print(f"[SCAN] Found {len(promising_hosts)} hosts with management ports")
    
    # Phase 2: Device identification with multiple credentials
    print("[SCAN] Phase 2: Identifying Cisco devices...")
    cisco_devices = []
    
    for host_info in promising_hosts:
        ip = host_info["ip"]
        print(f"[SCAN] Testing device {ip}...")
        
        device_info = scan_single_device_multi_cred(ip)
        if device_info and device_info.get("authenticated"):
            cisco_devices.append(device_info)
            print(f"[SCAN] ✅ Found Cisco device: {device_info.get('hostname', 'unknown')} at {ip}")
        else:
            print(f"[SCAN] ❌ {ip}: Not accessible or not Cisco")
        
        # Small delay to be network-friendly
        time.sleep(0.2)
    
    print(f"[SCAN] Smart scan complete: {len(cisco_devices)} Cisco devices found")
    return cisco_devices

def _enhanced_port_scan_production(hosts: List[ipaddress.IPv4Address]) -> List[Dict]:
    """
    Production-optimized port scanner with better error handling.
    """
    def scan_host_management_ports(host_ip: str) -> Optional[Dict]:
        """Scan management ports on a single host"""
        open_ports = []
        priority_score = 0
        response_time = None
        
        # Test ports in priority order
        for port, service in MANAGEMENT_PORTS.items():
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            
            try:
                result = sock.connect_ex((host_ip, port))
                if result == 0:
                    response_time = time.time() - start_time
                    open_ports.append({"port": port, "service": service, "response_time": response_time})
                    
                    # Calculate priority score
                    if port == 22:
                        priority_score += 50  # SSH highest priority
                    elif port == 23:
                        priority_score += 40  # Telnet suggests network device
                    elif port == 443:
                        priority_score += 30  # HTTPS management
                    elif port == 161:
                        priority_score += 25  # SNMP
                    else:
                        priority_score += 10
                        
            except socket.error:
                pass
            finally:
                sock.close()
        
        if open_ports:
            return {
                "ip": host_ip,
                "open_ports": [p["port"] for p in open_ports],
                "port_details": open_ports,
                "priority_score": priority_score,
                "has_ssh": 22 in [p["port"] for p in open_ports],
                "has_telnet": 23 in [p["port"] for p in open_ports],
                "avg_response_time": sum(p["response_time"] for p in open_ports) / len(open_ports) if response_time else None,
                "likely_network_device": priority_score >= 40
            }
        return None
    
    # Use threading for port scanning
    max_workers = min(SCAN_THREADS * 2, 20)  # More threads for port scanning
    promising_hosts = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        host_strings = [str(host) for host in hosts]
        
        # Submit all scan jobs
        future_to_host = {
            executor.submit(scan_host_management_ports, host): host 
            for host in host_strings
        }
        
        # Collect results with timeout
        for future in concurrent.futures.as_completed(future_to_host, timeout=60):
            try:
                result = future.result(timeout=5)
                if result and result["likely_network_device"]:
                    promising_hosts.append(result)
            except (concurrent.futures.TimeoutError, Exception) as e:
                host = future_to_host[future]
                print(f"[SCAN] Port scan error for {host}: {e}")
    
    # Sort by priority and response time
    promising_hosts.sort(
        key=lambda x: (x["priority_score"], -x.get("avg_response_time", 1)), 
        reverse=True
    )
    
    return promising_hosts

def scan_single_device_multi_cred(ip: str) -> Dict:
    """
    Enhanced single device scan with multiple credential attempts.
    """
    print(f"[SCAN] Comprehensive scan of {ip} with multiple credentials")
    
    # Quick connectivity check first
    if not _quick_connectivity_check(ip):
        return {
            "ip": ip,
            "status": "unreachable",
            "error": "Host unreachable or no SSH/Telnet",
            "authenticated": False,
            "reachable": False
        }
    
    # Try each credential set
    for i, cred_set in enumerate(CISCO_CREDENTIAL_SETS):
        print(f"[SCAN] Trying credential set {i+1}/{len(CISCO_CREDENTIAL_SETS)} for {ip}")
        
        try:
            result = test_cisco_connectivity_multi_cred(
                ip=ip,
                username=cred_set["username"],
                password=cred_set["password"],
                enable_password=cred_set["enable"],
                timeout=12
            )
            
            if result.get("authenticated"):
                print(f"[SCAN] ✅ Authentication successful for {ip} with credential set {i+1}")
                result["credential_set_used"] = i + 1
                result["credentials"] = f"{cred_set['username']}/*****"
                return result
                
        except Exception as e:
            print(f"[SCAN] Credential set {i+1} failed for {ip}: {e}")
            continue
    
    # If all credentials failed
    print(f"[SCAN] ❌ All credential sets failed for {ip}")
    return {
        "ip": ip,
        "status": "auth_failed", 
        "error": f"Authentication failed with all {len(CISCO_CREDENTIAL_SETS)} credential sets",
        "authenticated": False,
        "reachable": True,
        "credential_attempts": len(CISCO_CREDENTIAL_SETS)
    }

def _quick_connectivity_check(ip: str) -> bool:
    """Quick check if host has SSH or Telnet open"""
    for port in [22, 23]:  # SSH, Telnet
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            if sock.connect_ex((ip, port)) == 0:
                sock.close()
                return True
        except:
            pass
        finally:
            sock.close()
    return False

def discover_networks() -> List[str]:
    """
    Auto-discover likely network ranges on the current system.
    """
    networks = []
    
    try:
        import subprocess
        import re
        
        # Try to get routing table to find networks
        if os.name == 'nt':  # Windows
            result = subprocess.run(['route', 'print'], capture_output=True, text=True)
            # Parse Windows route table
            for line in result.stdout.split('\n'):
                match = re.search(r'(\d+\.\d+\.\d+\.)0\s+255\.255\.255\.0', line)
                if match:
                    network = f"{match.group(1)}0/24"
                    if network not in networks:
                        networks.append(network)
        else:  # Linux/Unix
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            # Parse Linux route table  
            for line in result.stdout.split('\n'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+/\d+)', line)
                if match and '/24' in match.group(1):
                    networks.append(match.group(1))
                    
    except Exception as e:
        print(f"[SCAN] Network discovery error: {e}")
    
    # Add common enterprise ranges if nothing found
    if not networks:
        networks = [
            "192.168.1.0/24",
            "192.168.0.0/24", 
            "10.0.0.0/24",
            "172.16.0.0/24"
        ]
        
    # Remove duplicates and limit
    networks = list(set(networks))[:10]  # Max 10 networks
    
    print(f"[SCAN] Discovered networks: {networks}")
    return networks

def scan_discovered_networks() -> List[Dict]:
    """
    Scan all discovered networks and return consolidated results.
    """
    if not AUTO_DISCOVER_NETWORK:
        print("[SCAN] Auto-discovery disabled")
        return []
    
    networks = discover_networks()
    all_devices = []
    
    for network in networks:
        print(f"[SCAN] Scanning discovered network: {network}")
        try:
            devices = _smart_network_scan(network)
            all_devices.extend(devices)
            
            if devices:
                print(f"[SCAN] Found {len(devices)} devices in {network}")
            else:
                print(f"[SCAN] No Cisco devices found in {network}")
                
        except Exception as e:
            print(f"[SCAN] Error scanning {network}: {e}")
    
    # Remove duplicates by IP
    unique_devices = {}
    for device in all_devices:
        ip = device["ip"]
        if ip not in unique_devices:
            unique_devices[ip] = device
    
    final_devices = list(unique_devices.values())
    print(f"[SCAN] Network discovery complete: {len(final_devices)} unique Cisco devices found")
    
    return final_devices

# Utility functions
def _is_single_ip(network_str: str) -> bool:
    """Check if input is single IP"""
    try:
        ipaddress.ip_address(network_str)
        return True
    except ValueError:
        return False

def get_scan_recommendations() -> Dict:
    """Get scanning recommendations for the current environment"""
    return {
        "recommended_approach": "smart_scan",
        "credential_sets": len(CISCO_CREDENTIAL_SETS),
        "auto_discovery": AUTO_DISCOVER_NETWORK,
        "max_concurrent_devices": SCAN_THREADS,
        "timeout_settings": {
            "port_scan": 3,
            "device_auth": 12,
            "total_per_device": 15
        },
        "tips": [
            "Use smart scanning for unknown networks",
            "Set environment variables for your credentials",
            "Start with smaller network ranges (/26 or /27)",
            "Enable auto-discovery for enterprise environments"
        ]
    }