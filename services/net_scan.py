# services/net_scan.py
from typing import Optional, List
import nmap
import shutil
import socket
import ipaddress
import concurrent.futures
import threading
from config import DEFAULT_SCAN_RANGE
from services.ssh_utils import detect_bridge, test_cisco_connectivity

def _scan_with_nmap(network: str) -> List[dict]:
    """
    Advanced nmap scan focusing on Cisco network devices.
    Scans for common management ports and performs device fingerprinting.
    """
    nm = nmap.PortScanner()
    
    # Comprehensive scan for network management ports
    # Port 22: SSH, 23: Telnet, 80: HTTP, 443: HTTPS, 161: SNMP
    scan_args = "-p 22,23,80,443,161 --open -T4 -sS -O --osscan-guess"
    
    print(f"[NMAP] Starting advanced scan of {network}")
    nm.scan(hosts=network, arguments=scan_args)
    
    results = []
    
    for host in nm.all_hosts():
        device_info = {
            "ip": host,
            "status": nm[host].state(),
            "open_ports": [],
            "bridge": "scanning...",
            "os_info": {},
            "device_priority": 0  # Higher = more likely to be network device
        }
        
        # Extract open ports
        if "tcp" in nm[host]:
            for port in nm[host]["tcp"]:
                if nm[host]["tcp"][port]["state"] == "open":
                    device_info["open_ports"].append(port)
        
        # Analyze OS fingerprinting results
        if "osmatch" in nm[host]:
            for osmatch in nm[host]["osmatch"]:
                os_name = osmatch["name"].lower()
                device_info["os_info"]["name"] = osmatch["name"]
                device_info["os_info"]["accuracy"] = osmatch["accuracy"]
                
                # Prioritize Cisco devices
                if "cisco" in os_name or "ios" in os_name:
                    device_info["device_priority"] = 100
                    device_info["bridge"] = "Cisco-Detected"
                elif "linux" in os_name and any(port in device_info["open_ports"] for port in [22, 23, 161]):
                    device_info["device_priority"] = 50
                elif any(port in device_info["open_ports"] for port in [22, 23, 80, 443, 161]):
                    device_info["device_priority"] = 30
        
        # Enhanced device detection based on port combinations
        ports = set(device_info["open_ports"])
        
        if ports.intersection({22, 23, 161}):  # Network device pattern
            device_info["device_priority"] += 40
            
            # Attempt SSH detection for detailed device info
            if 22 in ports:
                print(f"[SCAN] Attempting SSH detection for {host}")
                bridge_info = detect_bridge(host)
                device_info["bridge"] = bridge_info
                
                # If it's a Cisco device, boost priority significantly
                if "Cisco" in bridge_info:
                    device_info["device_priority"] = 100
                # elif "OVS" in bridge_info:  # COMMENTED OUT - DE-PRIORITIZING OVS
                #     device_info["device_priority"] = 20  # Lower priority than Cisco
                elif "Linux" in bridge_info:
                    device_info["device_priority"] = 40
            else:
                device_info["bridge"] = "no-ssh-access"
        
        elif ports.intersection({80, 443}) and not ports.intersection({22, 23}):
            # Web-only device (might be AP or lightweight device)
            device_info["bridge"] = "web-managed-device"
            device_info["device_priority"] = 20
        
        else:
            device_info["bridge"] = "unknown-device"
            device_info["device_priority"] = 10
        
        # Only include devices that are likely network infrastructure
        if device_info["device_priority"] >= 20:
            results.append(device_info)
    
    # Sort by priority (Cisco devices first)
    results.sort(key=lambda x: x["device_priority"], reverse=True)
    
    print(f"[NMAP] Scan complete: {len(results)} network devices found")
    return results

def _scan_single_host(ip_str: str, management_ports: List[int]) -> Optional[dict]:
    """
    Scan a single host for network management services.
    Optimized for parallel execution.
    """
    open_ports = []
    
    # Quick port scan
    for port in management_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)  # Fast timeout for bulk scanning
        try:
            result = s.connect_ex((ip_str, port))
            if result == 0:
                open_ports.append(port)
        except:
            pass
        finally:
            s.close()
    
    if not open_ports:
        return None
    
    device_info = {
        "ip": ip_str,
        "status": "up",
        "open_ports": open_ports,
        "bridge": "scanning...",
        "device_priority": 0
    }
    
    # Prioritize devices with network management port patterns
    ports = set(open_ports)
    
    # Cisco/Network device indicators
    if 22 in ports and (23 in ports or 161 in ports):  # SSH + Telnet/SNMP
        device_info["device_priority"] = 80
    elif 22 in ports:  # SSH only
        device_info["device_priority"] = 60
    elif 23 in ports:  # Telnet (older Cisco devices)
        device_info["device_priority"] = 70
    elif ports.intersection({80, 443, 161}):  # Web/SNMP managed
        device_info["device_priority"] = 40
    
    # Attempt device identification if SSH is available
    if 22 in open_ports and device_info["device_priority"] >= 60:
        try:
            bridge_info = detect_bridge(ip_str)
            device_info["bridge"] = bridge_info
            
            if "Cisco" in bridge_info:
                device_info["device_priority"] = 100
            # elif "OVS" in bridge_info:  # COMMENTED OUT
            #     device_info["device_priority"] = 30
            elif "Linux" in bridge_info and "Network" in bridge_info:
                device_info["device_priority"] = 50
        except:
            device_info["bridge"] = "ssh-failed"
            device_info["device_priority"] = max(30, device_info["device_priority"] - 20)
    else:
        device_info["bridge"] = "no-ssh" if 22 not in open_ports else "ssh-timeout"
    
    return device_info if device_info["device_priority"] >= 30 else None

def _scan_with_sockets(network: str) -> List[dict]:
    """
    Fallback socket-based scan with parallel processing.
    Focuses on Cisco device discovery patterns.
    """
    try:
        net = ipaddress.ip_network(network, strict=False)
        hosts = list(net.hosts())[:254]  # Limit to reasonable subnet size
    except ValueError:
        print(f"[SCAN] Invalid network range: {network}")
        return []
    
    print(f"[SCAN] Starting socket scan of {len(hosts)} hosts in {network}")
    
    # Network management ports (prioritizing Cisco-common ports)
    management_ports = [22, 23, 80, 443, 161]  # SSH, Telnet, HTTP, HTTPS, SNMP
    
    results = []
    
    # Use thread pool for parallel scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_ip = {
            executor.submit(_scan_single_host, str(host), management_ports): str(host) 
            for host in hosts
        }
        
        for future in concurrent.futures.as_completed(future_to_ip):
            try:
                result = future.result(timeout=5)
                if result:
                    results.append(result)
            except concurrent.futures.TimeoutError:
                pass
            except Exception as e:
                print(f"[SCAN] Error scanning {future_to_ip[future]}: {e}")
    
    # Sort by priority (Cisco devices first)
    results.sort(key=lambda x: x["device_priority"], reverse=True)
    
    print(f"[SCAN] Socket scan complete: {len(results)} potential network devices found")
    return results

def scan_hosts(network_range: Optional[str] = None) -> List[dict]:
    """
    Scan a network range for Cisco and other network devices.
    Prioritizes Cisco device discovery and proper role detection.
    Returns a list of {ip, status, open_ports, bridge, device_priority}.
    """
    network = network_range or DEFAULT_SCAN_RANGE
    print(f"[SCAN] Scanning network: {network}")
    
    # Try nmap first for better device fingerprinting
    if shutil.which("nmap"):
        try:
            print("[SCAN] Using nmap for advanced device detection")
            results = _scan_with_nmap(network)
            
            # If we found devices, return them
            if results:
                print(f"[SCAN] Nmap found {len(results)} devices")
                return results
            else:
                print("[SCAN] Nmap found no devices, trying socket scan")
                
        except Exception as e:
            print(f"[SCAN] Nmap scan failed: {e}, falling back to socket scan")
    
    # Fallback to socket scan
    print("[SCAN] Using socket-based scanning")
    return _scan_with_sockets(network)

def scan_single_device(ip: str, username: str = "admin", password: str = "admin") -> dict:
    """
    Perform detailed scan of a single device.
    Returns comprehensive information for dashboard display.
    """
    print(f"[SCAN] Detailed scan of {ip}")
    
    # Basic connectivity test
    management_ports = [22, 23, 80, 443, 161]
    open_ports = []
    
    for port in management_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
        except:
            pass
        finally:
            s.close()
    
    device_info = {
        "ip": ip,
        "status": "up" if open_ports else "down",
        "open_ports": open_ports,
        "bridge": "unknown",
        "device_type": "unknown",
        "hostname": "unknown",
        "model": "unknown",
        "role_hint": "access",
        "scan_timestamp": None,
        "detailed": True
    }
    
    if not open_ports:
        device_info["bridge"] = "unreachable"
        return device_info
    
    # If SSH is available, get detailed device info
    if 22 in open_ports:
        try:
            # First, try device detection
            bridge_info = detect_bridge(ip, username, password)
            device_info["bridge"] = bridge_info
            
            # If it looks like a Cisco device, get detailed info
            if "Cisco" in bridge_info:
                device_info["device_type"] = "cisco"
                cisco_info = test_cisco_connectivity(ip, username, password)
                
                if cisco_info["authenticated"]:
                    device_info.update({
                        "hostname": cisco_info["hostname"],
                        "model": cisco_info["model"],
                        "ios_version": cisco_info["ios_version"],
                        "role_hint": cisco_info["role_hint"],
                        "device_type": "cisco"
                    })
                    
                    # Update bridge info with more details
                    if cisco_info["hostname"] != "unknown":
                        device_info["bridge"] = f"Cisco-{cisco_info['role_hint'].title()} ({cisco_info['hostname']})"
            
            # elif "OVS" in bridge_info:  # COMMENTED OUT - OVS DEPRIORITIZED
            #     device_info["device_type"] = "ovs"
            #     device_info["role_hint"] = "access"  # Default for OVS
            
            elif "Linux" in bridge_info:
                device_info["device_type"] = "linux"
                device_info["role_hint"] = "access"  # Most Linux devices are access-level
                
        except Exception as e:
            device_info["bridge"] = f"ssh-error: {str(e)[:30]}"
    
    else:
        # No SSH, try to infer device type from port pattern
        ports = set(open_ports)
        if 23 in ports:  # Telnet suggests older network equipment
            device_info["bridge"] = "telnet-device"
            device_info["device_type"] = "cisco"  # Likely older Cisco
            device_info["role_hint"] = "access"
        elif ports.intersection({80, 443}):
            device_info["bridge"] = "web-managed"
            device_info["device_type"] = "unknown"
        elif 161 in ports:
            device_info["bridge"] = "snmp-device"
            device_info["device_type"] = "cisco"  # SNMP suggests network equipment
    
    import time
    device_info["scan_timestamp"] = time.time()
    
    print(f"[SCAN] Device {ip}: {device_info['bridge']} ({device_info['device_type']})")
    return device_info

def validate_cisco_device(ip: str, username: str, password: str, enable_password: str = None) -> dict:
    """
    Validate and gather comprehensive information about a Cisco device.
    Used before adding device to topology.
    """
    print(f"[VALIDATE] Testing Cisco device at {ip}")
    
    validation_result = {
        "valid": False,
        "device_info": {},
        "errors": [],
        "warnings": []
    }
    
    try:
        # Test basic connectivity
        connectivity = test_cisco_connectivity(ip, username, password, enable_password)
        
        if not connectivity["reachable"]:
            validation_result["errors"].append("Device is not reachable")
            return validation_result
        
        if not connectivity["authenticated"]:
            validation_result["errors"].append("Authentication failed")
            validation_result["errors"].append(connectivity.get("error", "Unknown auth error"))
            return validation_result
        
        # Device is reachable and authenticated
        validation_result["valid"] = True
        validation_result["device_info"] = connectivity
        
        # Add warnings for missing information
        if connectivity["hostname"] == "unknown":
            validation_result["warnings"].append("Could not determine hostname")
        
        if connectivity["model"] == "unknown":
            validation_result["warnings"].append("Could not determine device model")
        
        if connectivity["device_type"] != "cisco_ios":
            validation_result["warnings"].append("Device may not be running Cisco IOS")
        
        print(f"[VALIDATE] Device {ip} validated successfully: {connectivity['hostname']}")
        
    except Exception as e:
        validation_result["errors"].append(f"Validation failed: {str(e)}")
    
    return validation_result