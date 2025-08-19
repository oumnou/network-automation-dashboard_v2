# services/net_scan.py
from typing import Optional, List
import nmap
import shutil
import socket, ipaddress
from config import DEFAULT_SCAN_RANGE
from services.ssh_utils import detect_bridge

def _scan_with_nmap(network: str) -> List[dict]:
    """Scan using nmap for devices with SSH open"""
    nm = nmap.PortScanner()
    # More aggressive scan - includes common switch management ports
    nm.scan(hosts=network, arguments="-p 22,23,80,443 --open -T4 -sS")
    results = []
    
    for host in nm.all_hosts():
        state = nm[host].state()
        open_ports = []
        
        if "tcp" in nm[host]:
            for port in nm[host]["tcp"]:
                if nm[host]["tcp"][port]["state"] == "open":
                    open_ports.append(port)
        
        # If device has SSH (22) or other management ports, check for OVS
        if 22 in open_ports:
            bridge = detect_bridge(host)
            results.append({
                "ip": host,
                "status": state,
                "open_ports": open_ports,
                "bridge": bridge
            })
        elif any(port in [23, 80, 443] for port in open_ports):
            # Likely a network device, but no SSH - mark as potential switch
            results.append({
                "ip": host,
                "status": state,
                "open_ports": open_ports,
                "bridge": "no-ssh"
            })
    
    return results

def _scan_with_sockets(network: str) -> List[dict]:
    """Fallback socket-based scan"""
    try:
        net = ipaddress.ip_network(network, strict=False)
        # Scan more hosts but with timeout
        hosts = list(net.hosts())[:254]
    except ValueError:
        return []
    
    results = []
    management_ports = [22, 23, 80, 443]
    
    for h in hosts:
        ip = str(h)
        open_ports = []
        
        for port in management_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            try:
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
            except:
                pass
            finally:
                s.close()
        
        if open_ports:
            if 22 in open_ports:
                bridge = detect_bridge(ip)
            else:
                bridge = "no-ssh"
            
            results.append({
                "ip": ip,
                "status": "up",
                "open_ports": open_ports,
                "bridge": bridge
            })
    
    return results

def scan_hosts(network_range: Optional[str] = None) -> List[dict]:
    """
    Scan a network range for network devices (switches, routers, etc.).
    Returns a list of {ip, status, open_ports, bridge}.
    """
    network = network_range or DEFAULT_SCAN_RANGE

    if shutil.which("nmap"):
        try:
            return _scan_with_nmap(network)
        except Exception as e:
            print(f"[ERROR] Nmap scan failed: {e}")

    # fallback to socket scan
    return _scan_with_sockets(network)