# new-network-automation-dashboard/services/net_scan.py
from typing import Optional, List
import nmap
import shutil
import socket, ipaddress
from config import DEFAULT_SCAN_RANGE
from services.ssh_utils import detect_bridge

def _scan_with_nmap(network: str) -> List[dict]:
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments="-p 22 --open")
    results = []
    for host in nm.all_hosts():
        state = nm[host].state()
        if "tcp" in nm[host] and 22 in nm[host]["tcp"] and nm[host]["tcp"][22]["state"] == "open":
            results.append({
                "ip": host,
                "status": state,
                "open_ports": [22],
                "bridge": detect_bridge(host)
            })
    return results

def _scan_with_sockets(network: str) -> List[dict]:
    net = ipaddress.ip_network(network, strict=False)
    hosts = list(net.hosts())[:256]  # limit to first 256 hosts
    results = []
    for h in hosts:
        ip = str(h)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        try:
            s.connect((ip, 22))
            results.append({
                "ip": ip,
                "status": "up",
                "open_ports": [22],
                "bridge": detect_bridge(ip)
            })
        except Exception:
            pass
        finally:
            s.close()
    return results

def scan_hosts(network_range: Optional[str] = None) -> List[dict]:
    """
    Scan a network range for OVS 'switches' reachable via SSH.
    Returns a list of {ip, status, open_ports, bridge}.
    """
    network = network_range or DEFAULT_SCAN_RANGE

    if shutil.which("nmap"):
        try:
            return _scan_with_nmap(network)
        except Exception:
            pass

    # fallback to socket scan
    return _scan_with_sockets(network)
