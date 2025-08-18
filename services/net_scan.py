from typing import List, Tuple, Optional
import socket, ipaddress, subprocess, shutil
from config import DEFAULT_SCAN_RANGE, DEFAULT_SCAN_PORTS

def _scan_with_nmap(network: str, ports: list) -> list:
    import nmap  # python-nmap
    nm = nmap.PortScanner()
    port_str = ",".join(str(p) for p in ports)
    # Only list hosts with at least one open port
    nm.scan(hosts=network, arguments=f"-p {port_str} --open")
    results = []
    for host in nm.all_hosts():
        host_state = nm[host].state()
        open_ports = []
        for proto in nm[host].all_protocols():
            for p, pdata in nm[host][proto].items():
                if pdata.get("state") == "open":
                    open_ports.append(int(p))
        results.append({
            "ip": host,
            "state": host_state,
            "open_ports": sorted(open_ports),
        })
    return results

def _scan_with_sockets(network: str, ports: list) -> list:
    # Simple, slower fallback: TCP connect scan for first 256 hosts of subnet
    net = ipaddress.ip_network(network, strict=False)
    hosts = list(net.hosts())[:256]
    out = []
    for h in hosts:
        ip = str(h)
        open_ports = []
        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            try:
                s.connect((ip, port))
                open_ports.append(port)
            except Exception:
                pass
            finally:
                s.close()
        if open_ports:
            out.append({"ip": ip, "state": "up", "open_ports": open_ports})
    return out

def scan_hosts(network_range: Optional[str]=None, ports: Optional[list]=None) -> Tuple[list, str]:
    network = network_range or DEFAULT_SCAN_RANGE
    ports = ports or DEFAULT_SCAN_PORTS
    # Prefer python-nmap if nmap engine is available on system
    try:
        # Quick check if nmap binary exists; python-nmap still needs it
        if shutil.which("nmap"):
            results = _scan_with_nmap(network, ports)
            return results, "nmap"
    except Exception:
        pass
    # Fallback
    results = _scan_with_sockets(network, ports)
    return results, "socket"
