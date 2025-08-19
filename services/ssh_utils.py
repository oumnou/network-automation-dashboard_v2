# new-network-automation-dashboard/services/ssh_utils.py
from typing import Optional
import paramiko

SSH_USER = "kali"  # replace with your SSH username
SSH_PASS = "kali"  # replace with your SSH password

def detect_bridge(ip: str) -> str:
    """
    Connect via SSH and return the first OVS bridge name found.
    Returns "unknown" if unreachable or no bridges found.
    """
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=SSH_USER, password=SSH_PASS, timeout=2)
        stdin, stdout, stderr = ssh.exec_command("ovs-vsctl br-list")
        bridges = stdout.read().decode().splitlines()
        ssh.close()
        if bridges:
            return bridges[0]  # return first bridge
    except Exception:
        pass
    return "unknown"

def fetch_running_config(ip: str) -> str:
    """
    Connect via SSH and fetch the switch running config (OVS config).
    Returns as a string.
    """
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=SSH_USER, password=SSH_PASS, timeout=2)
        stdin, stdout, stderr = ssh.exec_command("ovs-vsctl show")
        config = stdout.read().decode()
        ssh.close()
        return config
    except Exception as e:
        print(f"[!] Failed to fetch config from {ip}: {e}")
        return ""
