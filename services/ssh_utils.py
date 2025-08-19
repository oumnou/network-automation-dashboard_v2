# services/ssh_utils.py
from typing import Optional, Tuple
import paramiko

# services/ssh_utils.py
from typing import Optional, Tuple
import paramiko

def detect_bridge(ip: str, username: str = "kali", password: str = "kali") -> str:
    """
    Connect via SSH and detect device type and bridge/interface info.
    Returns bridge name for OVS, interface info for other devices, or status.
    """
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=5)
        
        # First check if it's an OVS switch
        stdin, stdout, stderr = ssh.exec_command("which ovs-vsctl 2>/dev/null")
        if stdout.read().decode().strip():
            # It's OVS - get bridge list
            stdin, stdout, stderr = ssh.exec_command("ovs-vsctl br-list 2>/dev/null")
            bridges = stdout.read().decode().splitlines()
            ssh.close()
            
            if bridges:
                bridge_name = bridges[0].strip()
                return bridge_name if bridge_name else "ovs-no-bridges"
            return "ovs-no-bridges"
        
        # Check if it's a Linux device with network interfaces
        stdin, stdout, stderr = ssh.exec_command("ip link show 2>/dev/null | grep -E '^[0-9]+:' | head -3")
        interfaces = stdout.read().decode()
        ssh.close()
        
        if interfaces:
            # Extract first non-loopback interface
            lines = interfaces.strip().split('\n')
            for line in lines:
                if 'lo:' not in line and ':' in line:
                    iface = line.split(':')[1].strip().split('@')[0]
                    return f"linux-{iface}"
            return "linux-device"
        
        return "ssh-accessible"
        
    except paramiko.AuthenticationException:
        return "auth-failed"
    except paramiko.SSHException:
        return "ssh-failed"
    except Exception:
        return "unknown"

def fetch_running_config(ip: str, username: str, password: str, 
                        secret: Optional[str] = None, 
                        device_type: str = "ovs") -> Tuple[bool, str, str]:
    """
    Connect via SSH and fetch the device running config.
    Supports OVS and Linux devices. Will add Cisco support later.
    Returns (success, config_output, engine_used).
    """
    engine = f"ssh_{device_type}"
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=10)
        
        if device_type == "ovs":
            # Get OVS configuration
            stdin, stdout, stderr = ssh.exec_command("ovs-vsctl show")
            config = stdout.read().decode()
            
            if not config.strip():
                # Try bridge info
                stdin, stdout, stderr = ssh.exec_command("ovs-vsctl br-list")
                bridges = stdout.read().decode()
                config = f"! OVS Bridges:\n{bridges}\n! Use 'ovs-vsctl show' for detailed config"
        
        elif device_type == "linux":
            # Get Linux network configuration
            commands = [
                "ip addr show",
                "ip route show", 
                "cat /proc/net/dev"
            ]
            config_parts = []
            for cmd in commands:
                stdin, stdout, stderr = ssh.exec_command(cmd)
                output = stdout.read().decode()
                config_parts.append(f"! {cmd}\n{output}\n")
            config = "\n".join(config_parts)
        
        else:
            # Generic device info
            stdin, stdout, stderr = ssh.exec_command("uname -a && ip addr")
            config = stdout.read().decode()
        
        ssh.close()
        
        if not config.strip():
            config = f"! No configuration retrieved from {ip}\n! Device may not support requested commands"
        
        return True, config, engine
        
    except paramiko.AuthenticationException:
        return False, f"Authentication failed for {ip}", engine
    except paramiko.SSHException as e:
        return False, f"SSH connection failed for {ip}: {str(e)}", engine
    except Exception as e:
        return False, f"Failed to fetch config from {ip}: {str(e)}", engine

def fetch_running_config(ip: str, username: str, password: str, 
                        secret: Optional[str] = None, 
                        device_type: str = "ovs") -> Tuple[bool, str, str]:
    """
    Connect via SSH and fetch the switch running config (OVS config).
    Returns (success, config_output, engine_used).
    """
    engine = "ssh_ovs"
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=10)
        
        # Get OVS configuration
        stdin, stdout, stderr = ssh.exec_command("ovs-vsctl show")
        config = stdout.read().decode()
        error = stderr.read().decode()
        ssh.close()
        
        if error and not config:
            return False, f"SSH Error: {error}", engine
        
        if not config.strip():
            config = f"! No OVS configuration found on {ip}\n! Device may not have OVS installed"
        
        return True, config, engine
        
    except paramiko.AuthenticationException:
        return False, f"Authentication failed for {ip}", engine
    except paramiko.SSHException as e:
        return False, f"SSH connection failed for {ip}: {str(e)}", engine
    except Exception as e:
        return False, f"Failed to fetch config from {ip}: {str(e)}", engine