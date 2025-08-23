# services/ssh_utils.py - Cisco Optimized
from typing import Optional, Tuple, Dict
import paramiko
import time
import re
import socket
from config import (
    DEFAULT_CISCO_USERNAME, DEFAULT_CISCO_PASSWORD, DEFAULT_ENABLE_PASSWORD,
    SSH_CONNECT_TIMEOUT, COMMAND_TIMEOUT, CISCO_IOS_PATTERNS,
    CISCO_HOSTNAME_PATTERNS
)

def test_cisco_connectivity(ip: str, username: str = None, password: str = None, 
                          enable_password: str = None, timeout: int = 10) -> Dict:
    """
    Test connectivity to Cisco device and gather comprehensive information.
    Returns detailed device information for dashboard integration.
    """
    # Use default credentials if not provided
    username = username or DEFAULT_CISCO_USERNAME
    password = password or DEFAULT_CISCO_PASSWORD
    enable_password = enable_password or DEFAULT_ENABLE_PASSWORD
    
    result = {
        "reachable": False,
        "authenticated": False,
        "device_type": "unknown",
        "hostname": "unknown",
        "model": "unknown",
        "ios_version": "unknown",
        "serial": "unknown",
        "uptime": "unknown",
        "role_hint": "access",
        "interface_count": 0,
        "management_ip": ip,
        "status": "down",
        "error": None,
        "last_seen": int(time.time())
    }
    
    try:
        # Test basic TCP connectivity first
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        if sock.connect_ex((ip, 22)) != 0:
            result["error"] = "SSH port (22) not reachable"
            sock.close()
            return result
        sock.close()
        
        result["reachable"] = True
        
        # Establish SSH connection
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=ip, 
            username=username, 
            password=password, 
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False
        )
        
        result["authenticated"] = True
        result["status"] = "up"
        
        # Get device information using Cisco IOS commands
        device_info = _get_cisco_device_info(ssh, enable_password)
        result.update(device_info)
        
        ssh.close()
        
        print(f"[SSH] Successfully connected to {ip}: {result['hostname']} ({result['device_type']})")
        
    except paramiko.AuthenticationException:
        result["error"] = f"Authentication failed with {username}/*****"
        print(f"[SSH] Auth failed for {ip} with {username}")
        
    except paramiko.SSHException as e:
        result["error"] = f"SSH connection failed: {str(e)}"
        print(f"[SSH] SSH error for {ip}: {e}")
        
    except socket.timeout:
        result["error"] = "Connection timeout"
        print(f"[SSH] Timeout connecting to {ip}")
        
    except Exception as e:
        result["error"] = f"Connection error: {str(e)}"
        print(f"[SSH] Unexpected error for {ip}: {e}")
    
    return result

def _get_cisco_device_info(ssh: paramiko.SSHClient, enable_password: str = None) -> Dict:
    """
    Extract detailed information from Cisco device using IOS commands.
    """
    info = {
        "device_type": "cisco_ios",
        "hostname": "unknown",
        "model": "unknown",
        "ios_version": "unknown",
        "serial": "unknown",
        "uptime": "unknown",
        "role_hint": "access",
        "interface_count": 0
    }
    
    try:
        # Start interactive shell for better control
        shell = ssh.invoke_shell()
        time.sleep(2)
        
        # Enter enable mode if enable password provided
        if enable_password:
            shell.send("enable\n")
            time.sleep(1)
            shell.send(f"{enable_password}\n")
            time.sleep(2)
        
        # Set terminal parameters
        shell.send("terminal length 0\n")
        shell.send("terminal width 0\n")
        time.sleep(1)
        
        # Clear buffer
        if shell.recv_ready():
            shell.recv(4096)
        
        # Get version information
        version_info = _execute_cisco_command(shell, "show version")
        if version_info:
            info.update(_parse_version_output(version_info))
        
        # Get hostname
        hostname_info = _execute_cisco_command(shell, "show running-config | include hostname")
        if hostname_info:
            hostname_match = re.search(r'hostname\s+(\S+)', hostname_info, re.IGNORECASE)
            if hostname_match:
                info["hostname"] = hostname_match.group(1)
                # Determine role from hostname
                info["role_hint"] = _determine_role_from_hostname(info["hostname"])
        
        # Get interface count
        interface_info = _execute_cisco_command(shell, "show ip interface brief")
        if interface_info:
            # Count interfaces (exclude loopback typically)
            interface_lines = [line for line in interface_info.split('\n') 
                             if re.match(r'^\w+\d+/', line.strip()) or re.match(r'^GigabitEthernet', line.strip()) or re.match(r'^FastEthernet', line.strip())]
            info["interface_count"] = len(interface_lines)
        
        shell.close()
        
    except Exception as e:
        print(f"[SSH] Error getting device info: {e}")
    
    return info

def _execute_cisco_command(shell, command: str, timeout: int = 10) -> str:
    """
    Execute a single Cisco IOS command and return output.
    """
    try:
        shell.send(f"{command}\n")
        time.sleep(2)  # Wait for command to execute
        
        output = ""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if shell.recv_ready():
                chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                output += chunk
                if '#' in chunk and len(chunk) < 100:  # Likely prompt return
                    break
            else:
                time.sleep(0.5)
        
        return output
        
    except Exception as e:
        print(f"[SSH] Error executing command '{command}': {e}")
        return ""

def _parse_version_output(version_output: str) -> Dict:
    """
    Parse 'show version' output to extract device information.
    """
    info = {}
    
    try:
        # Extract IOS version
        version_patterns = [
            r'IOS.*Version\s+([0-9]+\.[0-9]+\.[0-9]+)',
            r'Cisco IOS Software.*Version\s+([0-9]+\.[0-9]+\.[0-9]+)',
            r'Version\s+([0-9]+\.[0-9]+\([0-9]+\)[A-Za-z0-9]*)',
        ]
        
        for pattern in version_patterns:
            version_match = re.search(pattern, version_output, re.IGNORECASE)
            if version_match:
                info["ios_version"] = version_match.group(1)
                break
        
        # Extract model/platform
        model_patterns = [
            r'cisco\s+(\S+)\s+\(',
            r'Model\s+number\s*:\s*(\S+)',
            r'Hardware:\s*(\S+)',
            r'processor\s+\(revision\s+\S+\)\s+with\s+.*',
        ]
        
        for pattern in model_patterns:
            model_match = re.search(pattern, version_output, re.IGNORECASE)
            if model_match:
                info["model"] = model_match.group(1)
                break
        
        # Extract serial number
        serial_match = re.search(r'Processor board ID\s+(\S+)', version_output, re.IGNORECASE)
        if serial_match:
            info["serial"] = serial_match.group(1)
        
        # Extract uptime
        uptime_match = re.search(r'uptime is\s+(.*)', version_output, re.IGNORECASE)
        if uptime_match:
            info["uptime"] = uptime_match.group(1).strip()
            
    except Exception as e:
        print(f"[SSH] Error parsing version output: {e}")
    
    return info

def _determine_role_from_hostname(hostname: str) -> str:
    """
    Determine switch role based on hostname patterns.
    """
    hostname_lower = hostname.lower()
    
    for role, patterns in CISCO_HOSTNAME_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in hostname_lower:
                return role
    
    return "access"  # Default

def detect_bridge(ip: str, username: str = None, password: str = None) -> str:
    """
    Detect device type and basic information for display.
    Simplified version for compatibility.
    """
    username = username or DEFAULT_CISCO_USERNAME
    password = password or DEFAULT_CISCO_PASSWORD
    
    try:
        device_info = test_cisco_connectivity(ip, username, password)
        
        if device_info["authenticated"]:
            hostname = device_info["hostname"]
            role = device_info["role_hint"].title()
            
            if hostname != "unknown":
                return f"Cisco-{role} ({hostname})"
            else:
                return f"Cisco-{role} ({device_info['model']})"
        else:
            return "cisco-auth-failed"
            
    except Exception as e:
        return f"cisco-error: {str(e)[:20]}"

def fetch_running_config(ip: str, username: str = None, password: str = None, 
                        secret: str = None, device_type: str = "cisco") -> Tuple[bool, str, str]:
    """
    Fetch running configuration from Cisco device.
    """
    username = username or DEFAULT_CISCO_USERNAME
    password = password or DEFAULT_CISCO_PASSWORD
    secret = secret or DEFAULT_ENABLE_PASSWORD
    
    engine = f"ssh_{device_type}"
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=ip, 
            username=username, 
            password=password, 
            timeout=SSH_CONNECT_TIMEOUT,
            allow_agent=False,
            look_for_keys=False
        )
        
        # Use interactive shell for better control
        shell = ssh.invoke_shell()
        time.sleep(2)
        
        # Enter enable mode
        if secret:
            shell.send("enable\n")
            time.sleep(1)
            shell.send(f"{secret}\n")
            time.sleep(2)
        
        # Set terminal parameters
        shell.send("terminal length 0\n")
        shell.send("terminal width 0\n")
        time.sleep(1)
        
        # Clear buffer
        if shell.recv_ready():
            shell.recv(4096)
        
        # Execute show running-config
        shell.send("show running-config\n")
        time.sleep(5)  # Wait longer for full config
        
        # Collect output
        config_output = ""
        start_time = time.time()
        
        while time.time() - start_time < CONFIG_BACKUP_TIMEOUT:
            if shell.recv_ready():
                chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                config_output += chunk
                # Look for end of config
                if 'end\n' in chunk or config_output.count('#') > 2:
                    time.sleep(1)  # Get any remaining output
                    if shell.recv_ready():
                        config_output += shell.recv(4096).decode('utf-8', errors='ignore')
                    break
            else:
                time.sleep(0.5)
        
        shell.close()
        ssh.close()
        
        if not config_output.strip():
            return False, "No configuration output received", engine
        
        # Clean up the configuration
        config_lines = config_output.split('\n')
        cleaned_lines = []
        in_config = False
        
        for line in config_lines:
            line = line.strip()
            # Start collecting from 'version' or first '!' line
            if line.startswith('version ') or line.startswith('!') or in_config:
                in_config = True
                cleaned_lines.append(line)
                if line == 'end':
                    break
        
        config = '\n'.join(cleaned_lines)
        
        # Add metadata header
        header = f"""!
! Configuration backup from {ip}
! Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
! Device Type: {device_type}
! Engine: {engine}
!
"""
        
        config = header + config
        
        print(f"[BACKUP] Successfully retrieved config from {ip}: {len(config)} bytes")
        return True, config, engine
        
    except Exception as e:
        error_msg = f"Failed to fetch config from {ip}: {str(e)}"
        print(f"[BACKUP] Error: {error_msg}")
        return False, error_msg, engine