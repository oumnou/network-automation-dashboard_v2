# services/ssh_utils.py
from typing import Optional, Tuple
import paramiko
import time
import re

def detect_bridge(ip: str, username: str = "admin", password: str = "admin") -> str:
    """
    Connect via SSH and detect device type focusing on Cisco devices.
    Returns device information for Cisco switches or other network devices.
    """
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=5)
        
        # Priority 1: Check if it's a Cisco device
        stdin, stdout, stderr = ssh.exec_command("show version | include Software")
        version_output = stdout.read().decode().strip()
        
        if "IOS" in version_output or "Cisco" in version_output:
            # It's a Cisco device - get more details
            stdin, stdout, stderr = ssh.exec_command("show version | include uptime")
            uptime_output = stdout.read().decode()
            
            # Get hostname
            stdin, stdout, stderr = ssh.exec_command("show running-config | include hostname")
            hostname_output = stdout.read().decode()
            hostname = "unknown"
            if hostname_output:
                match = re.search(r'hostname\s+(\S+)', hostname_output)
                if match:
                    hostname = match.group(1)
            
            # Determine device role based on hostname or interface count
            stdin, stdout, stderr = ssh.exec_command("show ip interface brief | count")
            interface_output = stdout.read().decode()
            
            # Try to get interface count for role detection
            stdin, stdout, stderr = ssh.exec_command("show interfaces summary | include interfaces")
            summary_output = stdout.read().decode()
            
            ssh.close()
            
            # Intelligent role detection based on naming and interface patterns
            hostname_lower = hostname.lower()
            if "core" in hostname_lower or "c1" in hostname_lower or "c2" in hostname_lower:
                return f"Cisco-Core ({hostname})"
            elif "dist" in hostname_lower or "d1" in hostname_lower or "d2" in hostname_lower:
                return f"Cisco-Distribution ({hostname})"
            elif "access" in hostname_lower or "a1" in hostname_lower or "sw" in hostname_lower:
                return f"Cisco-Access ({hostname})"
            else:
                # Generic Cisco device
                if "Stack" in version_output:
                    return f"Cisco-Stack ({hostname})"
                elif "Switch" in version_output:
                    return f"Cisco-Switch ({hostname})"
                elif "Router" in version_output:
                    return f"Cisco-Router ({hostname})"
                else:
                    return f"Cisco-Device ({hostname})"
        
        # Priority 2: Check for other network devices (commented out OVS check)
        # # Check if it's an OVS switch (COMMENTED OUT - FOCUSING ON CISCO)
        # stdin, stdout, stderr = ssh.exec_command("which ovs-vsctl 2>/dev/null")
        # if stdout.read().decode().strip():
        #     # It's OVS - get bridge list (keeping for reference but not primary focus)
        #     stdin, stdout, stderr = ssh.exec_command("ovs-vsctl br-list 2>/dev/null")
        #     bridges = stdout.read().decode().splitlines()
        #     
        #     if bridges:
        #         bridges = [b.strip() for b in bridges if b.strip()]
        #         ssh.close()
        #         return f"OVS-Switch ({len(bridges)} bridges: {', '.join(bridges[:2])}{'...' if len(bridges) > 2 else ''})"
        #     else:
        #         ssh.close()
        #         return "ovs-no-bridges"
        
        # Priority 3: Check if it's a Linux device with network capabilities
        stdin, stdout, stderr = ssh.exec_command("ip link show 2>/dev/null | grep -E '^[0-9]+:' | head -3")
        interfaces = stdout.read().decode()
        
        # Check if it might be a Linux-based network device
        stdin, stdout, stderr = ssh.exec_command("uname -a")
        uname_output = stdout.read().decode()
        
        ssh.close()
        
        if interfaces:
            # Check for common network device indicators
            if "bridge" in interfaces.lower() or "bond" in interfaces.lower():
                return "Linux-NetworkDevice"
            else:
                # Extract first non-loopback interface
                lines = interfaces.strip().split('\n')
                for line in lines:
                    if 'lo:' not in line and ':' in line:
                        iface = line.split(':')[1].strip().split('@')[0]
                        return f"Linux-{iface}"
                return "Linux-Device"
        
        return "SSH-Unknown"
        
    except paramiko.AuthenticationException:
        return "auth-failed"
    except paramiko.SSHException:
        return "ssh-failed"
    except Exception as e:
        return f"error-{str(e)[:20]}"

def fetch_running_config(ip: str, username: str, password: str, 
                        secret: Optional[str] = None, 
                        device_type: str = "cisco") -> Tuple[bool, str, str]:
    """
    Connect via SSH and fetch the device running config.
    Prioritizes Cisco devices with proper privilege escalation.
    Returns (success, config_output, engine_used).
    """
    engine = f"ssh_{device_type}"
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=15)
        
        if device_type == "cisco":
            # Priority: Cisco device configuration backup
            config_parts = []
            
            # Start an interactive shell for better control
            shell = ssh.invoke_shell()
            time.sleep(1)
            
            # Send enable command if enable password provided
            if secret:
                shell.send("enable\n")
                time.sleep(1)
                shell.send(f"{secret}\n")
                time.sleep(1)
            
            # Set terminal length to 0 to avoid pagination
            shell.send("terminal length 0\n")
            time.sleep(1)
            
            # Clear any output
            shell.recv(1000)
            
            # Execute show running-config
            shell.send("show running-config\n")
            time.sleep(3)  # Wait for command to complete
            
            # Collect output
            config_output = ""
            while shell.recv_ready():
                config_output += shell.recv(4096).decode('utf-8', errors='ignore')
                time.sleep(0.5)
            
            # Clean up the output (remove command echoes and prompts)
            lines = config_output.split('\n')
            cleaned_lines = []
            in_config = False
            
            for line in lines:
                line = line.strip()
                if line.startswith('!') or line.startswith('version') or in_config:
                    in_config = True
                    cleaned_lines.append(line)
                    if line.startswith('end') and len(line.strip()) == 3:
                        break
            
            config = '\n'.join(cleaned_lines)
            
            # If interactive shell didn't work well, try direct commands
            if len(config.strip()) < 50:
                commands = [
                    "show version",
                    "show running-config | begin version",
                    "show ip interface brief",
                    "show cdp neighbors"
                ]
                
                config_parts = []
                for cmd in commands:
                    try:
                        stdin, stdout, stderr = ssh.exec_command(cmd)
                        output = stdout.read().decode('utf-8', errors='ignore')
                        if output.strip() and len(output) > 10:
                            config_parts.append(f"! === {cmd.upper()} ===\n{output}\n")
                    except Exception as e:
                        config_parts.append(f"! ERROR executing {cmd}: {str(e)}\n")
                
                config = '\n'.join(config_parts) if config_parts else "! Unable to retrieve Cisco configuration"
            
            shell.close()
        
        # elif device_type == "ovs":
        #     # COMMENTED OUT - OVS support (keeping for reference)
        #     # Get comprehensive OVS configuration
        #     commands = [
        #         "ovs-vsctl show",
        #         "ovs-vsctl br-list", 
        #         "ovs-dpctl show",
        #         "ovs-ofctl dump-flows br0"  # Assuming br0 is main bridge
        #     ]
        #     
        #     config_parts = []
        #     for cmd in commands:
        #         stdin, stdout, stderr = ssh.exec_command(cmd)
        #         output = stdout.read().decode()
        #         error = stderr.read().decode()
        #         
        #         if output.strip():
        #             config_parts.append(f"! === {cmd.upper()} ===\n{output}\n")
        #         elif error.strip():
        #             config_parts.append(f"! === {cmd.upper()} (ERROR) ===\n{error}\n")
        #     
        #     config = "\n".join(config_parts) if config_parts else f"! No OVS configuration found on {ip}"
        
        elif device_type == "linux":
            # Linux network device configuration
            commands = [
                "ip addr show",
                "ip route show", 
                "ip link show",
                "cat /proc/net/dev",
                "brctl show",  # Bridge information
                "ethtool -S eth0"  # Interface statistics (if available)
            ]
            config_parts = []
            for cmd in commands:
                try:
                    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=10)
                    output = stdout.read().decode('utf-8', errors='ignore')
                    if output.strip():
                        config_parts.append(f"! === {cmd.upper()} ===\n{output}\n")
                except Exception:
                    # Skip commands that fail
                    pass
            
            config = "\n".join(config_parts) if config_parts else f"! No configuration retrieved from Linux device {ip}"
        
        else:
            # Generic device - try to get basic system information
            commands = ["show version", "uname -a", "ifconfig -a", "ip addr show"]
            config_parts = []
            
            for cmd in commands:
                try:
                    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=5)
                    output = stdout.read().decode('utf-8', errors='ignore')
                    if output.strip() and len(output) > 10:
                        config_parts.append(f"! === {cmd.upper()} ===\n{output}\n")
                        break  # If one command works, likely sufficient
                except Exception:
                    continue
            
            config = "\n".join(config_parts) if config_parts else f"! No configuration retrieved from {ip}"
        
        ssh.close()
        
        if not config.strip():
            config = f"! No configuration retrieved from {ip}\n! Device may not support requested commands or insufficient privileges"
        
        # Add metadata header
        header = f"""!
! Configuration backup from {ip}
! Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
! Device Type: {device_type}
! Engine: {engine}
!
"""
        
        config = header + config
        
        return True, config, engine
        
    except paramiko.AuthenticationException:
        error_msg = f"Authentication failed for {ip}\n"
        error_msg += "- Check username and password\n"
        error_msg += "- Verify SSH access is enabled on device\n"
        if device_type == "cisco":
            error_msg += "- For Cisco devices, ensure 'login local' is configured on VTY lines"
        return False, error_msg, engine
        
    except paramiko.SSHException as e:
        error_msg = f"SSH connection failed for {ip}: {str(e)}\n"
        error_msg += "- Verify device is reachable (ping test)\n"
        error_msg += "- Check if SSH service is running on device\n"
        error_msg += "- Verify SSH version compatibility"
        return False, error_msg, engine
        
    except Exception as e:
        return False, f"Failed to fetch config from {ip}: {str(e)}", engine

def test_cisco_connectivity(ip: str, username: str, password: str, enable_password: Optional[str] = None) -> dict:
    """
    Test basic connectivity to Cisco device and return device information.
    Returns detailed information about the device for better role detection.
    """
    result = {
        "reachable": False,
        "authenticated": False,
        "device_type": "unknown",
        "hostname": "unknown",
        "model": "unknown",
        "ios_version": "unknown",
        "role_hint": "access",  # Default assumption
        "error": None
    }
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=10)
        
        result["reachable"] = True
        result["authenticated"] = True
        
        # Get basic device information
        commands = {
            "version": "show version | include Software|Model|uptime",
            "hostname": "show running-config | include hostname",
            "interfaces": "show ip interface brief | count"
        }
        
        for cmd_type, command in commands.items():
            try:
                stdin, stdout, stderr = ssh.exec_command(command, timeout=5)
                output = stdout.read().decode('utf-8', errors='ignore').strip()
                
                if cmd_type == "version" and output:
                    if "IOS" in output:
                        result["device_type"] = "cisco_ios"
                    # Extract model information
                    model_match = re.search(r'Model\s+number\s*:\s*(\S+)', output)
                    if model_match:
                        result["model"] = model_match.group(1)
                    # Extract IOS version
                    version_match = re.search(r'Version\s+([0-9]+\.[0-9]+\.[0-9]+)', output)
                    if version_match:
                        result["ios_version"] = version_match.group(1)
                
                elif cmd_type == "hostname" and output:
                    hostname_match = re.search(r'hostname\s+(\S+)', output)
                    if hostname_match:
                        result["hostname"] = hostname_match.group(1)
                        # Determine role based on hostname
                        hostname_lower = result["hostname"].lower()
                        if "core" in hostname_lower or "c1" in hostname_lower or "c2" in hostname_lower:
                            result["role_hint"] = "core"
                        elif "dist" in hostname_lower or "d1" in hostname_lower or "d2" in hostname_lower:
                            result["role_hint"] = "distribution"
                        else:
                            result["role_hint"] = "access"
                            
            except Exception as cmd_error:
                result["error"] = f"Command '{command}' failed: {str(cmd_error)}"
                continue
        
        ssh.close()
        
    except paramiko.AuthenticationException:
        result["error"] = "Authentication failed - check credentials"
    except paramiko.SSHException as e:
        result["error"] = f"SSH connection failed: {str(e)}"
    except Exception as e:
        result["error"] = f"Connection test failed: {str(e)}"
    
    return result