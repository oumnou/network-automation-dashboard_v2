import paramiko

def fetch_running_config(ip: str, username: str, password: str, **kwargs) -> tuple:
    """
    SSH into an OVS 'device' (namespace) and fetch its config.
    Returns (success: bool, output: str, engine: str).
    """
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=10)

        # Collect OVS info
        commands = [
            "hostname",
            "ovs-vsctl show",
            f"ovs-ofctl dump-flows {ip_to_bridge(ip)}"
        ]

        output = ""
        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            out = stdout.read().decode()
            err = stderr.read().decode()
            output += f"\n## {cmd}\n{out or err}"

        ssh.close()
        return True, output, "ovs-ssh"

    except Exception as e:
        return False, str(e), "ovs-ssh"


def ip_to_bridge(ip: str) -> str:
    """
    Map IP addresses to OVS bridge names.
    Adjust this if you change your namespace IPs.
    """
    mapping = {
        "10.0.0.1": "core-sw-01",
        "10.0.0.2": "dist-sw-01",
        "10.0.0.3": "dist-sw-02",
        "10.0.0.11": "access-sw-01",
        "10.0.0.12": "access-sw-02",
        "10.0.0.13": "access-sw-03",
        "10.0.0.14": "access-sw-04",
    }
    return mapping.get(ip, "br-unknown")
