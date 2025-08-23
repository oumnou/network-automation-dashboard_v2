# config.py - Cisco DevNet Sandbox Configuration
import os

# Flask configuration
DEBUG = True
HOST = "0.0.0.0"
PORT = 5000

# File paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "data", "activity.log")
BACKUP_DIR = os.path.join(BASE_DIR, "data", "backups")
SWITCH_DB = os.path.join(BASE_DIR, "data", "switches.json")

# Network scanning configuration for Cisco Sandbox
DEFAULT_SCAN_RANGE = "10.10.20.0/24"  # Your Cisco sandbox network

# Cisco sandbox credentials
DEFAULT_CISCO_USERNAME = "developer"           # DevNet Sandbox standard
DEFAULT_CISCO_PASSWORD = "C1sco12345"          # DevNet Sandbox standard
DEFAULT_ENABLE_PASSWORD = "C1sco12345"         # Same as login for sandbox

# Alternative credentials (if different in your sandbox)
# DEFAULT_CISCO_USERNAME = "cisco"
# DEFAULT_CISCO_PASSWORD = "cisco"
# DEFAULT_ENABLE_PASSWORD = "cisco"

# Scanning optimization for Cisco devices
SCAN_TIMEOUT = 5                               # Longer timeout for Cisco devices
SCAN_THREADS = 8                               # Conservative for sandbox
MAX_SCAN_DEVICES = 50                          # Limit for sandbox environment

# Cisco device role detection patterns (based on your topology)
CISCO_HOSTNAME_PATTERNS = {
    "core": ["core", "Core"],
    "distribution": ["dist", "Dist"],
    "access": ["end", "End", "access"]
}

# Cisco IOS command timeouts
SSH_CONNECT_TIMEOUT = 15                       # SSH connection timeout
COMMAND_TIMEOUT = 30                           # Individual command timeout
CONFIG_BACKUP_TIMEOUT = 60                     # Full backup timeout

# Port priorities for Cisco device detection
MANAGEMENT_PORTS = {
    22: "SSH",           # Primary - secure management
    23: "Telnet",        # Legacy Cisco management
    443: "HTTPS",        # Secure web management
    80: "HTTP",          # Web management
    161: "SNMP"          # Network monitoring
}

# Device type priorities (Cisco focused)
DEVICE_PRIORITIES = {
    "cisco_ios": 100,    # Highest priority for Cisco IOS devices
    "cisco": 95,         # General Cisco devices
    "linux": 30,         # Linux-based network devices
    "unknown": 10        # Unknown devices
}

# Backup configuration
BACKUP_RETENTION_DAYS = 30                     
BACKUP_COMPRESSION = True                      
AUTO_BACKUP_ENABLED = False                    

# Logging configuration
LOG_LEVEL = "DEBUG"                            # More verbose for testing
LOG_MAX_SIZE = 10 * 1024 * 1024               
LOG_BACKUP_COUNT = 5                           

# Dashboard refresh settings
AUTO_REFRESH_INTERVAL = 300                    
TOPOLOGY_CACHE_TIMEOUT = 60                    

# Security settings
ENABLE_AUTHENTICATION = False                  
SESSION_TIMEOUT = 3600                         
MAX_LOGIN_ATTEMPTS = 3                         

# Cisco specific settings
CISCO_MODE = True                              # Enable Cisco optimizations
CISCO_IOS_DETECTION = True                     # Auto-detect Cisco IOS devices

# Cisco device identification patterns
CISCO_IOS_PATTERNS = [
    "Cisco IOS Software",
    "Cisco Internetwork Operating System",
    "IOS-XE Software",
    "Cisco IOS XE Software",
    "IOS (tm)"
]

# Network topology layout settings
TOPOLOGY_PHYSICS = {
    "enabled": True,
    "hierarchical": True,
    "nodeSpacing": 150,
    "levelSeparation": 200,
    "gravitationalConstant": -8000
}

# Create required directories
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)
os.makedirs(os.path.dirname(SWITCH_DB), exist_ok=True)

# Configuration validation
def validate_config():
    """Validate configuration settings and provide warnings"""
    warnings = []
    
    # Check if network range is valid
    try:
        import ipaddress
        ipaddress.ip_network(DEFAULT_SCAN_RANGE, strict=False)
    except ValueError:
        warnings.append(f"Invalid DEFAULT_SCAN_RANGE: {DEFAULT_SCAN_RANGE}")
    
    # Check for default credentials (security warning)
    if DEFAULT_CISCO_USERNAME == "developer" and DEFAULT_CISCO_PASSWORD == "C1sco12345":
        warnings.append("Using DevNet sandbox credentials - ensure they match your environment")
    
    # Check directory permissions
    for directory in [BACKUP_DIR, os.path.dirname(LOG_FILE)]:
        if not os.access(directory, os.W_OK):
            warnings.append(f"Directory not writable: {directory}")
    
    return warnings

# Print configuration summary
if __name__ == "__main__":
    print("=== Cisco Network Dashboard Configuration ===")
    print(f"Network Range: {DEFAULT_SCAN_RANGE}")
    print(f"Cisco Credentials: {DEFAULT_CISCO_USERNAME}/*****")
    print(f"Target IPs: 10.10.20.3, 10.10.20.4, 10.10.20.5, 10.10.20.10-13")
    print(f"Cisco Mode: {'Enabled' if CISCO_MODE else 'Disabled'}")
    print(f"Data Directory: {os.path.join(BASE_DIR, 'data')}")
    print(f"Backup Directory: {BACKUP_DIR}")
    
    warnings = validate_config()
    if warnings:
        print("\n⚠️  Configuration Warnings:")
        for warning in warnings:
            print(f"   - {warning}")
    else:
        print("\n✅ Configuration validated successfully")
    
    print("\n🚀 Ready for Cisco Sandbox integration!")