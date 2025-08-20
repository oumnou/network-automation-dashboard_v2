# config.py - Cisco DevNet Focused Configuration
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

# Network scanning configuration
# Update this to match your DevNet/Cisco Modeling Labs environment
DEFAULT_SCAN_RANGE = "192.168.1.0/24"  # Common DevNet range

# Common DevNet lab ranges (uncomment the one that matches your environment):
# DEFAULT_SCAN_RANGE = "10.0.0.0/24"        # CML default management network
# DEFAULT_SCAN_RANGE = "192.168.116.0/24"   # Your original range
# DEFAULT_SCAN_RANGE = "10.10.20.0/24"      # DevNet Always-On Sandbox
# DEFAULT_SCAN_RANGE = "198.18.1.0/24"      # DevNet Reservable Sandbox

# Cisco device defaults
DEFAULT_DEVICE_TYPE = "cisco"              # Prioritize Cisco devices
DEFAULT_CISCO_USERNAME = "admin"           # Common Cisco lab username
DEFAULT_CISCO_PASSWORD = "admin"           # Common Cisco lab password
DEFAULT_ENABLE_PASSWORD = "admin"          # Common enable password

# Alternative DevNet credentials (uncomment as needed):
# DEFAULT_CISCO_USERNAME = "developer"      # DevNet Sandbox standard
# DEFAULT_CISCO_PASSWORD = "C1sco12345"     # DevNet Sandbox standard
# DEFAULT_CISCO_USERNAME = "cisco"          # Some lab environments
# DEFAULT_CISCO_PASSWORD = "cisco"          # Some lab environments

# Scanning optimization
SCAN_TIMEOUT = 2                           # Seconds per device scan
SCAN_THREADS = 15                          # Concurrent scanning threads
MAX_SCAN_DEVICES = 254                     # Maximum devices to scan

# Device role detection patterns
ROLE_PATTERNS = {
    "core": ["core", "c1", "c2", "backbone", "spine"],
    "distribution": ["dist", "d1", "d2", "aggregation", "agg"],
    "access": ["access", "a1", "a2", "edge", "sw", "switch"]
}

# Cisco IOS command timeouts
SSH_CONNECT_TIMEOUT = 15                   # SSH connection timeout
COMMAND_TIMEOUT = 30                       # Individual command timeout
CONFIG_BACKUP_TIMEOUT = 60                 # Full backup timeout

# Port priorities for device detection
MANAGEMENT_PORTS = {
    22: "SSH",           # Primary - secure management
    23: "Telnet",        # Legacy Cisco management
    80: "HTTP",          # Web management
    443: "HTTPS",        # Secure web management
    161: "SNMP"          # Network monitoring
}

# Device type priorities (higher = more preferred)
DEVICE_PRIORITIES = {
    "cisco": 100,        # Highest priority for Cisco devices
    "linux": 40,         # Linux-based network devices
    # "ovs": 20,         # COMMENTED OUT - OVS deprioritized
    "unknown": 10        # Unknown devices
}

# Backup configuration
BACKUP_RETENTION_DAYS = 30                 # Days to keep backups
BACKUP_COMPRESSION = True                  # Compress old backups
AUTO_BACKUP_ENABLED = False                # Enable scheduled backups

# Logging configuration
LOG_LEVEL = "INFO"                         # DEBUG, INFO, WARN, ERROR
LOG_MAX_SIZE = 10 * 1024 * 1024           # 10MB max log file size
LOG_BACKUP_COUNT = 5                       # Number of log files to keep

# Dashboard refresh settings
AUTO_REFRESH_INTERVAL = 300                # Seconds (5 minutes)
TOPOLOGY_CACHE_TIMEOUT = 60                # Cache topology data (seconds)

# Security settings
ENABLE_AUTHENTICATION = False              # Set to True for production
SESSION_TIMEOUT = 3600                     # Session timeout (seconds)
MAX_LOGIN_ATTEMPTS = 3                     # Max failed login attempts

# DevNet specific settings
DEVNET_MODE = True                         # Enable DevNet optimizations
DEVNET_SANDBOX_DETECTION = True            # Auto-detect sandbox environments

# Cisco device identification patterns
CISCO_IOS_PATTERNS = [
    "Cisco IOS Software",
    "Cisco Internetwork Operating System",
    "IOS-XE Software",
    "Cisco IOS XE Software"
]

CISCO_MODEL_PATTERNS = {
    "catalyst": ["2960", "3560", "3750", "3850", "9200", "9300", "9400", "9500"],
    "isr": ["1900", "2900", "4000"],
    "asr": ["1000", "9000"],
    "nexus": ["3000", "5000", "7000", "9000"]
}

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

# Ensure data directory structure
data_dirs = [
    os.path.join(BASE_DIR, "data"),
    os.path.join(BASE_DIR, "data", "backups"),
    os.path.join(BASE_DIR, "data", "templates"),  # For config templates
    os.path.join(BASE_DIR, "data", "exports")     # For export files
]

for directory in data_dirs:
    os.makedirs(directory, exist_ok=True)

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
    if DEFAULT_CISCO_USERNAME == "admin" and DEFAULT_CISCO_PASSWORD == "admin":
        warnings.append("Using default credentials - update for production use")
    
    # Check directory permissions
    for directory in [BACKUP_DIR, os.path.dirname(LOG_FILE)]:
        if not os.access(directory, os.W_OK):
            warnings.append(f"Directory not writable: {directory}")
    
    return warnings

# Print configuration summary
if __name__ == "__main__":
    print("=== Cisco Network Dashboard Configuration ===")
    print(f"Network Range: {DEFAULT_SCAN_RANGE}")
    print(f"Default Device Type: {DEFAULT_DEVICE_TYPE}")
    print(f"Cisco Credentials: {DEFAULT_CISCO_USERNAME}/*****")
    print(f"DevNet Mode: {'Enabled' if DEVNET_MODE else 'Disabled'}")
    print(f"Data Directory: {os.path.join(BASE_DIR, 'data')}")
    print(f"Backup Directory: {BACKUP_DIR}")
    
    warnings = validate_config()
    if warnings:
        print("\n⚠️  Configuration Warnings:")
        for warning in warnings:
            print(f"   - {warning}")
    else:
        print("\n✅ Configuration validated successfully")
    
    print("\n🚀 Ready for Cisco DevNet integration!")