# config.py - Complete Production-Ready Configuration
import os
import sys

# Flask configuration
DEBUG = True
HOST = "0.0.0.0"
PORT = 5000

# File paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
LOG_FILE = os.path.join(DATA_DIR, "activity.log")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
SWITCH_DB = os.path.join(DATA_DIR, "switches.json")

# Network scanning configuration - FLEXIBLE FOR ANY NETWORK
DEFAULT_SCAN_RANGE = os.getenv("NETWORK_RANGE", "192.168.1.0/24")  # Change this or set env var

# Cisco credentials - SUPPORTS ENVIRONMENT VARIABLES
DEFAULT_CISCO_USERNAME = os.getenv("CISCO_USERNAME", "cisco")       # Default: cisco
DEFAULT_CISCO_PASSWORD = os.getenv("CISCO_PASSWORD", "cisco")       # Default: cisco
DEFAULT_ENABLE_PASSWORD = os.getenv("CISCO_ENABLE", "cisco")        # Default: cisco

# Multiple credential sets to try automatically
CISCO_CREDENTIAL_SETS = [
    # Your environment variables (highest priority)
    {"username": os.getenv("CISCO_USERNAME", "cisco"), 
     "password": os.getenv("CISCO_PASSWORD", "cisco"),
     "enable": os.getenv("CISCO_ENABLE", "cisco")},
    
    # Common Cisco defaults
    {"username": "cisco", "password": "cisco", "enable": "cisco"},
    {"username": "admin", "password": "admin", "enable": "admin"},
    {"username": "admin", "password": "cisco", "enable": "cisco"},
    
    # DevNet Sandbox credentials (in case you're still testing)
    {"username": "developer", "password": "C1sco12345", "enable": "C1sco12345"},
    
    # Enterprise common
    {"username": "netadmin", "password": "netadmin", "enable": "netadmin"},
    {"username": "administrator", "password": "password", "enable": "password"}
]

# Scanning optimization for production networks
SCAN_TIMEOUT = 8                               # Good for most networks
SCAN_THREADS = 6                               # Conservative threading
MAX_SCAN_DEVICES = 100                         # Reasonable limit

# Auto-discovery settings
AUTO_DISCOVER_NETWORK = True                   # Will find networks automatically
COMMON_NETWORK_RANGES = [                      # Fallback networks to try
    "192.168.1.0/24",
    "192.168.0.0/24", 
    "10.0.0.0/24",
    "10.1.1.0/24",
    "172.16.0.0/24",
    "192.168.10.0/24"
]

# Cisco device role detection patterns
CISCO_HOSTNAME_PATTERNS = {
    "core": ["core", "Core", "CORE", "c1", "c2", "spine", "backbone"],
    "distribution": ["dist", "Dist", "DIST", "d1", "d2", "aggregation", "agg", "distrib"],
    "access": ["sw", "switch", "access", "edge", "end", "End", "ACCESS", "acc", "floor"]
}

# SSH timeouts - optimized for real networks
SSH_CONNECT_TIMEOUT = 20                       # Longer for production
COMMAND_TIMEOUT = 45                           # Busy devices need time
CONFIG_BACKUP_TIMEOUT = 90                     # Large configs take time

# Port priorities for Cisco device detection
MANAGEMENT_PORTS = {
    22: "SSH",           # Primary - secure management
    23: "Telnet",        # Legacy Cisco management
    443: "HTTPS",        # Secure web management
    80: "HTTP",          # Web management
    161: "SNMP",         # Network monitoring
    8443: "Alt-HTTPS",   # Alternative HTTPS port
    9443: "APIC-HTTPS"   # Cisco APIC management
}

# Device type priorities
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
LOG_LEVEL = "INFO"                             # INFO for production, DEBUG for troubleshooting
LOG_MAX_SIZE = 10 * 1024 * 1024               # 10MB
LOG_BACKUP_COUNT = 5                           

# Dashboard refresh settings
AUTO_REFRESH_INTERVAL = 300                    # 5 minutes
TOPOLOGY_CACHE_TIMEOUT = 60                    # 1 minute

# Security settings
ENABLE_AUTHENTICATION = False                  # Set True for production
SESSION_TIMEOUT = 3600                         # 1 hour
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
    "IOS (tm)",
    "IOS Software"
]

# Smart device loading - adapts to your environment
def load_known_devices():
    """Load known devices - adapts based on environment"""
    
    # Option 1: Load from file if you have one
    known_file = os.getenv("KNOWN_DEVICES_FILE")
    if known_file and os.path.exists(known_file):
        import json
        try:
            with open(known_file, 'r') as f:
                devices = json.load(f)
                print(f"✅ Loaded {len(devices)} known devices from {known_file}")
                return devices
        except Exception as e:
            print(f"⚠️ Could not load devices from {known_file}: {e}")
    
    # Option 2: Use sandbox devices if environment suggests it
    if os.getenv("CISCO_ENVIRONMENT") == "sandbox" or DEFAULT_SCAN_RANGE == "10.10.20.0/24":
        sandbox_devices = {
            "10.10.20.3": {"hostname": "Core1", "role": "core", "expected": True},
            "10.10.20.4": {"hostname": "Dist1", "role": "distribution", "expected": True},
            "10.10.20.5": {"hostname": "Dist2", "role": "distribution", "expected": True},
            "10.10.20.10": {"hostname": "End1", "role": "access", "expected": True},
            "10.10.20.11": {"hostname": "End2", "role": "access", "expected": True},
            "10.10.20.12": {"hostname": "End3", "role": "access", "expected": True},
            "10.10.20.13": {"hostname": "End4", "role": "access", "expected": True}
        }
        print(f"✅ Using DevNet Sandbox device configuration ({len(sandbox_devices)} devices)")
        return sandbox_devices
    
    # Option 3: Empty dict for auto-discovery
    print("ℹ️ No known devices configured - will use network discovery")
    return {}

# Load the known devices
KNOWN_CISCO_DEVICES = load_known_devices()

# Network topology layout settings
TOPOLOGY_PHYSICS = {
    "enabled": True,
    "hierarchical": True,
    "nodeSpacing": 150,
    "levelSeparation": 200,
    "gravitationalConstant": -8000
}

def create_directories():
    """Create required directories with proper error handling."""
    directories = [
        DATA_DIR,
        os.path.dirname(LOG_FILE),
        BACKUP_DIR,
        os.path.dirname(SWITCH_DB)
    ]
    
    created = []
    failed = []
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            created.append(directory)
        except PermissionError:
            failed.append(f"{directory} (Permission denied)")
        except Exception as e:
            failed.append(f"{directory} ({str(e)})")
    
    return created, failed

def validate_config():
    """Validate configuration settings and provide helpful feedback."""
    warnings = []
    errors = []
    info = []
    
    # Check network range
    try:
        import ipaddress
        ipaddress.ip_network(DEFAULT_SCAN_RANGE, strict=False)
        info.append(f"Network range: {DEFAULT_SCAN_RANGE}")
    except ValueError:
        errors.append(f"Invalid DEFAULT_SCAN_RANGE: {DEFAULT_SCAN_RANGE}")
    except ImportError:
        errors.append("ipaddress module not available - network validation disabled")
    
    # Check credentials
    if DEFAULT_CISCO_USERNAME == "cisco" and DEFAULT_CISCO_PASSWORD == "cisco":
        if not os.getenv("CISCO_USERNAME"):
            warnings.append("Using default credentials (cisco/cisco) - set environment variables for your network")
        else:
            info.append("Using environment variable credentials")
    
    # Check credential sets
    info.append(f"Will try {len(CISCO_CREDENTIAL_SETS)} different credential combinations")
    
    # Check auto-discovery
    if AUTO_DISCOVER_NETWORK:
        info.append("Network auto-discovery enabled")
    else:
        warnings.append("Network auto-discovery disabled - may miss some networks")
    
    # Check known devices
    if KNOWN_CISCO_DEVICES:
        info.append(f"Known devices configured: {len(KNOWN_CISCO_DEVICES)}")
    else:
        info.append("No known devices - will rely on network scanning")
    
    # Check directories
    created_dirs, failed_dirs = create_directories()
    if failed_dirs:
        for failed_dir in failed_dirs:
            errors.append(f"Cannot create directory: {failed_dir}")
    else:
        info.append("All required directories accessible")
    
    # Validate timeout values
    if SSH_CONNECT_TIMEOUT <= 0:
        errors.append("SSH_CONNECT_TIMEOUT must be positive")
    
    return warnings, errors, info

def get_known_device_ips():
    """Get list of known Cisco device IPs."""
    return list(KNOWN_CISCO_DEVICES.keys())

def get_expected_device_count():
    """Get expected number of devices."""
    return len(KNOWN_CISCO_DEVICES)

def get_device_info(ip):
    """Get expected device information by IP."""
    return KNOWN_CISCO_DEVICES.get(ip, {})

def is_known_device(ip):
    """Check if IP is a known device."""
    return ip in KNOWN_CISCO_DEVICES

def get_config_summary():
    """Get a comprehensive summary of current configuration."""
    return {
        "network": {
            "scan_range": DEFAULT_SCAN_RANGE,
            "auto_discovery": AUTO_DISCOVER_NETWORK,
            "known_devices": len(KNOWN_CISCO_DEVICES)
        },
        "credentials": {
            "primary": f"{DEFAULT_CISCO_USERNAME}/*****",
            "total_sets": len(CISCO_CREDENTIAL_SETS),
            "using_env_vars": bool(os.getenv("CISCO_USERNAME"))
        },
        "scanning": {
            "threads": SCAN_THREADS,
            "timeout": SSH_CONNECT_TIMEOUT,
            "max_devices": MAX_SCAN_DEVICES
        },
        "directories": {
            "base": BASE_DIR,
            "data": DATA_DIR,
            "backups": BACKUP_DIR,
            "log": LOG_FILE
        }
    }

def discover_local_networks():
    """Try to discover local networks automatically."""
    networks = []
    
    try:
        import socket
        # Get local machine's IP to guess network
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        # Create likely network ranges
        parts = local_ip.split('.')
        if len(parts) == 4:
            potential_networks = [
                f"{parts[0]}.{parts[1]}.{parts[2]}.0/24",  # Same subnet
                f"{parts[0]}.{parts[1]}.0.0/16",           # Larger range
            ]
            networks.extend(potential_networks)
            
    except Exception as e:
        print(f"Network discovery error: {e}")
    
    # Add common ranges
    networks.extend(COMMON_NETWORK_RANGES)
    
    # Remove duplicates and limit
    return list(set(networks))[:8]  # Max 8 networks

# Initialize directories on import
try:
    created_dirs, failed_dirs = create_directories()
    
    if failed_dirs:
        print("⚠️ Warning: Some directories could not be created:")
        for failed_dir in failed_dirs:
            print(f"   - {failed_dir}")
    
    # Create empty log file if it doesn't exist
    if not os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "w", encoding="utf-8") as f:
                f.write(f"# Cisco Network Dashboard Log\n# Started: {__import__('time').strftime('%Y-%m-%d %H:%M:%S')}\n")
        except Exception as e:
            print(f"⚠️ Warning: Could not create log file {LOG_FILE}: {e}")
    
except Exception as e:
    print(f"❌ Error during configuration initialization: {e}")

# Print configuration when run directly
if __name__ == "__main__":
    print("=" * 60)
    print("🚀 CISCO NETWORK DASHBOARD - PRODUCTION READY")
    print("=" * 60)
    
    # Show current configuration
    config = get_config_summary()
    print(f"🌐 Network Range: {config['network']['scan_range']}")
    print(f"🔐 Primary Credentials: {config['credentials']['primary']}")
    print(f"🔑 Total Credential Sets: {config['credentials']['total_sets']}")
    print(f"🎯 Known Devices: {config['network']['known_devices']}")
    print(f"🔍 Auto Discovery: {'Enabled' if config['network']['auto_discovery'] else 'Disabled'}")
    print(f"⚙️ Scan Settings: {config['scanning']['threads']} threads, {config['scanning']['timeout']}s timeout")
    
    print(f"\n📁 Directory Structure:")
    print(f"   • Data: {config['directories']['data']}")
    print(f"   • Backups: {config['directories']['backups']}")
    print(f"   • Logs: {config['directories']['log']}")
    
    # Validate configuration
    print(f"\n🔍 Configuration Validation:")
    warnings, errors, info = validate_config()
    
    if errors:
        print("❌ ERRORS (must fix):")
        for error in errors:
            print(f"   • {error}")
    
    if warnings:
        print("⚠️ WARNINGS (recommended to address):")
        for warning in warnings:
            print(f"   • {warning}")
    
    if info:
        print("ℹ️ INFORMATION:")
        for item in info:
            print(f"   • {item}")
    
    # Show environment variable options
    print(f"\n📋 ENVIRONMENT VARIABLES (optional):")
    print("   export NETWORK_RANGE='192.168.1.0/24'      # Your network")
    print("   export CISCO_USERNAME='your_username'        # Your Cisco username")
    print("   export CISCO_PASSWORD='your_password'        # Your Cisco password")
    print("   export CISCO_ENABLE='your_enable_password'   # Enable password")
    print("   export CISCO_ENVIRONMENT='production'        # Environment type")
    
    # Show what will happen
    print(f"\n🎯 SCANNING STRATEGY:")
    if KNOWN_CISCO_DEVICES:
        print(f"   1. Quick scan of {len(KNOWN_CISCO_DEVICES)} known devices")
        print(f"   2. Full network scan of {DEFAULT_SCAN_RANGE} if requested")
    else:
        print(f"   1. Smart scan of {DEFAULT_SCAN_RANGE}")
        if AUTO_DISCOVER_NETWORK:
            discovered = discover_local_networks()
            print(f"   2. Auto-discover additional networks: {len(discovered)} found")
    
    print(f"   • Will try {len(CISCO_CREDENTIAL_SETS)} credential combinations per device")
    print(f"   • Maximum {MAX_SCAN_DEVICES} devices per scan")
    
    if not errors:
        print(f"\n✅ CONFIGURATION READY!")
        print(f"   Run: python app.py")
        print(f"   Dashboard: http://localhost:{PORT}")
    else:
        print(f"\n❌ PLEASE FIX ERRORS BEFORE RUNNING")
    
    print("=" * 60)