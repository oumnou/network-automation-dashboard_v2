# config.py - Enhanced Cisco DevNet Sandbox Configuration
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
    "core": ["core", "Core", "CORE"],
    "distribution": ["dist", "Dist", "DIST"],
    "access": ["end", "End", "END", "access", "Access", "ACCESS"]
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
LOG_MAX_SIZE = 10 * 1024 * 1024               # 10MB
LOG_BACKUP_COUNT = 5                           

# Dashboard refresh settings
AUTO_REFRESH_INTERVAL = 300                    # 5 minutes
TOPOLOGY_CACHE_TIMEOUT = 60                    # 1 minute

# Security settings
ENABLE_AUTHENTICATION = False                  # Disabled for sandbox
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

# Known Cisco device IPs and expected configuration
KNOWN_CISCO_DEVICES = {
    "10.10.20.3": {"hostname": "Core1", "role": "core", "expected": True},
    "10.10.20.4": {"hostname": "Dist1", "role": "distribution", "expected": True},
    "10.10.20.5": {"hostname": "Dist2", "role": "distribution", "expected": True},
    "10.10.20.10": {"hostname": "End1", "role": "access", "expected": True},
    "10.10.20.11": {"hostname": "End2", "role": "access", "expected": True},
    "10.10.20.12": {"hostname": "End3", "role": "access", "expected": True},
    "10.10.20.13": {"hostname": "End4", "role": "access", "expected": True}
}

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
    """Validate configuration settings and provide warnings."""
    warnings = []
    errors = []
    
    # Check if network range is valid
    try:
        import ipaddress
        ipaddress.ip_network(DEFAULT_SCAN_RANGE, strict=False)
    except ValueError:
        errors.append(f"Invalid DEFAULT_SCAN_RANGE: {DEFAULT_SCAN_RANGE}")
    except ImportError:
        errors.append("ipaddress module not available - network validation disabled")
    
    # Check for default credentials (security warning)
    if DEFAULT_CISCO_USERNAME == "developer" and DEFAULT_CISCO_PASSWORD == "C1sco12345":
        warnings.append("Using DevNet sandbox credentials - ensure they match your environment")
    
    # Validate known device IPs
    try:
        import ipaddress
        for ip in KNOWN_CISCO_DEVICES.keys():
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                errors.append(f"Invalid IP in KNOWN_CISCO_DEVICES: {ip}")
    except ImportError:
        pass  # Already warned about missing ipaddress
    
    # Check directory creation
    created_dirs, failed_dirs = create_directories()
    
    if failed_dirs:
        for failed_dir in failed_dirs:
            errors.append(f"Cannot create directory: {failed_dir}")
    
    # Check directory permissions
    for directory in created_dirs:
        if not os.access(directory, os.W_OK):
            warnings.append(f"Directory not writable: {directory}")
    
    # Validate timeout values
    if SSH_CONNECT_TIMEOUT <= 0:
        errors.append("SSH_CONNECT_TIMEOUT must be positive")
    
    if COMMAND_TIMEOUT <= 0:
        errors.append("COMMAND_TIMEOUT must be positive")
    
    # Check log file
    try:
        # Try to create/write to log file
        test_log = os.path.join(os.path.dirname(LOG_FILE), "test.log")
        with open(test_log, "w") as f:
            f.write("test")
        os.remove(test_log)
    except Exception as e:
        errors.append(f"Cannot write to log directory: {e}")
    
    return warnings, errors

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
    """Get a summary of current configuration."""
    return {
        "network_range": DEFAULT_SCAN_RANGE,
        "known_devices": len(KNOWN_CISCO_DEVICES),
        "cisco_mode": CISCO_MODE,
        "credentials": f"{DEFAULT_CISCO_USERNAME}/*****",
        "timeouts": {
            "ssh_connect": SSH_CONNECT_TIMEOUT,
            "command": COMMAND_TIMEOUT,
            "backup": CONFIG_BACKUP_TIMEOUT
        },
        "directories": {
            "base": BASE_DIR,
            "data": DATA_DIR,
            "backups": BACKUP_DIR,
            "log": LOG_FILE
        }
    }

# Initialize directories on import
try:
    created_dirs, failed_dirs = create_directories()
    
    if failed_dirs:
        print("⚠️  Warning: Some directories could not be created:")
        for failed_dir in failed_dirs:
            print(f"   - {failed_dir}")
    
    # Create empty log file if it doesn't exist
    if not os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "w", encoding="utf-8") as f:
                f.write("")
        except Exception as e:
            print(f"⚠️  Warning: Could not create log file {LOG_FILE}: {e}")
    
except Exception as e:
    print(f"❌ Error during configuration initialization: {e}")

# Print configuration summary when run directly
if __name__ == "__main__":
    print("=== Cisco Network Dashboard Configuration ===")
    print(f"🌐 Network Range: {DEFAULT_SCAN_RANGE}")
    print(f"🔐 Cisco Credentials: {DEFAULT_CISCO_USERNAME}/*****")
    print(f"🎯 Known Device IPs: {', '.join(get_known_device_ips())}")
    print(f"🔧 Cisco Mode: {'Enabled' if CISCO_MODE else 'Disabled'}")
    print(f"📁 Data Directory: {DATA_DIR}")
    print(f"💾 Backup Directory: {BACKUP_DIR}")
    print(f"📝 Log File: {LOG_FILE}")
    
    print("\n🔍 Configuration Validation:")
    warnings, errors = validate_config()
    
    if errors:
        print("❌ Errors found:")
        for error in errors:
            print(f"   • {error}")
    
    if warnings:
        print("⚠️  Warnings:")
        for warning in warnings:
            print(f"   • {warning}")
    
    if not errors and not warnings:
        print("✅ Configuration validated successfully")
    
    print(f"\n📊 Expected Topology:")
    role_counts = {}
    for device_info in KNOWN_CISCO_DEVICES.values():
        role = device_info.get("role", "unknown")
        role_counts[role] = role_counts.get(role, 0) + 1
    
    for role, count in role_counts.items():
        print(f"   • {role.title()}: {count} device(s)")
    
    print("\n🚀 Ready for Cisco Sandbox integration!")
    
    # Test basic functionality
    print("\n🧪 Testing basic functionality...")
    
    # Test IP validation
    try:
        import ipaddress
        test_ip = "10.10.20.3"
        ipaddress.ip_address(test_ip)
        print(f"✅ IP validation working: {test_ip}")
    except ImportError:
        print("⚠️  IP validation unavailable (missing ipaddress module)")
    except Exception as e:
        print(f"❌ IP validation error: {e}")
    
    # Test directory access
    try:
        test_file = os.path.join(DATA_DIR, "test.tmp")
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
        print(f"✅ Directory write access: {DATA_DIR}")
    except Exception as e:
        print(f"❌ Directory access error: {e}")
    
    # Test log file access
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"[{__name__}] Configuration test at startup\n")
        print(f"✅ Log file access: {LOG_FILE}")
    except Exception as e:
        print(f"❌ Log file access error: {e}")
    
    print("\nConfiguration check complete! 🎉")