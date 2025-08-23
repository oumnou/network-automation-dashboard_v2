# config.py - Enhanced Cisco Network Automation Configuration
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
# Update this to match your CML/lab environment
DEFAULT_SCAN_RANGE = "192.168.116.0/24"  # Common CML range

# Alternative common lab ranges:
# DEFAULT_SCAN_RANGE = "192.168.1.0/24"     # Standard private range
# DEFAULT_SCAN_RANGE = "10.0.0.0/24"        # CML default management
# DEFAULT_SCAN_RANGE = "172.16.1.0/24"      # Another common lab range
# DEFAULT_SCAN_RANGE = "198.18.1.0/24"      # DevNet Reservable Sandbox
# DEFAULT_SCAN_RANGE = "10.10.20.0/24"      # DevNet Always-On Sandbox

# =============================================================================
# CISCO DEVICE CONFIGURATION
# =============================================================================

# Primary Cisco device credentials (commonly used in labs)
DEFAULT_CISCO_USERNAME = "admin"
DEFAULT_CISCO_PASSWORD = "admin"
DEFAULT_ENABLE_PASSWORD = "admin"

# Alternative common Cisco lab credentials:
# For DevNet Sandboxes:
DEVNET_USERNAME = "developer"
DEVNET_PASSWORD = "C1sco12345"

# For some lab environments:
# CISCO_USERNAME = "cisco"
# CISCO_PASSWORD = "cisco"

# For production (should be changed):
# PROD_USERNAME = "netadmin"
# PROD_PASSWORD = "your_secure_password"

# Credential sets to try during device discovery (in order of preference)
CISCO_CREDENTIAL_SETS = [
    (DEFAULT_CISCO_USERNAME, DEFAULT_CISCO_PASSWORD, DEFAULT_ENABLE_PASSWORD),
    ("cisco", "cisco", "cisco"),
    (DEVNET_USERNAME, DEVNET_PASSWORD, DEVNET_PASSWORD),
    ("root", "cisco", None),  # Some IOL devices
    ("admin", "", "admin"),   # Some devices with blank passwords
]

# =============================================================================
# NMAP CONFIGURATION
# =============================================================================

# Nmap scanning parameters
NMAP_ENABLED = True                        # Enable Nmap-based scanning
NMAP_TIMEOUT = 30                          # Maximum scan time per batch (seconds)
NMAP_PARALLEL_PROCESSES = 5                # Number of parallel Nmap processes
NMAP_HOST_BATCH_SIZE = 10                  # Hosts per Nmap batch
NMAP_MAX_RETRIES = 1                       # Retry attempts for failed scans

# Cisco-specific port ranges for comprehensive scanning
CISCO_COMMON_PORTS = [22, 23, 80, 443, 161, 162, 830]  # Essential ports
CISCO_EXTENDED_PORTS = [
    21,     # FTP (some devices)
    22,     # SSH (primary management)
    23,     # Telnet (legacy management)
    25,     # SMTP (mail relay on some devices)
    53,     # DNS (DNS server functionality)
    69,     # TFTP (configuration transfer)
    80,     # HTTP (web management)
    123,    # NTP (time synchronization)
    161,    # SNMP (network management)
    162,    # SNMP Trap (notifications)
    179,    # BGP (routing protocol)
    443,    # HTTPS (secure web management)
    514,    # Syslog (logging)
    830,    # NETCONF (modern configuration protocol)
    1645,   # RADIUS Authentication (legacy)
    1646,   # RADIUS Accounting (legacy)
    1812,   # RADIUS Authentication
    1813,   # RADIUS Accounting
    2001,   # CML Console redirection
    5000,   # HTTP alternate (some virtual devices)
    8080,   # HTTP alternate
    8443    # HTTPS alternate
]

# Port scanning strategy
NMAP_QUICK_PORTS = "22,23,80,443,161"                    # For quick scans
NMAP_COMPREHENSIVE_PORTS = ",".join(map(str, CISCO_EXTENDED_PORTS))  # For detailed scans

# Nmap scan arguments for different scan types
NMAP_ARGS = {
    "quick": "-sS -T4 --max-retries 1 --host-timeout 10s",
    "comprehensive": "-sS -O -sV --version-intensity 7 -T4 --max-retries 2",
    "stealth": "-sS -T2 --scan-delay 1s --max-retries 1",
    "aggressive": "-sS -O -sV -sC -A -T4"
}

# =============================================================================
# DEVICE DETECTION AND CLASSIFICATION
# =============================================================================

# Cisco device identification patterns
CISCO_IOS_PATTERNS = [
    "Cisco IOS Software",
    "Cisco Internetwork Operating System",
    "IOS-XE Software",
    "Cisco IOS XE Software",
    "Cisco IOS-XR Software",
    "Cisco NX-OS Software",
    "Cisco Nexus Operating System"
]

# Cisco hardware model patterns for device classification
CISCO_MODEL_PATTERNS = {
    # Switches
    "catalyst": ["2960", "2970", "3560", "3750", "3850", "4500", "6500", "9200", "9300", "9400", "9500", "9600"],
    "nexus": ["3000", "5000", "7000", "9000"],
    
    # Routers  
    "isr": ["1900", "2900", "4000", "4300", "4400"],
    "asr": ["1000", "1001", "1002", "1006", "9000", "9001", "9006", "9010"],
    "csr": ["1000v"],
    
    # Wireless
    "wireless_controller": ["2504", "3504", "5520", "8540", "9800"],
    "access_point": ["1130", "1140", "1260", "2600", "2700", "3600", "3700"],
    
    # Virtual/Lab devices
    "virtual": ["IOSv", "IOSvL2", "IOL", "VIRL", "CML"]
}

# Device role detection patterns (based on hostname)
ROLE_PATTERNS = {
    "core": ["core", "c1", "c2", "backbone", "spine", "border"],
    "distribution": ["dist", "d1", "d2", "aggregation", "agg", "distrib"],
    "access": ["access", "a1", "a2", "edge", "sw", "switch", "acc"],
    "wan": ["wan", "branch", "remote", "edge", "border"],
    "dmz": ["dmz", "firewall", "fw", "security"],
    "management": ["mgmt", "management", "oob", "console"]
}

# Device priority scoring (higher = more important/likely to be network infrastructure)
DEVICE_PRIORITIES = {
    "cisco_confirmed": 100,         # SSH validated Cisco device
    "cisco_likely": 90,             # Multiple Cisco indicators
    "network_device": 70,           # Network management ports
    "linux_network": 50,            # Linux with network services  
    "server": 40,                   # Server-class device
    "workstation": 30,              # End-user device
    "unknown": 10                   # Unclassified device
}

# =============================================================================
# SCANNING OPTIMIZATION
# =============================================================================

# Performance tuning
SCAN_TIMEOUT = 5                           # Seconds per individual device scan
SCAN_THREADS = 15                          # Concurrent scanning threads
MAX_SCAN_DEVICES = 254                     # Maximum devices to scan (safety limit)
SOCKET_TIMEOUT = 2                         # Socket connection timeout
PING_TIMEOUT = 1                           # Ping timeout for host discovery

# Network discovery phases
ENABLE_HOST_DISCOVERY = True               # Phase 1: Quick host discovery
ENABLE_PORT_SCANNING = True                # Phase 2: Detailed port scanning  
ENABLE_SSH_VALIDATION = True               # Phase 3: SSH-based device validation
ENABLE_SNMP_DISCOVERY = False              # Phase 4: SNMP-based discovery (optional)

# =============================================================================
# SSH AND DEVICE CONNECTIVITY
# =============================================================================

# SSH connection parameters
SSH_CONNECT_TIMEOUT = 15                   # SSH connection timeout
SSH_AUTH_TIMEOUT = 10                      # SSH authentication timeout
SSH_COMMAND_TIMEOUT = 30                   # Individual command timeout
SSH_KEEPALIVE_INTERVAL = 60                # Keep SSH connections alive

# Console/Telnet settings
TELNET_TIMEOUT = 10                        # Telnet connection timeout
CONSOLE_BAUD_RATE = 9600                   # Serial console baud rate

# Device command timeouts
SHOW_VERSION_TIMEOUT = 15                  # "show version" command timeout
SHOW_CONFIG_TIMEOUT = 60                   # Configuration backup timeout
SHOW_INVENTORY_TIMEOUT = 30                # Hardware inventory timeout

# =============================================================================
# BACKUP AND CONFIGURATION MANAGEMENT
# =============================================================================

# Backup configuration
BACKUP_RETENTION_DAYS = 30                 # Days to keep backups
BACKUP_COMPRESSION = True                  # Compress old backups
AUTO_BACKUP_ENABLED = False                # Enable scheduled backups

# Configuration templates
CONFIG_TEMPLATE_DIR = os.path.join(BASE_DIR, "data", "templates")
CONFIG_SNIPPETS_DIR = os.path.join(BASE_DIR, "data", "snippets")

# =============================================================================
# MONITORING AND ALERTING
# =============================================================================

# Health monitoring
ENABLE_HEALTH_MONITORING = True            # Monitor device health
HEALTH_CHECK_INTERVAL = 300                # Health check interval (seconds)
CPU_THRESHOLD_WARNING = 80                 # CPU usage warning threshold (%)
MEMORY_THRESHOLD_WARNING = 85              # Memory usage warning threshold (%)
TEMP_THRESHOLD_WARNING = 70                # Temperature warning threshold (°C)

# SNMP monitoring settings
SNMP_COMMUNITY = "public"                  # Default SNMP community string
SNMP_VERSION = "2c"                        # SNMP version (1, 2c, 3)
SNMP_TIMEOUT = 5                           # SNMP query timeout
SNMP_RETRIES = 3                           # SNMP retry attempts

# =============================================================================
# LOGGING AND DEBUGGING
# =============================================================================

# Logging configuration
LOG_LEVEL = "INFO"                         # DEBUG, INFO, WARN, ERROR
LOG_MAX_SIZE = 10 * 1024 * 1024           # 10MB max log file size
LOG_BACKUP_COUNT = 5                       # Number of log files to keep
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

# Debug settings
DEBUG_NMAP_COMMANDS = False                # Log Nmap commands
DEBUG_SSH_SESSIONS = False                 # Log SSH session details
DEBUG_DEVICE_DETECTION = True              # Log device detection process
VERBOSE_SCAN_LOGGING = True                # Detailed scan progress logging

# =============================================================================
# SECURITY SETTINGS
# =============================================================================

# Authentication and authorization
ENABLE_AUTHENTICATION = False              # Set to True for production
SESSION_TIMEOUT = 3600                     # Session timeout (seconds)
MAX_LOGIN_ATTEMPTS = 3                     # Max failed login attempts
REQUIRE_HTTPS = False                      # Force HTTPS (production)

# Network security
ALLOWED_SCAN_RANGES = [                    # Restrict scanning to these ranges
    "192.168.0.0/16",                      # Private Class B
    "172.16.0.0/12",                       # Private Class B
    "10.0.0.0/8",                          # Private Class A
]

BLOCKED_SCAN_RANGES = [                    # Never scan these ranges
    "0.0.0.0/8",                          # Invalid/reserved
    "127.0.0.0/8",                        # Loopback
    "169.254.0.0/16",                     # Link-local
    "224.0.0.0/4",                        # Multicast
]

# Rate limiting
MAX_CONCURRENT_SCANS = 1                   # Maximum concurrent network scans
SCAN_RATE_LIMIT = 3600                     # Minimum seconds between scans
MAX_DEVICES_PER_SCAN = 500                 # Safety limit on scan size

# =============================================================================
# DASHBOARD AND UI SETTINGS
# =============================================================================

# Dashboard refresh settings  
AUTO_REFRESH_INTERVAL = 300                # Seconds (5 minutes)
TOPOLOGY_CACHE_TIMEOUT = 60                # Cache topology data (seconds)
MAX_LOG_ENTRIES = 1000                     # Maximum log entries to display

# Visualization settings
TOPOLOGY_PHYSICS = {
    "enabled": True,
    "hierarchical": True,
    "nodeSpacing": 150,
    "levelSeparation": 200,
    "gravitationalConstant": -8000,
    "springConstant": 0.001,
    "springLength": 200
}

# Device icons and colors
DEVICE_COLORS = {
    "core": "#1e40af",        # Blue
    "distribution": "#7c3aed",  # Purple  
    "access": "#059669",        # Green
    "wan": "#dc2626",           # Red
    "server": "#ea580c",        # Orange
    "unknown": "#6b7280"        # Gray
}

# =============================================================================
# ENVIRONMENT-SPECIFIC SETTINGS
# =============================================================================

# CML/VIRL specific settings
CML_MODE = True                            # Enable CML-specific optimizations
CML_HOST = "localhost"                     # CML server hostname
CML_PORT = 443                             # CML server port
CML_USERNAME = "admin"                     # CML username
CML_PASSWORD = "admin"                     # CML password

# DevNet sandbox settings
DEVNET_MODE = True                         # Enable DevNet optimizations
DEVNET_SANDBOX_DETECTION = True            # Auto-detect sandbox environments

# Production network settings
PRODUCTION_MODE = False                    # Enable production safeguards
CHANGE_CONTROL_REQUIRED = False            # Require change control approval
BACKUP_BEFORE_CHANGES = True               # Always backup before changes

# =============================================================================
# DIRECTORY CREATION AND VALIDATION
# =============================================================================

# Create required directories
directories_to_create = [
    os.path.dirname(LOG_FILE),
    BACKUP_DIR,
    os.path.dirname(SWITCH_DB),
    os.path.join(BASE_DIR, "data", "exports"),
    os.path.join(BASE_DIR, "data", "templates"),
    os.path.join(BASE_DIR, "data", "snapshots"),
    CONFIG_TEMPLATE_DIR,
    CONFIG_SNIPPETS_DIR
]

for directory in directories_to_create:
    os.makedirs(directory, exist_ok=True)

# =============================================================================
# CONFIGURATION VALIDATION
# =============================================================================

def validate_config():
    """
    Validate configuration settings and provide warnings for common issues.
    
    Returns:
        List of warning messages
    """
    warnings = []
    
    # Network range validation
    try:
        import ipaddress
        ipaddress.ip_network(DEFAULT_SCAN_RANGE, strict=False)
    except ValueError:
        warnings.append(f"Invalid DEFAULT_SCAN_RANGE: {DEFAULT_SCAN_RANGE}")
    
    # Security warnings
    if DEFAULT_CISCO_PASSWORD in ["admin", "cisco", ""]:
        warnings.append("Using default/weak Cisco credentials - update for production")
    
    if not ENABLE_AUTHENTICATION and not DEBUG:
        warnings.append("Authentication disabled - enable for production use")
    
    # Nmap availability
    if NMAP_ENABLED:
        import shutil
        if not shutil.which("nmap"):
            warnings.append("Nmap not found in PATH - install for enhanced scanning")
    
    # Directory permissions
    for directory in directories_to_create:
        if not os.access(directory, os.W_OK):
            warnings.append(f"Directory not writable: {directory}")
    
    # Performance warnings
    if SCAN_THREADS > 50:
        warnings.append("High thread count may impact performance")
    
    if MAX_SCAN_DEVICES > 1000 and not PRODUCTION_MODE:
        warnings.append("Large scan range - consider enabling PRODUCTION_MODE")
    
    return warnings

def get_nmap_version():
    """Get installed Nmap version information."""
    try:
        import subprocess
        result = subprocess.run(['nmap', '--version'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            version_line = result.stdout.split('\n')[0]
            return version_line.strip()
    except Exception:
        pass
    return "Nmap not available"

# =============================================================================
# STARTUP VALIDATION AND SUMMARY
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 Enhanced Cisco Network Automation Dashboard Configuration")
    print("=" * 60)
    print(f"📡 Default Network Range: {DEFAULT_SCAN_RANGE}")
    print(f"🔧 Cisco Credentials: {DEFAULT_CISCO_USERNAME}/*****")  
    print(f"🔍 Nmap Integration: {'Enabled' if NMAP_ENABLED else 'Disabled'}")
    print(f"🏗️  CML Mode: {'Enabled' if CML_MODE else 'Disabled'}")
    print(f"🧪 DevNet Mode: {'Enabled' if DEVNET_MODE else 'Disabled'}")
    print(f"🏢 Production Mode: {'Enabled' if PRODUCTION_MODE else 'Disabled'}")
    print(f"📁 Data Directory: {os.path.join(BASE_DIR, 'data')}")
    print(f"💾 Backup Directory: {BACKUP_DIR}")
    print(f"📊 Max Concurrent Threads: {SCAN_THREADS}")
    print(f"⏱️  Default Scan Timeout: {SCAN_TIMEOUT}s")
    
    # Nmap information
    nmap_version = get_nmap_version()
    print(f"🗺️  Nmap Version: {nmap_version}")
    
    # Validation
    warnings = validate_config()
    if warnings:
        print(f"\n⚠️  Configuration Warnings ({len(warnings)}):")
        for i, warning in enumerate(warnings, 1):
            print(f"   {i}. {warning}")
    else:
        print("\n✅ Configuration validated successfully")
    
    print(f"\n🌟 Ready for enhanced Cisco device discovery and management!")
    print("=" * 60)