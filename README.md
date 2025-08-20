# Cisco Network Automation Dashboard

A Flask-based Cisco network management dashboard for DevNet/Cisco Modeling Labs environments.
Generated on 2025-08-18T15:45:05.266880Z

## Overview

This dashboard is designed to work with **real Cisco switches** in DevNet environments, including:
- **Core Switches**: High-performance backbone switches (Catalyst 9000 series)
- **Distribution Switches**: Aggregation layer switches (Catalyst 3850/9300 series)
- **Access Switches**: End-user access switches (Catalyst 2960/9200 series)

The dashboard provides automated discovery, topology visualization, and configuration management for Cisco network infrastructures.

## Cisco DevNet Integration

### Supported Platforms
- **Cisco IOS/IOS-XE**: Catalyst switches, ISR routers
- **Cisco Modeling Labs**: Virtual network topologies
- **DevNet Sandbox**: Remote lab environments
- **Physical Cisco Hardware**: Production networks

### Required Cisco Features
- SSH access enabled (`ip ssh version 2`)
- User accounts with appropriate privilege levels
- SNMP (optional, for enhanced monitoring)
- CDP/LLDP for neighbor discovery

## Quick Start (Windows PowerShell)

### 1. Environment Setup
```powershell
# Clone and navigate to project
cd "/mnt/data/new-network-automation-dashboard"

# Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Set Flask application
$env:FLASK_APP="app.py"
```

### 2. Cisco Device Configuration

Before using the dashboard, ensure your Cisco devices have SSH enabled:

```cisco
! Enable SSH on Cisco devices
configure terminal
hostname YourSwitchName
ip domain-name yourdomain.com
crypto key generate rsa modulus 2048
username admin privilege 15 secret YourPassword
line vty 0 15
 transport input ssh
 login local
ip ssh version 2
exit
```

### 3. Network Configuration

Update the network range in `config.py` to match your DevNet/lab environment:
```python
DEFAULT_SCAN_RANGE = "192.168.1.0/24"  # Update this to your network
```

Common DevNet ranges:
- Modeling Labs: `192.168.1.0/24`, `10.0.0.0/24`
- DevNet Sandbox: Provided in lab documentation
- Always-On Sandbox: Check current IP assignments

### 4. Start the Application
```powershell
python app.py
# Open http://127.0.0.1:5000
```

## Dashboard Features

### 🌐 Network Discovery
- **Automated Scanning**: Discovers Cisco devices via SSH (port 22)
- **Device Fingerprinting**: Identifies Cisco IOS/IOS-XE devices
- **Topology Detection**: Automatically determines switch roles based on configuration

### 📊 Visualization
- **Hierarchical Topology**: Core → Distribution → Access layout
- **Interactive Network Map**: Click switches for detailed information
- **Real-time Status**: Live connection and health monitoring

### 💾 Configuration Management
- **Running Config Backup**: Automated `show running-config` exports
- **Version Control**: Timestamped configuration snapshots
- **Bulk Operations**: Mass configuration deployment

### 📈 Monitoring
- **Health Metrics**: CPU, memory, temperature monitoring
- **Interface Status**: Port utilization and error tracking
- **Activity Logging**: Comprehensive audit trail

## API Endpoints

### Network Scanning
```http
POST /api/scan/
Content-Type: application/json
{
  "network": "192.168.1.0/24",
  "ports": [22, 23, 80, 443]
}
```

### Switch Management
```http
# List all switches
GET /api/switch/

# Add/Update switch
POST /api/switch/
{
  "hostname": "core-sw-01",
  "ip": "192.168.1.10",
  "role": "core",
  "device_type": "cisco"
}

# Get switch details
GET /api/switch/192.168.1.10

# Delete switch
DELETE /api/switch/192.168.1.10
```

### Configuration Backup
```http
POST /api/backup/run
{
  "ip": "192.168.1.10",
  "username": "admin",
  "password": "password",
  "enable_password": "enable_secret",
  "device_type": "cisco"
}
```

### Bulk Operations
```http
# Bulk import switches
POST /api/switch/bulk
{
  "switches": [
    {"hostname": "core-01", "ip": "192.168.1.10", "role": "core"},
    {"hostname": "dist-01", "ip": "192.168.1.20", "role": "distribution"},
    {"hostname": "access-01", "ip": "192.168.1.30", "role": "access"}
  ]
}

# Export topology
GET /api/switch/export
```

## DevNet Lab Examples

### Cisco Modeling Labs Topology
```yaml
# Example CML topology structure
topology:
  core_switches:
    - hostname: "CORE-SW-01"
      ip: "192.168.1.10"
      model: "Cat9000v"
      
  distribution_switches:
    - hostname: "DIST-SW-01" 
      ip: "192.168.1.20"
      model: "Cat3850"
      
  access_switches:
    - hostname: "ACCESS-SW-01"
      ip: "192.168.1.30" 
      model: "Cat2960"
```

### DevNet Sandbox Access
```python
# Example sandbox credentials
DEVNET_SANDBOX = {
    "host": "sandbox-iosxe-latest-1.cisco.com",
    "username": "developer", 
    "password": "C1sco12345",
    "port": 22
}
```

## Directory Structure

```
new-network-automation-dashboard/
├── data/
│   ├── switches.json          # Switch inventory database
│   ├── backups/              # Configuration backups
│   │   └── <ip>_<timestamp>/ # Individual backup folders
│   └── activity.log          # System activity log
├── routes/
│   ├── scan_routes.py        # Network discovery endpoints  
│   ├── switch_routes.py      # Switch management endpoints
│   └── backup_routes.py      # Configuration backup endpoints
├── services/
│   ├── net_scan.py          # Cisco device discovery
│   ├── ssh_utils.py         # SSH connection utilities
│   └── action_logger.py     # Activity logging
├── static/
│   ├── script.js            # Frontend JavaScript
│   └── styles.css           # Dashboard styling
├── templates/
│   └── index.html           # Main dashboard HTML
├── app.py                   # Flask application
├── config.py               # Configuration settings
└── requirements.txt        # Python dependencies
```

## Cisco Authentication

### Standard Authentication
```python
# SSH credentials for Cisco devices
credentials = {
    "username": "admin",
    "password": "password",
    "enable_password": "enable_secret"  # For privileged mode
}
```

### TACACS+ Integration (Advanced)
```python
# For enterprise environments
tacacs_config = {
    "tacacs_server": "192.168.1.100",
    "tacacs_key": "shared_secret",
    "fallback_local": True
}
```

## Troubleshooting

### Common Issues

**SSH Connection Failed**
```bash
# Check SSH service on Cisco device
show ip ssh
show line vty 0 15

# Verify connectivity
telnet <device_ip> 22
ssh -v admin@<device_ip>
```

**Authentication Errors**
```cisco
! Enable SSH and create user
username admin privilege 15 secret password
line vty 0 15
 login local
 transport input ssh
```

**Discovery Issues**
```python
# Check network connectivity
ping <device_ip>
nmap -p 22,23,80,443 <network_range>
```

**Configuration Backup Failures**
```cisco
! Ensure sufficient privilege level
show privilege
enable
show running-config
```

### DevNet Resources
- **DevNet Learning Labs**: https://developer.cisco.com/learning/
- **Cisco Modeling Labs**: https://developer.cisco.com/docs/modeling-labs/
- **Always-On Sandboxes**: https://devnetsandbox.cisco.com/
- **API Documentation**: https://developer.cisco.com/docs/

### Performance Optimization

**Large Network Scanning**
```python
# Optimize scan parameters in config.py
SCAN_TIMEOUT = 2  # Seconds per device
SCAN_THREADS = 10  # Concurrent scans
MAX_DEVICES = 254  # Scan limit
```

**Backup Scheduling**
```python
# Schedule automated backups
BACKUP_SCHEDULE = {
    "daily": "02:00",
    "retention_days": 30,
    "compression": True
}
```

## Security Considerations

### Network Security
- Use dedicated management VLANs
- Implement SSH key-based authentication
- Enable logging and monitoring
- Regular credential rotation

### Application Security  
- Configure HTTPS in production
- Implement user authentication
- Secure API endpoints
- Regular security updates

## Contributing

When working with Cisco devices:
1. Test in DevNet sandbox first
2. Follow Cisco configuration best practices
3. Document device-specific behaviors
4. Include proper error handling
5. Update API documentation

## License

This project is designed for educational and development purposes with Cisco DevNet resources.

---

**Ready for Cisco DevNet Integration!** 🚀

The dashboard now prioritizes Cisco device discovery and management while maintaining compatibility with mixed environments.