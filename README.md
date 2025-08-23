# Enhanced Cisco Network Scanner - Installation & Usage Guide

## 🚀 Quick Start

### 1. Install Dependencies

```bash
# Install Python dependencies
pip install nmap-python paramiko flask flask-cors ipaddress pyyaml

# Install Nmap system package (required for advanced scanning)
# Ubuntu/Debian:
sudo apt update && sudo apt install nmap

# CentOS/RHEL:
sudo yum install nmap

# macOS:
brew install nmap

# Windows: Download from https://nmap.org/download.html
```

### 2. Update Your Files

Replace your existing files with the enhanced versions:

1. **Replace `services/net_scan.py`** with the enhanced scanner
2. **Replace `routes/scan_routes.py`** with the updated routes
3. **Replace `config.py`** with the enhanced configuration
4. Keep all other files as they are (they'll work with the new scanner)

### 3. Configure for Your Environment

Edit `config.py` and update these key settings:

```python
# Your CML network range
DEFAULT_SCAN_RANGE = "192.168.116.0/24"  # Change to your lab range

# Your device credentials
DEFAULT_CISCO_USERNAME = "admin"          # Change to your username
DEFAULT_CISCO_PASSWORD = "admin"          # Change to your password
DEFAULT_ENABLE_PASSWORD = "admin"         # Change to your enable password

# CML mode (keep as True for lab environment)
CML_MODE = True
```

## 🔍 Usage Examples

### Basic Network Scanning

1. **Web Interface**: Use your existing dashboard - it will automatically use the enhanced scanner
2. **API Calls**:

```bash
# Basic scan
curl -X POST http://localhost:5000/api/scan/ \
  -H "Content-Type: application/json" \
  -d '{"network": "192.168.116.0/24"}'

# Quick scan (faster)
curl -X POST http://localhost:5000/api/scan/ \
  -H "Content-Type: application/json" \
  -d '{"network": "192.168.116.0/24", "quick_scan": true}'

# Scan single device
curl -X POST http://localhost:5000/api/scan/single \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.116.1", "username": "admin", "password": "admin"}'
```

### Command Line Testing

```bash
# Test the scanner directly
cd your-project-directory
python services/net_scan.py 192.168.116.0/24

# Quick scan
python services/net_scan.py --quick 192.168.116.0/24

# Single device scan
python services/net_scan.py --single 192.168.116.1

# Export results
python services/net_scan.py 192.168.116.0/24 --export json
```

## 🎯 What's New and Enhanced

### Advanced Cisco Detection

The enhanced scanner now:

1. **Uses Nmap for comprehensive port scanning** - detects more devices and services
2. **Identifies Cisco devices more accurately** - recognizes IOSv, IOSvL2, IOL, and physical Cisco gear
3. **Validates devices via SSH** - confirms device type and gathers detailed information
4. **Tries multiple credential sets** - tests common Cisco lab credentials automatically
5. **Provides detailed device classification** - distinguishes between core, distribution, and access devices

### New API Endpoints

Your dashboard now has these additional endpoints:

- `POST /api/scan/single` - Detailed scan of single device
- `POST /api/scan/validate` - Comprehensive Cisco device validation
- `POST /api/scan/credentials/test` - Test multiple credentials against a device
- `POST /api/scan/range/validate` - Validate network range before scanning
- `GET /api/scan/config` - Get scanning configuration and capabilities

### Enhanced Device Information

Each discovered device now includes:

```json
{
  "ip": "192.168.116.1",
  "device_type": "cisco",
  "bridge": "Cisco-Core-Router",
  "open_ports": [22, 23, 80, 161],
  "services": {
    "22": {"service": "ssh", "product": "Cisco SSH", "version": "2.0"}
  },
  "cisco_indicators": ["SSH+Telnet combination", "SNMP management"],
  "device_priority": 100,
  "hostname": "R1-Core",
  "model": "IOSv",
  "ios_version": "15.9",
  "role_hint": "core",
  "scan_method": "nmap"
}
```

## 🔧 Configuration Options

### Network Ranges

Configure allowed scanning ranges in `config.py`:

```python
# Your lab networks
ALLOWED_SCAN_RANGES = [
    "192.168.116.0/24",  # Your CML range
    "10.0.0.0/24",       # Management network
    "172.16.0.0/16"      # Additional lab range
]
```

### Credential Sets

Add your specific credentials:

```python
CISCO_CREDENTIAL_SETS = [
    ("admin", "admin", "admin"),           # Default
    ("cisco", "cisco", "cisco"),           # Alternative
    ("your_user", "your_pass", "enable"),  # Your credentials
]
```

### Scan Performance

Adjust for your environment:

```python
SCAN_THREADS = 15           # Concurrent threads (reduce if network is slow)
SCAN_TIMEOUT = 5           # Timeout per device (increase for slow devices)
NMAP_HOST_BATCH_SIZE = 10  # Devices per Nmap batch (reduce for stability)
```

## 🐛 Troubleshooting

### Common Issues

1. **"Nmap not found"**
   ```bash
   # Install Nmap system package
   sudo apt install nmap  # Ubuntu/Debian
   sudo yum install nmap  # CentOS/RHEL
   ```

2. **Slow scanning**
   - Reduce `SCAN_THREADS` in config.py
   - Use quick_scan mode
   - Scan smaller network ranges

3. **SSH authentication failures**
   - Check credentials in `config.py`
   - Verify SSH is enabled on devices
   - Check if devices are using default credentials

4. **No devices found**
   - Verify network range is correct
   - Check if devices are powered on
   - Ensure network connectivity from scanner

### Debug Mode

Enable detailed logging:

```python
# In config.py
DEBUG_DEVICE_DETECTION = True
VERBOSE_SCAN_LOGGING = True

# Run with verbose output
python services/net_scan.py --verbose 192.168.116.0/24
```

## 🔒 Security Considerations

### Lab Environment (Current Setup)
- ✅ Safe for CML/lab environments
- ✅ Uses common lab credentials
- ✅ Scans only private networks

### Production Deployment
Before using in production:

1. **Change default credentials**:
   ```python
   DEFAULT_CISCO_USERNAME = "your_prod_user"
   DEFAULT_CISCO_PASSWORD = "secure_password"
   ```