# config.py
import os

# Flask configuration
DEBUG = True
HOST = "0.0.0.0"
PORT = 5000

# File paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "app.log")
BACKUP_DIR = os.path.join(BASE_DIR, "backups")
SWITCH_DB = os.path.join(BASE_DIR, "switches.json")

# Network scanning
DEFAULT_SCAN_RANGE = "192.168.116.0/24"  # Updated to match your network

# Create directories if they don't exist
os.makedirs(BACKUP_DIR, exist_ok=True)
os.makedirs(os.path.dirname(SWITCH_DB), exist_ok=True)