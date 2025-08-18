import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
BACKUP_DIR = DATA_DIR / "backups"
SWITCH_DB = DATA_DIR / "switches.json"
LOG_FILE = DATA_DIR / "activity.log"

# Ensure directories exist
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# App settings
DEBUG = True
HOST = "0.0.0.0"
PORT = 5000

# Default scan settings
DEFAULT_SCAN_RANGE = "192.168.1.0/24"
DEFAULT_SCAN_PORTS = [22]  # SSH
