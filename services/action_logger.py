# services/action_logger.py - Enhanced Action Logger
import os
import time
from datetime import datetime
from config import LOG_FILE

def action_logger(message: str, level: str = "INFO"):
    """
    Enhanced action logger with proper formatting and error handling.
    
    Args:
        message (str): The message to log
        level (str): Log level (INFO, WARNING, ERROR, DEBUG)
    """
    try:
        # Ensure log directory exists
        log_dir = os.path.dirname(LOG_FILE)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        # Format the log entry
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] [{level}] {message}"
        
        # Write to log file
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(formatted_message + "\n")
            f.flush()  # Ensure immediate write
        
        # Also print to console for debugging
        print(formatted_message)
        
    except Exception as e:
        # Fallback to console logging if file logging fails
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] Logging failed: {e}")
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [{level}] {message}")

def log_info(message: str):
    """Log an informational message."""
    action_logger(message, "INFO")

def log_warning(message: str):
    """Log a warning message."""
    action_logger(message, "WARNING")

def log_error(message: str):
    """Log an error message."""
    action_logger(message, "ERROR")

def log_debug(message: str):
    """Log a debug message."""
    action_logger(message, "DEBUG")

def log_scan_start(scan_type: str, target: str):
    """Log the start of a network scan."""
    action_logger(f"Starting {scan_type} scan of {target}", "INFO")

def log_scan_result(ip: str, hostname: str, success: bool, error: str = None):
    """Log individual scan results."""
    if success:
        action_logger(f"✅ {ip} ({hostname}): Successfully authenticated", "INFO")
    else:
        error_msg = f" - {error}" if error else ""
        action_logger(f"❌ {ip}: Authentication failed{error_msg}", "WARNING")

def log_scan_complete(total: int, successful: int, duration: float):
    """Log scan completion summary."""
    success_rate = (successful / total * 100) if total > 0 else 0
    action_logger(
        f"Scan complete: {successful}/{total} devices accessible "
        f"({success_rate:.1f}% success rate) in {duration:.1f}s", 
        "INFO"
    )

def log_backup_start(ip: str):
    """Log the start of a backup operation."""
    action_logger(f"Starting configuration backup for {ip}", "INFO")

def log_backup_complete(ip: str, success: bool, size: int = None, error: str = None):
    """Log backup completion."""
    if success:
        size_info = f" ({size} bytes)" if size else ""
        action_logger(f"✅ Backup completed for {ip}{size_info}", "INFO")
    else:
        error_msg = f" - {error}" if error else ""
        action_logger(f"❌ Backup failed for {ip}{error_msg}", "ERROR")

def log_topology_validation(valid: bool, found: int, expected: int, missing: list = None):
    """Log topology validation results."""
    if valid:
        action_logger(f"✅ Topology validation: {found}/{expected} devices found", "INFO")
    else:
        missing_str = ", ".join(missing) if missing else "unknown"
        action_logger(
            f"⚠️ Topology validation failed: {found}/{expected} devices found. "
            f"Missing: {missing_str}", 
            "WARNING"
        )

def get_recent_logs(lines: int = 50):
    """
    Get recent log entries.
    
    Args:
        lines (int): Number of recent lines to return
        
    Returns:
        list: List of recent log entries
    """
    try:
        if not os.path.exists(LOG_FILE):
            return []
        
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            all_lines = f.readlines()
            return [line.rstrip("\n") for line in all_lines[-lines:]]
    except Exception as e:
        print(f"Error reading log file: {e}")
        return [f"[ERROR] Could not read log file: {e}"]

def clear_logs():
    """Clear the log file."""
    try:
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write("")
        action_logger("Log file cleared", "INFO")
        return True
    except Exception as e:
        print(f"Error clearing log file: {e}")
        return False

def setup_logging():
    """Initialize logging system."""
    try:
        # Ensure log directory exists
        log_dir = os.path.dirname(LOG_FILE)
        os.makedirs(log_dir, exist_ok=True)
        
        # Log startup message
        action_logger("=" * 50, "INFO")
        action_logger("Cisco Network Dashboard - Logging Initialized", "INFO")
        action_logger(f"Log file: {LOG_FILE}", "INFO")
        action_logger("=" * 50, "INFO")
        
        return True
    except Exception as e:
        print(f"Failed to setup logging: {e}")
        return False

# Initialize logging on import
if __name__ != "__main__":
    setup_logging()