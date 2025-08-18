from datetime import datetime
from config import LOG_FILE

def action_logger(message: str):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts} UTC] {message}\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        # As a last resort, ignore logging errors to avoid breaking APIs
        pass
