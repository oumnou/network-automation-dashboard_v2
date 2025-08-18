# New Network Automation Dashboard

A Flask-based Cisco network management dashboard.
Generated on 2025-08-18T15:45:05.266880Z

## Quick Start (Windows PowerShell)

```powershell
cd "/mnt/data/new-network-automation-dashboard"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:FLASK_APP="app.py"
python app.py
# Open http://127.0.0.1:5000
```

### Notes
- **Network Scan**: Uses `nmap` if available, otherwise falls back to a basic socket scan (slower).
  - Install Nmap from https://nmap.org/download.html and ensure `nmap.exe` is in PATH for best results.
- **Backups**: Uses Netmiko to run `show running-config`. Provide device credentials when prompted.
- **Data**:
  - Switch DB: `data/switches.json`
  - Backups: `data/backups/<ip>_<timestamp>/`
  - Logs: `data/activity.log`

## API Endpoints

- `POST /api/scan/` → `{ "network": "192.168.1.0/24", "ports": [22] }`
- `GET  /api/switch/` → list switches
- `POST /api/switch/` → upsert `{"hostname": "...", "ip": "...", "role": "core|distribution|access"}`
- `GET  /api/switch/<ip>`
- `DELETE /api/switch/<ip>`
- `POST /api/backup/run` → `{"ip":"...","username":"...","password":"...","enable_password":"..."}`
- `GET  /api/logs/tail?n=200`

## Troubleshooting

- If you see `nmap not found`, install Nmap and reopen your terminal.
- If Netmiko can't connect, verify IP/creds and that port 22 is open.
