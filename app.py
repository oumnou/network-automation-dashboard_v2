# app.py - Cisco Network Dashboard Main Application
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import os
import sys

# Add current directory to path to ensure imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)
CORS(app)

# Import configuration first
try:
    from config import DEBUG, HOST, PORT, LOG_FILE
    print("✅ Configuration loaded successfully")
except ImportError as e:
    print(f"❌ Failed to import config: {e}")
    # Fallback configuration
    DEBUG = True
    HOST = "0.0.0.0"
    PORT = 5000
    LOG_FILE = "data/activity.log"

# Import blueprints with error handling
blueprints_loaded = []
blueprints_failed = []

# Import switch routes
try:
    from routes.switch_routes import switch_bp
    app.register_blueprint(switch_bp, url_prefix="/api/switch")
    blueprints_loaded.append("switch_routes")
except ImportError as e:
    blueprints_failed.append(f"switch_routes: {e}")

# Import backup routes
try:
    from routes.backup_routes import backup_bp
    app.register_blueprint(backup_bp, url_prefix="/api/backup")
    blueprints_loaded.append("backup_routes")
except ImportError as e:
    blueprints_failed.append(f"backup_routes: {e}")

# Import scan routes (most important)
try:
    from routes.scan_routes import scan_bp
    app.register_blueprint(scan_bp, url_prefix="/api/scan")
    blueprints_loaded.append("scan_routes")
except ImportError as e:
    blueprints_failed.append(f"scan_routes: {e}")
    print(f"⚠️  WARNING: Scan routes failed to load: {e}")

@app.route("/")
def home():
    """Main dashboard page"""
    try:
        return render_template("index.html")
    except Exception as e:
        return f"""
        <html>
        <body>
        <h1>Cisco Network Dashboard</h1>
        <p style="color: red;">Template error: {e}</p>
        <p>Please ensure templates/index.html exists</p>
        <a href="/api/health">Check API Health</a>
        </body>
        </html>
        """, 500

@app.route("/api/logs/tail", methods=["GET"])
def tail_logs():
    """Get recent log entries"""
    try:
        n = int(request.args.get("n", 200))
        
        if not os.path.exists(LOG_FILE):
            os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
            with open(LOG_FILE, "w", encoding="utf-8") as f:
                f.write(f"[{__name__}] Log file created\n")
        
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()[-n:]
        
        return jsonify({
            "lines": [ln.rstrip("\n") for ln in lines],
            "total_lines": len(lines)
        })
        
    except FileNotFoundError:
        return jsonify({
            "lines": ["[ERROR] Log file not found"],
            "error": "Log file not accessible"
        })
    except Exception as e:
        return jsonify({
            "error": str(e), 
            "lines": [f"[ERROR] Failed to read logs: {e}"]
        }), 500

@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "Cisco Network Dashboard",
        "version": "1.0.0",
        "blueprints_loaded": blueprints_loaded,
        "blueprints_failed": blueprints_failed,
        "endpoints": {
            "scan": "/api/scan/",
            "switches": "/api/switch/",
            "backup": "/api/backup/",
            "logs": "/api/logs/tail"
        }
    })

@app.route("/api/debug/routes", methods=["GET"])
def debug_routes():
    """Debug endpoint to list all available routes"""
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            "endpoint": rule.endpoint,
            "methods": list(rule.methods),
            "path": str(rule.rule)
        })
    
    return jsonify({
        "total_routes": len(routes),
        "routes": sorted(routes, key=lambda x: x["path"])
    })

@app.route("/api/debug/imports", methods=["GET"])
def debug_imports():
    """Debug endpoint to check import status"""
    import_status = {}
    
    test_imports = [
        ("flask", "Flask web framework"),
        ("paramiko", "SSH connectivity"),
        ("ipaddress", "Network validation"),
        ("config", "Application configuration"),
        ("services.net_scan", "Network scanning"),
        ("services.ssh_utils", "SSH utilities")
    ]
    
    for module_name, description in test_imports:
        try:
            __import__(module_name)
            import_status[module_name] = {"status": "OK", "description": description}
        except ImportError as e:
            import_status[module_name] = {"status": "FAILED", "error": str(e), "description": description}
    
    return jsonify(import_status)

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "error": "Endpoint not found",
        "available_endpoints": [
            "/api/scan/ (POST)",
            "/api/scan/known (POST)",
            "/api/scan/single (POST)",
            "/api/switch/ (GET, POST)",
            "/api/backup/ (GET, POST)",
            "/api/logs/tail (GET)"
        ]
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "error": "Internal server error",
        "message": str(error)
    }), 500

def create_required_directories():
    """Ensure all required directories exist"""
    directories = ["data", "data/backups", "templates", "static", "routes", "services"]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
        except Exception as e:
            print(f"⚠️  Could not create directory {directory}: {e}")

if __name__ == "__main__":
    print("🚀 Starting Cisco Network Dashboard...")
    
    # Create required directories
    create_required_directories()
    
    # Print configuration
    print(f"🌐 Server will be available at: http://{HOST}:{PORT}")
    print("📊 Dashboard features:")
    print("  • Network topology discovery")
    print("  • Cisco device management") 
    print("  • Configuration backup")
    print("  • Real-time monitoring")
    
    if blueprints_loaded:
        print(f"✅ Loaded blueprints: {', '.join(blueprints_loaded)}")
    if blueprints_failed:
        print(f"⚠️  Failed blueprints: {', '.join(blueprints_failed)}")
    
    try:
        app.run(debug=DEBUG, host=HOST, port=PORT)
    except Exception as e:
        print(f"❌ Failed to start server: {e}")
        sys.exit(1)