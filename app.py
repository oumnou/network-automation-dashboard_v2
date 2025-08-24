from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from routes.switch_routes import switch_bp
from routes.backup_routes import backup_bp
from routes.scan_routes import scan_bp  # Add the missing scan routes
from config import DEBUG, HOST, PORT
from config import LOG_FILE
import os

app = Flask(__name__)
CORS(app)

# Register all blueprints
app.register_blueprint(switch_bp, url_prefix="/api/switch")
app.register_blueprint(backup_bp, url_prefix="/api/backup")
app.register_blueprint(scan_bp, url_prefix="/api/scan")  # Add scan routes

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/logs/tail", methods=["GET"])
def tail_logs():
    try:
        n = int(request.args.get("n", 200))
        if not os.path.exists(LOG_FILE):
            # Create empty log file if it doesn't exist
            os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
            with open(LOG_FILE, "w") as f:
                f.write("")
        
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()[-n:]
        return jsonify({"lines": [ln.rstrip("\n") for ln in lines]})
    except FileNotFoundError:
        return jsonify({"lines": []})
    except Exception as e:
        return jsonify({"error": str(e), "lines": []}), 500

@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint for monitoring"""
    return jsonify({
        "status": "healthy",
        "service": "Cisco Network Dashboard",
        "version": "1.0.0",
        "endpoints": {
            "scan": "/api/scan/",
            "switches": "/api/switch/",
            "backup": "/api/backup/",
            "logs": "/api/logs/tail"
        }
    })

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found", "available_endpoints": [
        "/api/scan/ (POST)",
        "/api/scan/known (POST)",
        "/api/scan/single (POST)",
        "/api/switch/ (GET, POST)",
        "/api/backup/ (GET, POST)",
        "/api/logs/tail (GET)"
    ]}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error", "message": str(error)}), 500

if __name__ == "__main__":
    print("🚀 Starting Cisco Network Dashboard...")
    print(f"🌐 Server will be available at: http://{HOST}:{PORT}")
    print("📊 Dashboard features:")
    print("  • Network topology discovery")
    print("  • Cisco device management")
    print("  • Configuration backup")
    print("  • Real-time monitoring")
    
    app.run(debug=DEBUG, host=HOST, port=PORT)