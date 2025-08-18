from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from routes.scan_routes import scan_bp
from routes.switch_routes import switch_bp
from routes.backup_routes import backup_bp
from config import DEBUG, HOST, PORT
from config import LOG_FILE

app = Flask(__name__)
CORS(app)

# Blueprints
app.register_blueprint(scan_bp, url_prefix="/api/scan")
app.register_blueprint(switch_bp, url_prefix="/api/switch")
app.register_blueprint(backup_bp, url_prefix="/api/backup")

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/logs/tail", methods=["GET"])
def tail_logs():
    try:
        n = int(request.args.get("n", 200))
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()[-n:]
        return jsonify({"lines": [ln.rstrip("\n") for ln in lines]})
    except FileNotFoundError:
        return jsonify({"lines": []})

if __name__ == "__main__":
    app.run(debug=DEBUG, host=HOST, port=PORT)
