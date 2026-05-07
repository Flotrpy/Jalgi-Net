"""
JalgiNet – Flask Application Entry Point
==========================================
Bootstraps the Flask app, registers all Blueprints,
initialises the database, and starts all background modules.

Usage:
    python app.py

The app serves both the REST API (port 5000) and the frontend
dashboard from the ../frontend/ directory.
"""

import os
import sys
import threading

from flask import Flask, send_from_directory, jsonify
from flask_cors import CORS

# ── Path setup so modules can import config / database ────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
import database as db
from routes.alerts   import alerts_bp
from routes.traffic  import traffic_bp
from routes.ids      import ids_bp
from routes.threats  import threats_bp
from routes.settings import settings_bp

# ── Flask app factory ──────────────────────────────────────────────────────────
FRONTEND_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "frontend"
)

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
CORS(app, origins=config.API["cors_origins"])

# ── Register Blueprints ────────────────────────────────────────────────────────
app.register_blueprint(alerts_bp)
app.register_blueprint(traffic_bp)
app.register_blueprint(ids_bp)
app.register_blueprint(threats_bp)
app.register_blueprint(settings_bp)


# ── Frontend serving ───────────────────────────────────────────────────────────
@app.route("/")
@app.route("/<path:path>")
def serve_frontend(path="index.html"):
    """Serve the React/HTML dashboard from the frontend directory."""
    target = os.path.join(FRONTEND_DIR, path)
    if os.path.isfile(target):
        return send_from_directory(FRONTEND_DIR, path)
    return send_from_directory(FRONTEND_DIR, "index.html")


# ── Health check ───────────────────────────────────────────────────────────────
@app.route("/api/health")
def health():
    import engine_manager
    capture = engine_manager.engines.get("capture")
    return jsonify({
        "status":          "ok",
        "version":         "1.0.0",
        "simulation_mode": config.SIMULATION_MODE,
        "capture_status":  capture.status if capture else "Offline",
        "modules":         config.MODULES,
    })


# ── Main ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("""
╔═══════════════════════════════════════════════════════════╗
║           JalgiNet – SOC Security Monitor v1.0            ║
║     DoS Detection + IDS Integration + Threat Correlation  ║
╚═══════════════════════════════════════════════════════════╝
    """)

    # 1. Initialise database schema
    db.init_db()

    # 2. Start background detection engines
    import engine_manager
    engine_manager.start_engines()

    # 3. Launch Flask dev server
    print(f"[JalgiNet] Dashboard → http://localhost:{config.API['port']}")
    app.run(
        host=config.API["host"],
        port=config.API["port"],
        debug=config.API["debug"],
        use_reloader=False,   # Reloader conflicts with background threads
        threaded=True,
    )
