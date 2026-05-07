"""
JalgiNet – Settings API Routes
/api/settings  – runtime threshold updates, module toggles, log management, export
"""
import json
from flask import Blueprint, request, jsonify
import database as db
import config

settings_bp = Blueprint("settings", __name__)


@settings_bp.route("/api/settings", methods=["GET"])
def get_settings():
    import engine_manager
    capture = engine_manager.engines.get("capture")
    return jsonify({
        "status":   "ok",
        "settings": {
            "dos_thresholds": config.DOS_THRESHOLDS,
            "modules":        config.MODULES,
            "auto_block":     config.AUTO_BLOCK,
            "simulation_mode": config.SIMULATION_MODE,
            "capture_status":  capture.status if capture else "Offline",
            "correlation_window": config.CORRELATION["window_seconds"],
        }
    })


@settings_bp.route("/api/settings", methods=["POST"])
def update_settings():
    """Update runtime thresholds and module toggles."""
    data = request.get_json(force=True)

    # DoS thresholds
    if "dos_thresholds" in data:
        for key, val in data["dos_thresholds"].items():
            if key in config.DOS_THRESHOLDS:
                config.DOS_THRESHOLDS[key] = val

    # Module toggles
    if "modules" in data:
        for key, val in data["modules"].items():
            if key in config.MODULES:
                config.MODULES[key] = bool(val)

    # Auto-block
    if "auto_block" in data:
        ab = data["auto_block"]
        if "enabled" in ab:
            config.AUTO_BLOCK["enabled"] = bool(ab["enabled"])
        if "block_on_severity" in ab:
            config.AUTO_BLOCK["block_on_severity"] = ab["block_on_severity"]
        if "block_duration_minutes" in ab:
            config.AUTO_BLOCK["block_duration_minutes"] = int(ab["block_duration_minutes"])

    # Correlation window
    if "correlation_window" in data:
        config.CORRELATION["window_seconds"] = int(data["correlation_window"])

    # Simulation mode
    if "simulation_mode" in data:
        new_mode = bool(data["simulation_mode"])
        if new_mode != config.SIMULATION_MODE:
            config.SIMULATION_MODE = new_mode
            import engine_manager
            engine_manager.restart_engines()

    return jsonify({"status": "ok", "message": "Settings updated."})


@settings_bp.route("/api/logs/clear", methods=["DELETE"])
def clear_logs():
    """Wipe all time-series data."""
    db.clear_all_logs()
    return jsonify({"status": "ok", "message": "All logs cleared."})


@settings_bp.route("/api/export/json", methods=["GET"])
def export_json():
    """Export all data as a single JSON object."""
    return jsonify({
        "status":             "ok",
        "export_time":        __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "alerts":             db.get_alerts(limit=10000),
        "ids_events":         db.get_ids_events(limit=10000),
        "correlated_threats": db.get_correlated_threats(limit=10000),
        "traffic_stats":      db.get_traffic_stats(limit=10000),
        "blocked_ips":        db.get_blocked_ips(),
        "summary":            db.get_summary_stats(),
    })
