"""
JalgiNet – Alerts API Routes
/api/alerts  – paginated alert feed with filters
"""
from flask import Blueprint, request, jsonify
import database as db

alerts_bp = Blueprint("alerts", __name__)


@alerts_bp.route("/api/alerts", methods=["GET"])
def get_alerts():
    """Return paginated alerts with optional severity/type filters."""
    limit    = int(request.args.get("limit", 50))
    offset   = int(request.args.get("offset", 0))
    severity = request.args.get("severity")
    alert_type = request.args.get("type")

    alerts = db.get_alerts(limit=limit, offset=offset,
                           severity=severity, alert_type=alert_type)
    counts = db.get_alert_counts()

    return jsonify({
        "status": "ok",
        "alerts": alerts,
        "counts": counts,
        "total":  sum(counts.values()),
    })


@alerts_bp.route("/api/alerts/summary", methods=["GET"])
def get_summary():
    """Return dashboard KPI numbers."""
    return jsonify({"status": "ok", "data": db.get_summary_stats()})


@alerts_bp.route("/api/alerts/<int:alert_id>", methods=["GET"])
def get_alert(alert_id):
    """Return a single alert by ID."""
    conn = db.get_connection()
    row = conn.execute(
        "SELECT * FROM alerts WHERE id = ?", (alert_id,)
    ).fetchone()
    if not row:
        return jsonify({"status": "error", "message": "Not found"}), 404
    return jsonify({"status": "ok", "alert": dict(row)})
