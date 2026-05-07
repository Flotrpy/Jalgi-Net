"""
JalgiNet – IDS Events API Routes
/api/ids  – IDS event feed with attack-type filtering
"""
from flask import Blueprint, request, jsonify
import database as db

ids_bp = Blueprint("ids", __name__)


@ids_bp.route("/api/ids/events", methods=["GET"])
def get_ids_events():
    """Return IDS events, optionally filtered by attack_type."""
    limit       = int(request.args.get("limit", 50))
    offset      = int(request.args.get("offset", 0))
    attack_type = request.args.get("attack_type")

    events = db.get_ids_events(limit=limit, offset=offset,
                               attack_type=attack_type)
    return jsonify({"status": "ok", "events": events, "count": len(events)})


@ids_bp.route("/api/ids/attack-types", methods=["GET"])
def get_attack_types():
    """Return distinct attack types present in the DB."""
    conn  = db.get_connection()
    rows  = conn.execute(
        "SELECT attack_type, COUNT(*) as count FROM ids_events "
        "GROUP BY attack_type ORDER BY count DESC"
    ).fetchall()
    return jsonify({
        "status": "ok",
        "attack_types": [dict(r) for r in rows]
    })


@ids_bp.route("/api/ids/stats", methods=["GET"])
def get_ids_stats():
    """Return IDS summary counts."""
    conn  = db.get_connection()
    total = conn.execute("SELECT COUNT(*) FROM ids_events").fetchone()[0]
    crit  = conn.execute(
        "SELECT COUNT(*) FROM ids_events WHERE severity='Critical'"
    ).fetchone()[0]
    return jsonify({
        "status": "ok",
        "total_events": total,
        "critical_events": crit,
    })
