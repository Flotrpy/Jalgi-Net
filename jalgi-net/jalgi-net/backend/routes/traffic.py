"""
JalgiNet – Traffic API Routes
/api/traffic  – RPS timeseries, top IPs, protocol breakdown
"""
from flask import Blueprint, request, jsonify
import database as db

traffic_bp = Blueprint("traffic", __name__)


@traffic_bp.route("/api/traffic/stats", methods=["GET"])
def get_traffic_stats():
    """Return RPS timeseries for charts (last N snapshots)."""
    limit = int(request.args.get("limit", 60))
    stats = db.get_traffic_stats(limit=limit)
    return jsonify({"status": "ok", "stats": stats})


@traffic_bp.route("/api/traffic/top-ips", methods=["GET"])
def get_top_ips():
    """Return top IPs by total packet count."""
    limit = int(request.args.get("limit", 10))
    ips   = db.get_top_ips_by_traffic(limit=limit)

    # Optionally enrich with GeoIP
    import config
    if config.MODULES.get("geo_ip", True):
        from modules.geo_ip import lookup
        for entry in ips:
            entry["geo"] = lookup(entry["source_ip"])

    return jsonify({"status": "ok", "top_ips": ips})


@traffic_bp.route("/api/traffic/protocols", methods=["GET"])
def get_protocol_breakdown():
    """Return packet count grouped by protocol."""
    conn = db.get_connection()
    rows = conn.execute(
        "SELECT protocol, COUNT(*) as count FROM traffic_logs "
        "GROUP BY protocol ORDER BY count DESC"
    ).fetchall()
    return jsonify({
        "status": "ok",
        "protocols": [dict(r) for r in rows]
    })
