"""
JalgiNet – Correlated Threats API Routes
/api/threats  – correlated threat records and risk data
"""
from flask import Blueprint, request, jsonify
import database as db

threats_bp = Blueprint("threats", __name__)


@threats_bp.route("/api/threats/correlated", methods=["GET"])
def get_correlated():
    """Return correlated threats ordered by risk score."""
    limit   = int(request.args.get("limit", 50))
    threats = db.get_correlated_threats(limit=limit)
    return jsonify({"status": "ok", "threats": threats, "count": len(threats)})


@threats_bp.route("/api/threats/summary", methods=["GET"])
def get_threat_summary():
    """Return aggregated threat KPIs."""
    conn      = db.get_connection()
    total     = conn.execute("SELECT COUNT(*) FROM correlated_threats").fetchone()[0]
    critical  = conn.execute(
        "SELECT COUNT(*) FROM correlated_threats WHERE severity='Critical'"
    ).fetchone()[0]
    avg_score = conn.execute(
        "SELECT AVG(risk_score) FROM correlated_threats"
    ).fetchone()[0] or 0.0

    return jsonify({
        "status":           "ok",
        "total_threats":    total,
        "critical_threats": critical,
        "avg_risk_score":   round(avg_score, 2),
    })


@threats_bp.route("/api/threats/block", methods=["POST"])
def block_ip():
    """Manually block an IP (simulation)."""
    data   = request.get_json(force=True)
    ip     = data.get("ip")
    reason = data.get("reason", "Manual block via dashboard")
    if not ip:
        return jsonify({"status": "error", "message": "IP required"}), 400
    db.block_ip(ip, reason)
    return jsonify({"status": "ok", "message": f"{ip} blocked."})


@threats_bp.route("/api/threats/blocked-ips", methods=["GET"])
def get_blocked():
    """Return list of blocked IPs."""
    return jsonify({"status": "ok", "blocked_ips": db.get_blocked_ips()})


@threats_bp.route("/api/threats/unblock", methods=["POST"])
def unblock_ip():
    """Remove an IP from the block list."""
    data = request.get_json(force=True)
    ip   = data.get("ip")
    if not ip:
        return jsonify({"status": "error", "message": "IP required"}), 400
    db.unblock_ip(ip)
    return jsonify({"status": "ok", "message": f"{ip} unblocked."})
