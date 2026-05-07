"""
JalgiNet – Correlation Engine
===============================
Combines DoS alerts + IDS events to detect multi-stage attacks,
assign risk scores, and create correlated threat records.

Risk scoring formula:
    raw_score = Σ (type_weight × severity_multiplier) for each event
    final_score = min(raw_score / normalization_factor, 10.0)

Pattern bonuses:
    port_scan + brute_force + dos → Critical (score cap = 10)
    sql_injection + dos            → High     (+2 bonus)
    malware_c2 + dos               → Critical (+3 bonus)
"""

import json
import threading
import time
from datetime import datetime, timedelta
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
import database as db


class CorrelationEngine:
    """
    Periodically scans recent alerts and IDS events, groups them by
    source IP within a configurable time window, calculates risk scores,
    and writes correlated threat records to the DB.
    """

    def __init__(self):
        self._running = False
        self._thread = None

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._correlation_loop, daemon=True, name="Correlation"
        )
        self._thread.start()
        print("[Correlation] Engine started.")

    def stop(self):
        self._running = False

    # ── Main loop ──────────────────────────────────────────────────────────────

    def _correlation_loop(self):
        """Run correlation every correlation_window / 3 seconds."""
        interval = max(config.CORRELATION["window_seconds"] / 3, 30)
        while self._running:
            try:
                if config.MODULES.get("correlation", True):
                    self._run_correlation()
            except Exception as e:
                print(f"[Correlation] Error: {e}")
            time.sleep(interval)

    def _run_correlation(self):
        """Fetch recent events, group by IP, compute scores, upsert threats."""
        window_start = (
            datetime.utcnow()
            - timedelta(seconds=config.CORRELATION["window_seconds"])
        ).isoformat() + "Z"

        conn = db.get_connection()

        # Fetch recent DoS + IDS alerts
        alerts = conn.execute(
            "SELECT id, type, severity, source_ip, description, timestamp "
            "FROM alerts WHERE timestamp >= ? AND type IN ('DoS','IDS')",
            (window_start,)
        ).fetchall()

        if len(alerts) < config.CORRELATION["min_events_to_correlate"]:
            return

        # Group by source_ip
        ip_events: dict = {}
        for row in alerts:
            ip = row["source_ip"]
            if "distributed" in ip:
                continue  # Skip pseudo-IPs
            if ip not in ip_events:
                ip_events[ip] = []
            ip_events[ip].append(dict(row))

        # Process each IP with ≥ 2 events
        for ip, events in ip_events.items():
            if len(events) < config.CORRELATION["min_events_to_correlate"]:
                continue
            self._process_ip_events(ip, events)

    def _process_ip_events(self, ip: str, events: list):
        """Score and classify a set of events from a single source IP."""
        raw_score = 0.0
        weights   = config.CORRELATION["risk_score_weights"]
        mults     = config.CORRELATION["severity_multipliers"]
        attack_types = set()
        event_ids = []

        for evt in events:
            evt_type = evt["type"]
            severity = evt["severity"]
            w  = weights.get(evt_type, 2.0)
            m  = mults.get(severity, 1.0)
            raw_score += w * m
            event_ids.append(evt["id"])

            # Collect normalised attack sub-types for pattern matching
            desc = evt["description"].lower()
            if "port scan" in desc or "portscan" in desc:
                attack_types.add("port_scan")
            if "brute force" in desc:
                attack_types.add("brute_force")
            if "sql injection" in desc:
                attack_types.add("sql_injection")
            if "malware" in desc or "c2" in desc:
                attack_types.add("malware_c2")
            if evt_type == "DoS":
                attack_types.add("dos")
            if "syn flood" in desc:
                attack_types.add("syn_flood")
            if "rce" in desc or "remote code" in desc:
                attack_types.add("rce")

        # Apply pattern bonuses
        bonus = self._pattern_bonus(attack_types)
        raw_score += bonus

        # Normalize to 0-10 scale
        risk_score = min(round(raw_score / 8.0, 2), 10.0)
        severity   = self._score_to_severity(risk_score)

        # Build human-readable attack chain
        attack_chain = list(attack_types)
        description  = self._describe_chain(ip, attack_chain, risk_score, len(events))

        db.upsert_correlated_threat(
            source_ip=ip,
            risk_score=risk_score,
            severity=severity,
            attack_chain=attack_chain,
            description=description,
            event_ids=event_ids,
        )

        # Fire a Correlated alert if high enough
        if risk_score >= 5.0:
            db.insert_alert(
                alert_type="Correlated",
                severity=severity,
                source_ip=ip,
                description=description,
                extra={
                    "risk_score": risk_score,
                    "attack_chain": attack_chain,
                    "event_count": len(events),
                },
            )
            print(f"[Correlation] Threat [{severity}] {ip} "
                  f"score={risk_score} chain={attack_chain}")

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _pattern_bonus(attack_types: set) -> float:
        """Return additional score points for known critical multi-stage patterns."""
        bonus = 0.0
        patterns = config.CORRELATION["critical_patterns"]
        for pattern in patterns:
            required = set(pattern["requires"])
            if required.issubset(attack_types):
                bonus += 20.0   # Major bonus – will push score to Critical
                break           # Only apply once per source IP
        # Smaller bonuses for pairs
        if "port_scan" in attack_types and "brute_force" in attack_types:
            bonus += 8.0
        if "sql_injection" in attack_types and "dos" in attack_types:
            bonus += 6.0
        if "malware_c2" in attack_types:
            bonus += 10.0
        return bonus

    @staticmethod
    def _score_to_severity(score: float) -> str:
        if score >= 8.0:
            return "Critical"
        elif score >= 6.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        return "Low"

    @staticmethod
    def _describe_chain(ip: str, chain: list, score: float, count: int) -> str:
        chain_str = " → ".join(c.replace("_", " ").title() for c in chain)
        return (
            f"Multi-stage attack from {ip}: [{chain_str}] "
            f"across {count} events (risk score: {score}/10)"
        )
