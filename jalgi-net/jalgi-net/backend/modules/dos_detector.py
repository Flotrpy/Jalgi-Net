"""
JalgiNet – DoS Detection Engine
=================================
Analyses per-IP packet counters from the PacketCapture module,
applies configurable thresholds, and generates structured alerts.
Runs continuously in a background thread.
"""

import threading
import time
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
import database as db


class DoSDetector:
    """
    Sliding-window DoS/DDoS detection engine.

    Detection strategies:
    - Volumetric flood:  single IP exceeds pkt/window thresholds
    - SYN flood:         high SYN-to-total ratio detected via DB query
    - Distributed flood: total RPS spike with many unique IPs
    """

    def __init__(self, capture):
        self._capture = capture          # Reference to PacketCapture instance
        self._running = False
        self._thread = None
        self._alerted_ips: set = set()  # Prevent duplicate alert spam

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._detection_loop, daemon=True, name="DoSDetector"
        )
        self._thread.start()
        print("[DoSDetector] Started.")

    def stop(self):
        self._running = False

    # ── Detection loop ─────────────────────────────────────────────────────────

    def _detection_loop(self):
        """Main detection loop; evaluates traffic every window_seconds / 4."""
        interval = max(config.DOS_THRESHOLDS["window_seconds"] / 4, 5)
        while self._running:
            try:
                if config.MODULES.get("dos_detection", True):
                    self._evaluate()
            except Exception as e:
                print(f"[DoSDetector] Error: {e}")
            time.sleep(interval)

    def _evaluate(self):
        """Run all detection checks against current packet counters."""
        counters = self._capture.get_ip_counters()

        if not counters:
            return

        total_pkts = sum(counters.values())
        unique_ips = len(counters)

        # 1. Per-IP volumetric check
        for ip, count in counters.items():
            severity = self._classify_severity(count)
            if severity:
                self._fire_alert(
                    ip, severity,
                    f"High packet rate detected: {count} pkts in "
                    f"{config.DOS_THRESHOLDS['window_seconds']}s window",
                    "volumetric"
                )

        # 2. Distributed flood check (many IPs, high total)
        if unique_ips >= 5 and total_pkts >= config.DOS_THRESHOLDS["Medium"]:
            self._fire_alert(
                "0.0.0.0/distributed", "High",
                f"Distributed flood: {unique_ips} unique IPs, "
                f"{total_pkts} total packets",
                "distributed",
                allow_repeat=True
            )

        # 3. SYN-flood check via DB query
        self._check_syn_flood()

    def _classify_severity(self, count: int) -> str | None:
        """Map packet count to severity level or None if below threshold."""
        t = config.DOS_THRESHOLDS
        if count >= t["Critical"]:
            return "Critical"
        elif count >= t["High"]:
            return "High"
        elif count >= t["Medium"]:
            return "Medium"
        elif count >= t["Low"]:
            return "Low"
        return None

    def _check_syn_flood(self):
        """
        Detect SYN floods by examining the TCP flags column in recent logs.
        If SYN packets exceed the configured ratio, fire an alert.
        """
        import sqlite3
        conn = db.get_connection()
        window_ts = self._window_start_ts()
        rows = conn.execute(
            "SELECT flags, COUNT(*) as cnt FROM traffic_logs "
            "WHERE timestamp >= ? GROUP BY flags",
            (window_ts,)
        ).fetchall()

        total = sum(r["cnt"] for r in rows)
        syn_count = sum(r["cnt"] for r in rows if r["flags"] == "SYN")

        if total > 50:
            ratio = syn_count / total
            if ratio >= config.DOS_THRESHOLDS["syn_flood_ratio"]:
                # Find the dominant IP
                top = conn.execute(
                    "SELECT source_ip, COUNT(*) as c FROM traffic_logs "
                    "WHERE timestamp >= ? AND flags='SYN' "
                    "GROUP BY source_ip ORDER BY c DESC LIMIT 1",
                    (window_ts,)
                ).fetchone()
                src = top["source_ip"] if top else "unknown"
                self._fire_alert(
                    src, "Critical",
                    f"SYN flood detected: {syn_count}/{total} packets are SYN "
                    f"({ratio*100:.1f}% ratio)",
                    "syn_flood",
                    allow_repeat=True
                )

    def _fire_alert(self, ip: str, severity: str, description: str,
                    attack_subtype: str, allow_repeat=False):
        """Create a DoS alert in the DB, avoiding duplicates unless allowed."""
        key = f"{ip}:{attack_subtype}"
        if not allow_repeat and key in self._alerted_ips:
            return

        alert_id = db.insert_alert(
            alert_type="DoS",
            severity=severity,
            source_ip=ip,
            description=description,
            extra={"attack_subtype": attack_subtype}
        )
        self._alerted_ips.add(key)

        # Auto-block if enabled
        if (config.AUTO_BLOCK["enabled"] and
                severity in config.AUTO_BLOCK["block_on_severity"]):
            db.block_ip(ip, f"Auto-blocked: {attack_subtype}",
                        config.AUTO_BLOCK["block_duration_minutes"])
            print(f"[DoSDetector] Auto-blocked {ip}")

        print(f"[DoSDetector] Alert [{severity}] {ip} – {description}")

    @staticmethod
    def _window_start_ts() -> str:
        """ISO timestamp for the start of the current detection window."""
        from datetime import datetime, timedelta
        delta = timedelta(seconds=config.DOS_THRESHOLDS["window_seconds"])
        return (datetime.utcnow() - delta).isoformat() + "Z"
