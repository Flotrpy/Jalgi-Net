"""
JalgiNet – IDS Integration / Log Parser Module
================================================
Supports two operating modes:
  1. REAL MODE:   Parse actual Snort unified2 or Suricata EVE JSON log files.
  2. SIMULATION:  Generate realistic Snort/Suricata-style events synthetically.

Runs in a background thread and stores parsed events to the DB.
"""

import json
import os
import random
import re
import threading
import time
from datetime import datetime
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
import database as db

# ── Realistic attack templates ─────────────────────────────────────────────────
_ATTACK_TEMPLATES = [
    {
        "type": "Port Scan",
        "severity": "Low",
        "rule_ids": ["1:1000", "1:1001", "1:1228"],
        "messages": [
            "SCAN nmap SYN scan",
            "SCAN portscan TCP",
            "SCAN Masscan detected",
        ],
        "dst_ports": [22, 80, 443, 3306, 8080, 21, 25],
    },
    {
        "type": "SQL Injection",
        "severity": "High",
        "rule_ids": ["1:2006446", "1:2006445", "1:100001"],
        "messages": [
            "SQL Injection attempt – UNION SELECT",
            "SQL Injection attempt – OR 1=1",
            "WEB-ATTACKS SQL injection attempt",
        ],
        "dst_ports": [80, 443, 8080, 3306],
    },
    {
        "type": "Brute Force",
        "severity": "Medium",
        "rule_ids": ["1:2019876", "1:2101411", "1:2020"],
        "messages": [
            "EXPLOIT SSH brute force login attempt",
            "EXPLOIT FTP brute force detected",
            "HTTP login brute force attempt",
        ],
        "dst_ports": [22, 21, 80, 443, 3389],
    },
    {
        "type": "XSS",
        "severity": "Medium",
        "rule_ids": ["1:2009714", "1:2009715"],
        "messages": [
            "WEB-ATTACKS XSS script tag",
            "WEB-ATTACKS XSS in URI parameter",
        ],
        "dst_ports": [80, 443, 8080],
    },
    {
        "type": "Remote Code Execution",
        "severity": "Critical",
        "rule_ids": ["1:2012887", "1:2001219"],
        "messages": [
            "WEB-ATTACKS PHP Remote File Inclusion attempt",
            "EXPLOIT Apache Struts RCE CVE-2017-5638",
            "SHELLSHOCK bash RCE attempt",
        ],
        "dst_ports": [80, 443, 8080, 8443],
    },
    {
        "type": "Malware C2",
        "severity": "Critical",
        "rule_ids": ["1:2404000", "1:2404001", "1:2000419"],
        "messages": [
            "MALWARE-CNC Cobalt Strike beacon",
            "MALWARE-CNC reverse shell detected",
            "TROJAN DNS C2 communication",
        ],
        "dst_ports": [4444, 8443, 443, 53],
    },
    {
        "type": "DNS Exfiltration",
        "severity": "High",
        "rule_ids": ["1:2016012", "1:2016013"],
        "messages": [
            "DNS long TXT record exfiltration attempt",
            "DNS tunneling detected – high entropy query",
        ],
        "dst_ports": [53],
    },
    {
        "type": "Directory Traversal",
        "severity": "Medium",
        "rule_ids": ["1:2000537"],
        "messages": [
            "WEB-ATTACKS directory traversal ../",
            "WEB-ATTACKS path traversal attempt",
        ],
        "dst_ports": [80, 443, 8080],
    },
]

_ATTACKER_IPS = [
    "185.220.101.42", "45.142.212.100", "91.108.4.41",
    "178.128.23.55",  "103.21.244.0",   "198.50.128.0",
    "62.210.115.92",  "194.165.16.11",  "89.248.167.131",
    "193.32.162.44",  "5.188.206.14",   "77.247.108.163",
]
_INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.30",
    "10.0.0.5",     "10.0.0.12",    "172.16.0.4",
]


class IDSParser:
    """
    Parses Snort/Suricata logs OR generates synthetic IDS events.
    Stores results in the ids_events table and issues alerts.
    """

    def __init__(self):
        self._running = False
        self._thread = None
        self._log_position = 0     # File byte offset for real log tailing

    def start(self):
        if self._running:
            return
        self._running = True
        target = self._simulate_loop if config.SIMULATION_MODE else self._parse_loop
        self._thread = threading.Thread(
            target=target, daemon=True, name="IDSParser"
        )
        self._thread.start()
        print(f"[IDSParser] Started in "
              f"{'SIMULATION' if config.SIMULATION_MODE else 'LIVE'} mode.")

    def stop(self):
        self._running = False

    # ── Simulation ─────────────────────────────────────────────────────────────

    def _simulate_loop(self):
        """Generate synthetic IDS events at a realistic rate."""
        while self._running:
            try:
                if config.MODULES.get("ids_integration", True):
                    # 30% chance of generating an event per tick
                    if random.random() < 0.30:
                        tpl = random.choice(_ATTACK_TEMPLATES)
                        self._store_event_from_template(tpl)
            except Exception as e:
                print(f"[IDSParser] Simulation error: {e}")
            # Variable interval for realism
            time.sleep(random.uniform(3, 8))

    def _store_event_from_template(self, tpl: dict):
        """Create a DB record and alert from one attack template."""
        src_ip   = random.choice(_ATTACKER_IPS)
        dst_ip   = random.choice(_INTERNAL_IPS)
        dst_port = random.choice(tpl["dst_ports"])
        rule_id  = random.choice(tpl["rule_ids"])
        rule_msg = random.choice(tpl["messages"])

        # Build a realistic simulated raw log line
        ts_str = datetime.utcnow().strftime("%m/%d-%H:%M:%S.%f")[:20]
        raw_log = (
            f'[**] [{rule_id}] {rule_msg} [**]\n'
            f'[Priority: {self._severity_to_priority(tpl["severity"])}]\n'
            f'{ts_str} {src_ip} -> {dst_ip}:{dst_port}'
        )

        event_id = db.insert_ids_event(
            attack_type=tpl["type"],
            source_ip=src_ip,
            dest_ip=dst_ip,
            dest_port=dst_port,
            rule_id=rule_id,
            rule_msg=rule_msg,
            severity=tpl["severity"],
            raw_log=raw_log,
        )

        # Also create an IDS-type alert
        db.insert_alert(
            alert_type="IDS",
            severity=tpl["severity"],
            source_ip=src_ip,
            description=f"[{tpl['type']}] {rule_msg} (Rule {rule_id})",
            extra={"ids_event_id": event_id, "attack_type": tpl["type"]},
        )

        print(f"[IDSParser] Event [{tpl['severity']}] {tpl['type']} from {src_ip}")

    @staticmethod
    def _severity_to_priority(severity: str) -> int:
        return {"Low": 4, "Medium": 3, "High": 2, "Critical": 1}.get(severity, 3)

    # ── Real Suricata EVE JSON parser ──────────────────────────────────────────

    def _parse_loop(self):
        """Tail a real Suricata EVE JSON log file."""
        log_path = config.SURICATA_LOG_PATH
        if not os.path.exists(log_path):
            print(f"[IDSParser] Log file not found: {log_path}. Falling back to simulation.")
            config.SIMULATION_MODE = True
            self._simulate_loop()
            return

        print(f"[IDSParser] Tailing {log_path}")
        with open(log_path, "r") as f:
            f.seek(0, 2)  # Seek to end
            while self._running:
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue
                self._parse_suricata_eve_line(line.strip())

    def _parse_suricata_eve_line(self, line: str):
        """Parse a single Suricata EVE JSON log line."""
        try:
            evt = json.loads(line)
            if evt.get("event_type") != "alert":
                return

            alert   = evt.get("alert", {})
            src_ip  = evt.get("src_ip", "unknown")
            dst_ip  = evt.get("dest_ip", "unknown")
            dst_port = evt.get("dest_port", 0)
            rule_id  = f"{alert.get('gid',1)}:{alert.get('signature_id',0)}"
            rule_msg = alert.get("signature", "Unknown rule")
            category = alert.get("category", "Unknown")
            severity_num = alert.get("severity", 3)
            severity_map = {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}
            severity = severity_map.get(severity_num, "Medium")

            # Map Suricata category to our attack types
            attack_type = self._map_category(category, rule_msg)

            db.insert_ids_event(
                attack_type=attack_type,
                source_ip=src_ip,
                dest_ip=dst_ip,
                dest_port=dst_port,
                rule_id=rule_id,
                rule_msg=rule_msg,
                severity=severity,
                raw_log=line,
            )
            db.insert_alert(
                alert_type="IDS",
                severity=severity,
                source_ip=src_ip,
                description=f"[{attack_type}] {rule_msg}",
                extra={"attack_type": attack_type, "rule_id": rule_id},
            )
        except (json.JSONDecodeError, KeyError) as e:
            pass  # Malformed line – skip silently

    @staticmethod
    def _map_category(category: str, msg: str) -> str:
        """Map a Suricata category string to our normalised attack type."""
        category_lower = category.lower()
        msg_lower = msg.lower()
        if "scan" in category_lower or "scan" in msg_lower:
            return "Port Scan"
        elif "sql" in msg_lower:
            return "SQL Injection"
        elif "brute" in msg_lower or "ssh" in msg_lower:
            return "Brute Force"
        elif "xss" in msg_lower or "cross-site" in msg_lower:
            return "XSS"
        elif "rce" in msg_lower or "exec" in msg_lower or "remote code" in msg_lower:
            return "Remote Code Execution"
        elif "malware" in category_lower or "trojan" in msg_lower or "c2" in msg_lower:
            return "Malware C2"
        elif "dns" in msg_lower and "exfil" in msg_lower:
            return "DNS Exfiltration"
        elif "traversal" in msg_lower or "../" in msg_lower:
            return "Directory Traversal"
        else:
            return "IDS Alert"
