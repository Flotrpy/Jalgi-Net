"""
JalgiNet – Configuration Module
================================
All runtime-configurable thresholds, paths, and feature flags.
This module acts as the single source of truth for system behavior.
"""

import os

# ─────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "jalgi_net.db")

# ─────────────────────────────────────────────
# SUPABASE / POSTGRES SETTINGS
# ─────────────────────────────────────────────
# Set USE_SUPABASE to True to use external PostgreSQL (Supabase)
USE_SUPABASE = os.getenv("USE_SUPABASE", "False").lower() == "true"
SUPABASE_URL = os.getenv("SUPABASE_DB_URL", "postgresql://postgres:password@db.supabase.co:5432/postgres")

# IDS log file paths (for real Snort/Suricata deployments)
SNORT_LOG_PATH = os.getenv("SNORT_LOG_PATH", "/var/log/snort/alert")
SURICATA_LOG_PATH = os.getenv("SURICATA_LOG_PATH", "/var/log/suricata/eve.json")

# ─────────────────────────────────────────────
# SIMULATION MODE
# ─────────────────────────────────────────────
# When True, all traffic and IDS events are generated synthetically.
# Set to False only if running with real Npcap + Snort.
SIMULATION_MODE = True

# How frequently (seconds) the simulator generates new events
SIMULATION_INTERVAL_SECONDS = 2

# ─────────────────────────────────────────────
# DOS DETECTION THRESHOLDS
# ─────────────────────────────────────────────
DOS_THRESHOLDS = {
    "window_seconds": 60,          # Sliding window duration
    "Low":      50,                # Min requests/window for Low alert
    "Medium":   150,               # Min requests/window for Medium alert
    "High":     300,               # Min requests/window for High alert
    "Critical": 600,               # Min requests/window for Critical alert
    "syn_flood_ratio": 0.85,       # SYN-to-ACK ratio threshold
    "udp_flood_pps": 1000,         # UDP packets-per-second threshold
    "icmp_flood_pps": 500,         # ICMP packets-per-second threshold
}

# ─────────────────────────────────────────────
# CORRELATION ENGINE THRESHOLDS
# ─────────────────────────────────────────────
CORRELATION = {
    "window_seconds": 300,         # Time window to group related events (5 min)
    "min_events_to_correlate": 2,  # Minimum events needed to create a correlation
    "risk_score_weights": {
        "DoS":        3.0,
        "IDS":        2.5,
        "Correlated": 5.0,
    },
    "severity_multipliers": {
        "Low":      1.0,
        "Medium":   2.0,
        "High":     3.5,
        "Critical": 5.0,
    },
    # Patterns that instantly trigger a Critical correlated threat
    "critical_patterns": [
        {"requires": ["port_scan", "brute_force", "dos"]},
        {"requires": ["sql_injection", "dos"]},
        {"requires": ["malware_c2", "dos"]},
    ],
}

# ─────────────────────────────────────────────
# MODULE TOGGLES
# ─────────────────────────────────────────────
MODULES = {
    "dos_detection":    True,
    "ids_integration":  True,
    "correlation":      True,
    "geo_ip":           True,
    "ai_analysis":      True,
    "auto_block":       False,   # Simulation only – doesn't touch firewall rules
}

# ─────────────────────────────────────────────
# AUTO-BLOCK SETTINGS
# ─────────────────────────────────────────────
AUTO_BLOCK = {
    "enabled":           False,
    "block_on_severity": ["Critical"],   # Severities that trigger auto-block
    "block_duration_minutes": 60,
}

# ─────────────────────────────────────────────
# GEO-IP SETTINGS
# ─────────────────────────────────────────────
GEO_IP = {
    "provider_url": "http://ip-api.com/json/{ip}",
    "cache_ttl_seconds": 3600,   # Cache lookups for 1 hour
    "timeout_seconds": 3,
}

# ─────────────────────────────────────────────
# API SERVER
# ─────────────────────────────────────────────
API = {
    "host": "0.0.0.0",
    "port": 3000,
    "debug": False,
    "cors_origins": "*",
}

# ─────────────────────────────────────────────
# ALERT SEVERITIES (ordered lowest → highest)
# ─────────────────────────────────────────────
SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]

# ─────────────────────────────────────────────
# IDS ATTACK CATEGORIES
# ─────────────────────────────────────────────
IDS_ATTACK_TYPES = [
    "Port Scan",
    "SQL Injection",
    "Brute Force",
    "XSS",
    "Remote Code Execution",
    "Malware C2",
    "DNS Exfiltration",
    "ARP Spoofing",
    "MITM Attack",
    "Directory Traversal",
]
