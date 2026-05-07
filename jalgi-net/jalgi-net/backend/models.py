"""
JalgiNet – Data Models
======================
Dataclass definitions for the core entities in the system.
While SQLite rows are often manipulated directly via dicts,
these classes represent the formal schema for type hinting.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict


@dataclass
class Alert:
    """Represents a security event detected by the system."""
    id: int
    type: str          # 'DoS' | 'IDS' | 'Correlated'
    severity: str      # 'Low' | 'Medium' | 'High' | 'Critical'
    source_ip: str
    description: str
    timestamp: str     # ISO 8601 UTC
    extra: Dict        # Additional context (e.g., attack subtypes)


@dataclass
class TrafficLog:
    """Raw network packet metadata."""
    id: int
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    packet_size: int
    timestamp: str
    flags: str = ""


@dataclass
class IDSEvent:
    """A parsed event from Snort or Suricata."""
    id: int
    attack_type: str
    source_ip: str
    dest_ip: str
    dest_port: int
    rule_id: str
    rule_msg: str
    severity: str
    timestamp: str
    raw_log: str


@dataclass
class CorrelatedThreat:
    """A multi-stage attack identified by cross-referencing alerts."""
    id: int
    source_ip: str
    risk_score: float
    severity: str
    attack_chain: list
    description: str
    first_seen: str
    last_seen: str
    event_ids: list
