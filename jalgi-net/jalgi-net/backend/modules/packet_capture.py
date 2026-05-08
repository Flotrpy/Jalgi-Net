"""
JalgiNet – Packet Capture Module
==================================
Captures live network packets using Scapy (or simulates them).
Runs in a background thread and feeds data to the DoS detector.
"""

import random
import threading
import time
from datetime import datetime
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
import database as db

# ── Realistic IP pool for simulation ─────────────────────────────────────────
_ATTACKER_IPS = [
    "185.220.101.42", "45.142.212.100", "91.108.4.41",
    "178.128.23.55",  "103.21.244.0",   "198.50.128.0",
    "62.210.115.92",  "194.165.16.11",  "89.248.167.131",
    "193.32.162.44",
]
_INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.30",
    "10.0.0.5",     "10.0.0.12",    "172.16.0.4",
]
_PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"]
_PORTS = [80, 443, 22, 3306, 8080, 53, 21, 25, 110, 3389]


class PacketCapture:
    """
    Captures (or simulates) network packets and stores them in the DB.
    In simulation mode generates realistic burst patterns including
    SYN floods, UDP storms, and normal background traffic.
    """

    def __init__(self):
        self._running = False
        self._thread = None
        self._lock = threading.Lock()
        self._pkt_count = 0          # packets captured this window
        self._window_start = time.time()
        self._ip_counters: dict = {}  # {ip: packet_count_this_window}
        self.status = "Stopped"      # Stopped | Simulated | Live | Failed
        self.active_iface = None     # Current sniffing interface

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self):
        """Start the capture/simulation loop in a daemon thread."""
        if self._running:
            return
        self._running = True
        if config.SIMULATION_MODE:
            self.status = "Simulated"
            self._thread = threading.Thread(
                target=self._simulate_loop, daemon=True, name="PacketCapture"
            )
        else:
            self.status = "Starting..."
            self._thread = threading.Thread(
                target=self._live_capture_loop, daemon=True, name="PacketCapture"
            )
        self._thread.start()
        print(f"[PacketCapture] Started in {self.status.upper()} mode.")

    def stop(self):
        """Signal the loop to stop."""
        self._running = False

    def get_ip_counters(self) -> dict:
        """Return a snapshot of per-IP packet counters for the current window."""
        with self._lock:
            return dict(self._ip_counters)

    def reset_window(self):
        """Reset sliding-window counters (called by DoS detector)."""
        with self._lock:
            self._ip_counters.clear()
            self._pkt_count = 0
            self._window_start = time.time()

    # ── Simulation loop ────────────────────────────────────────────────────────

    def _simulate_loop(self):
        """Generate synthetic traffic packets with realistic burst patterns."""
        while self._running:
            try:
                now = time.time()
                elapsed = now - self._window_start

                # Decide burst scenario every ~30 s
                scenario = self._pick_scenario()
                batch_size = scenario["batch_size"]

                for _ in range(batch_size):
                    src_ip = scenario["src_ip"]()
                    dst_ip = random.choice(_INTERNAL_IPS)
                    protocol = scenario["protocol"]()
                    src_port = random.randint(1024, 65535)
                    dst_port = random.choice(_PORTS)
                    pkt_size = random.randint(64, 1500)
                    flags = self._random_tcp_flags(protocol)

                    # Record to DB
                    db.insert_traffic_log(
                        src_ip, dst_ip, src_port,
                        dst_port, protocol, pkt_size, flags
                    )

                    with self._lock:
                        self._pkt_count += 1
                        self._ip_counters[src_ip] = \
                            self._ip_counters.get(src_ip, 0) + 1

                # Emit aggregated stat every window
                if elapsed >= 5:
                    rps = self._pkt_count / max(elapsed, 1)
                    unique_ips = len(self._ip_counters)
                    db.insert_traffic_stat(rps, self._pkt_count, unique_ips)

                    # Update real-time dashboard via WebSocket
                    try:
                        from app import socketio
                        socketio.emit('update_stats', db.get_summary_stats())
                    except ImportError:
                        pass

                    self.reset_window()

                time.sleep(config.SIMULATION_INTERVAL_SECONDS)
            except Exception as e:
                print(f"[PacketCapture] Simulation error: {e}")
                time.sleep(2)

    def _pick_scenario(self) -> dict:
        """Pick a random traffic scenario for this simulation tick."""
        roll = random.random()

        if roll < 0.15:          # DoS flood – single attacker IP
            attacker = random.choice(_ATTACKER_IPS)
            return {
                "batch_size": random.randint(80, 200),
                "src_ip":     lambda a=attacker: a,
                "protocol":   lambda: random.choice(["TCP", "UDP", "ICMP"]),
            }
        elif roll < 0.30:        # Distributed – multiple attacker IPs
            return {
                "batch_size": random.randint(40, 100),
                "src_ip":     lambda: random.choice(_ATTACKER_IPS),
                "protocol":   lambda: random.choice(["TCP", "UDP"]),
            }
        else:                    # Normal background traffic
            return {
                "batch_size": random.randint(5, 20),
                "src_ip":     lambda: random.choice(
                    _INTERNAL_IPS + _ATTACKER_IPS[:2]
                ),
                "protocol":   lambda: random.choice(_PROTOCOLS),
            }

    @staticmethod
    def _random_tcp_flags(protocol: str) -> str:
        if protocol != "TCP":
            return ""
        return random.choice(["SYN", "SYN-ACK", "ACK", "FIN", "RST", "SYN", "SYN"])

    # ── Live capture loop ──────────────────────────────────────────────────────

    def _live_capture_loop(self):
        """
        Real packet capture using Scapy.
        Requires Npcap (Windows) or libpcap (Linux/Mac) + admin privileges.
        """
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP, conf

            # Try to auto-select the interface talking to the internet (router)
            try:
                # conf.route.route("0.0.0.0") returns (iface, gateway, ip)
                best_iface = conf.route.route("0.0.0.0")[0]
                # On Windows, iface might be a Scapy NetworkInterface object
                if hasattr(best_iface, 'name'):
                    self.active_iface = best_iface.description or best_iface.name
                else:
                    self.active_iface = str(best_iface)
            except Exception:
                self.active_iface = str(conf.iface)

            print(f"[PacketCapture] Attempting live capture on: {self.active_iface}")
            self.status = f"Live: {self.active_iface}"

            def handle_packet(pkt):
                if not IP in pkt: return
                src_ip  = pkt[IP].src
                dst_ip  = pkt[IP].dst
                proto   = pkt[IP].proto
                pkt_len = len(pkt)
                protocol_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))
                src_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
                dst_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
                flags    = str(pkt[TCP].flags) if TCP in pkt else ""

                db.insert_traffic_log(src_ip, dst_ip, src_port, dst_port, protocol_name, pkt_len, flags)
                with self._lock:
                    self._pkt_count += 1
                    self._ip_counters[src_ip] = self._ip_counters.get(src_ip, 0) + 1

            # Start sniffing. If this fails due to permissions, it hits 'except'.
            sniff(iface=conf.route.route("0.0.0.0")[0], 
                  prn=handle_packet, store=False,
                  stop_filter=lambda _: not self._running)

        except Exception as e:
            err_msg = str(e)
            if "admin" in err_msg.lower() or "permission" in err_msg.lower():
                self.status = "Failed: Admin required"
            else:
                self.status = f"Failed: {err_msg[:40]}"
            print(f"[PacketCapture] Live capture failed: {e}. NO FALLBACK.")
            # Note: We do NOT fall back to simulation anymore to avoid user confusion.
            self._running = False
