"""
JalgiNet – GeoIP Lookup Module
================================
Resolves IP addresses to geographic locations using the free ip-api.com service.
Results are cached in-memory (TTL configurable) to avoid rate limiting.
"""

import time
import threading
import requests
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

_cache: dict = {}           # {ip: (timestamp, geo_data)}
_cache_lock = threading.Lock()

# Private/reserved IP ranges (no geo lookup needed)
_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "0.", "::1",
)


def is_private(ip: str) -> bool:
    """Return True if the IP is a private/reserved address."""
    return any(ip.startswith(prefix) for prefix in _PRIVATE_PREFIXES)


def lookup(ip: str) -> dict:
    """
    Return geo data for an IP address.
    Uses in-memory cache with TTL defined in config.
    Returns empty dict for private IPs or on failure.
    """
    if not config.MODULES.get("geo_ip", True):
        return {}
    if is_private(ip) or ip in ("unknown", "0.0.0.0", "0.0.0.0/distributed"):
        return {"country": "Internal", "city": "LAN", "isp": "Private Network"}

    with _cache_lock:
        if ip in _cache:
            ts, data = _cache[ip]
            if time.time() - ts < config.GEO_IP["cache_ttl_seconds"]:
                return data

    try:
        url = config.GEO_IP["provider_url"].format(ip=ip)
        resp = requests.get(url, timeout=config.GEO_IP["timeout_seconds"])
        if resp.status_code == 200:
            payload = resp.json()
            if payload.get("status") == "success":
                geo = {
                    "country":      payload.get("country", "Unknown"),
                    "country_code": payload.get("countryCode", ""),
                    "region":       payload.get("regionName", ""),
                    "city":         payload.get("city", "Unknown"),
                    "lat":          payload.get("lat", 0.0),
                    "lon":          payload.get("lon", 0.0),
                    "isp":          payload.get("isp", "Unknown"),
                    "org":          payload.get("org", ""),
                }
                with _cache_lock:
                    _cache[ip] = (time.time(), geo)
                return geo
    except Exception:
        pass  # Network error – return empty dict

    return {}


def bulk_lookup(ips: list) -> dict:
    """Resolve multiple IPs; returns {ip: geo_dict}."""
    return {ip: lookup(ip) for ip in ips}
