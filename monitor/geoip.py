"""
Dynamic & Intelligent GeoIP and Live Location Resolution Engine for CyberOracle Intelligence
Resolves real public IP addresses, local network IPs (Wi-Fi / LAN demonstration devices),
and simulated threat actors with accurate geographical coordinates and telemetry.
"""

import hashlib
import ipaddress
import urllib.request
import json
import time

# In-memory thread-safe GeoIP cache
GEOIP_CACHE = {}

# Default fallback local station coordinates (Bengaluru Hub)
DEFAULT_HOST_LOCATION = {
    "country": "India",
    "country_code": "IN",
    "city": "Bengaluru",
    "lat": 12.9753,
    "lng": 77.5910,
    "asn": "Reliance Jio Infocomm (Local Wi-Fi Network)",
}

# Registered Operator Laptop / Local Testbed Sensor IPs with verified physical location
OPERATOR_LAPTOP_IPS = {
    "192.168.31.173",
}

# Pre-mapped GeoIP coordinates for simulated threat actors
KNOWN_GEOIP_DATABASE = {
    "185.220.101.5": {
        "country": "Germany",
        "country_code": "DE",
        "city": "Frankfurt",
        "lat": 50.1109,
        "lng": 8.6821,
        "asn": "AS208291 Tor Exit Network",
    },
    "198.51.100.45": {
        "country": "United States",
        "country_code": "US",
        "city": "San Jose",
        "lat": 37.3382,
        "lng": -121.8863,
        "asn": "AS15169 Cloud Infrastructure",
    },
    "203.0.113.88": {
        "country": "Russia",
        "country_code": "RU",
        "city": "Moscow",
        "lat": 55.7558,
        "lng": 37.6173,
        "asn": "AS12389 Rostelecom",
    },
    "192.0.2.140": {
        "country": "China",
        "country_code": "CN",
        "city": "Shanghai",
        "lat": 31.2304,
        "lng": 121.4737,
        "asn": "AS4134 Chinanet",
    },
    "198.51.100.99": {
        "country": "Netherlands",
        "country_code": "NL",
        "city": "Amsterdam",
        "lat": 52.3676,
        "lng": 4.9041,
        "asn": "AS1103 SURFnet",
    },
    "203.0.113.12": {
        "country": "Brazil",
        "country_code": "BR",
        "city": "São Paulo",
        "lat": -23.5505,
        "lng": -46.6333,
        "asn": "AS28573 Claro Brasil",
    },
    "198.51.100.77": {
        "country": "Singapore",
        "country_code": "SG",
        "city": "Singapore",
        "lat": 1.3521,
        "lng": 103.8198,
        "asn": "AS4657 StarHub",
    },
}

GLOBAL_GEO_HUBS = [
    {"country": "United States", "country_code": "US", "city": "Ashburn", "lat": 39.0438, "lng": -77.4874},
    {"country": "United Kingdom", "country_code": "GB", "city": "London", "lat": 51.5074, "lng": -0.1278},
    {"country": "France", "country_code": "FR", "city": "Paris", "lat": 48.8566, "lng": 2.3522},
    {"country": "Japan", "country_code": "JP", "city": "Tokyo", "lat": 35.6762, "lng": 139.6503},
    {"country": "Australia", "country_code": "AU", "city": "Sydney", "lat": -33.8688, "lng": 151.2093},
    {"country": "India", "country_code": "IN", "city": "Bengaluru", "lat": 12.9753, "lng": 77.5910},
    {"country": "Canada", "country_code": "CA", "city": "Toronto", "lat": 43.6532, "lng": -79.3832},
    {"country": "South Korea", "country_code": "KR", "city": "Seoul", "lat": 37.5665, "lng": 126.9780},
    {"country": "UAE", "country_code": "AE", "city": "Dubai", "lat": 25.2048, "lng": 55.2708},
]


def is_private_or_local_ip(ip: str) -> bool:
    """Check if an IP is localhost, private subnet, or link-local."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return ip in {'127.0.0.1', '::1', 'localhost'}


def get_host_public_location() -> dict:
    """Dynamically discover host machine's live geographical location."""
    global DEFAULT_HOST_LOCATION
    if "host_public_geo" in GEOIP_CACHE:
        return GEOIP_CACHE["host_public_geo"]

    try:
        req = urllib.request.Request(
            "http://ip-api.com/json/",
            headers={"User-Agent": "CyberOracle-GeoIP/3.0"}
        )
        with urllib.request.urlopen(req, timeout=1.8) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get("status") == "success":
                geo = {
                    "country": data.get("country", "India"),
                    "country_code": data.get("countryCode", "IN"),
                    "city": data.get("city", "Bengaluru"),
                    "lat": float(data.get("lat", 12.9753)),
                    "lng": float(data.get("lon", 77.5910)),
                    "asn": data.get("isp", "Local Wi-Fi Network"),
                }
                GEOIP_CACHE["host_public_geo"] = geo
                DEFAULT_HOST_LOCATION = geo
                return geo
    except Exception:
        pass

    return DEFAULT_HOST_LOCATION


def resolve_ip_geo(ip: str) -> dict:
    """
    Resolve any IP address (public, Wi-Fi LAN device, or simulated)
    to its accurate geographic coordinates, city, country, and network ASN.
    Follows strict NO-FAKE-DATA policy: never generates random coordinates
    or fake geographical hubs.
    """
    if not ip:
        return {
            "country": "Location unavailable",
            "country_code": "UN",
            "city": "Location unavailable",
            "lat": None,
            "lng": None,
            "asn": "Unknown Origin",
            "has_geo": False,
            "geo_status": "Location unavailable",
            "is_local": False,
        }

    # 1. Check in-memory cache
    if ip in GEOIP_CACHE:
        cached = GEOIP_CACHE[ip]
        # If previously cached as unmapped local device, allow upgrading to resolved host location
        if not (cached.get('is_local') and not cached.get('has_geo')):
            return cached

    # 2. Check registered Operator Laptop / Local Testbed Sensor with verified physical location
    if ip in OPERATOR_LAPTOP_IPS:
        host_geo = get_host_public_location()
        lat = host_geo.get("lat")
        lng = host_geo.get("lng")
        has_geo = bool(lat is not None and lng is not None)
        result = {
            "country": host_geo.get("country", "India"),
            "country_code": host_geo.get("country_code", "IN"),
            "city": f"{host_geo.get('city', 'Local Origin')} (Operator Laptop)",
            "lat": lat,
            "lng": lng,
            "asn": f"{host_geo.get('asn', 'Local Wi-Fi Network')} [LAN: {ip}]",
            "has_geo": has_geo,
            "geo_status": f"Local Laptop Geo-Resolved ({host_geo.get('city')}, {host_geo.get('country')})" if has_geo else "Location unavailable",
            "is_local": True,
        }
        GEOIP_CACHE[ip] = result
        return result

    # 3. Check known simulation testbed dataset with verified geographic attribution
    if ip in KNOWN_GEOIP_DATABASE:
        res = dict(KNOWN_GEOIP_DATABASE[ip])
        res["has_geo"] = True
        res["geo_status"] = "Verified Simulation GeoIP"
        res["is_local"] = False
        GEOIP_CACHE[ip] = res
        return res

    # 4. Handle Local Network / Demonstration Devices without explicit physical coordinates
    if is_private_or_local_ip(ip):
        is_current_host = ip in {'127.0.0.1', '::1', 'localhost'}
        label = "SOC Host Station" if is_current_host else f"Local Test Device ({ip})"
        result = {
            "country": "Local / Private Network",
            "country_code": "LOCAL",
            "city": label,
            "lat": None,
            "lng": None,
            "asn": "RFC1918 / Loopback Address",
            "has_geo": False,
            "geo_status": "Location unavailable (Local/Private IP)",
            "is_local": True,
        }
        GEOIP_CACHE[ip] = result
        return result

    # 4. Handle Public IP: Fast Live Online Geolocation with Timeout
    try:
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip}",
            headers={"User-Agent": "CyberOracle-ThreatGeo/3.0"}
        )
        with urllib.request.urlopen(req, timeout=1.8) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get("status") == "success" and data.get("lat") is not None and data.get("lon") is not None:
                result = {
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "UN"),
                    "city": data.get("city", "Public Network Node"),
                    "lat": float(data.get("lat")),
                    "lng": float(data.get("lon")),
                    "asn": data.get("isp", data.get("org", "Public Autonomous System")),
                    "has_geo": True,
                    "geo_status": "Live Public GeoIP Resolved",
                    "is_local": False,
                }
                GEOIP_CACHE[ip] = result
                return result
    except Exception:
        pass

    # 5. Genuine Unresolvable State: NO random fallback, NO fake coordinates
    result = {
        "country": "Location unavailable",
        "country_code": "UN",
        "city": "Location unavailable",
        "lat": None,
        "lng": None,
        "asn": "Unresolved Public Network",
        "has_geo": False,
        "geo_status": "Location unavailable",
        "is_local": False,
    }
    GEOIP_CACHE[ip] = result
    return result
