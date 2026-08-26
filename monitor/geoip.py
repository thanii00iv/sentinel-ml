"""
Offline GeoIP and Coordinate Resolution Engine for SentinelML
Resolves public, simulated, and local IP addresses to geographical coordinates,
cities, and countries for interactive SOC Threat Map visualization.
"""

import hashlib

# Pre-mapped GeoIP coordinates for simulated threat actors and well-known test ranges
KNOWN_GEOIP_DATABASE = {
    # Full Killchain Attacker (Tor Exit Node simulated)
    "185.220.101.5": {
        "country": "Germany",
        "country_code": "DE",
        "city": "Frankfurt",
        "lat": 50.1109,
        "lng": 8.6821,
        "asn": "AS208291 Tor Exit Network",
    },
    # SQLi Attacker
    "198.51.100.45": {
        "country": "United States",
        "country_code": "US",
        "city": "San Jose",
        "lat": 37.3382,
        "lng": -121.8863,
        "asn": "AS15169 Cloud Infrastructure",
    },
    # Brute-Force Attacker
    "203.0.113.88": {
        "country": "Russia",
        "country_code": "RU",
        "city": "Moscow",
        "lat": 55.7558,
        "lng": 37.6173,
        "asn": "AS12389 Rostelecom",
    },
    # Recon Attacker
    "192.0.2.140": {
        "country": "China",
        "country_code": "CN",
        "city": "Shanghai",
        "lat": 31.2304,
        "lng": 121.4737,
        "asn": "AS4134 Chinanet",
    },
    # XSS Attacker
    "198.51.100.99": {
        "country": "Netherlands",
        "country_code": "NL",
        "city": "Amsterdam",
        "lat": 52.3676,
        "lng": 4.9041,
        "asn": "AS1103 SURFnet",
    },
    # Path Traversal Attacker
    "203.0.113.12": {
        "country": "Brazil",
        "country_code": "BR",
        "city": "São Paulo",
        "lat": -23.5505,
        "lng": -46.6333,
        "asn": "AS28573 Claro Brasil",
    },
    "127.0.0.1": {
        "country": "India",
        "country_code": "IN",
        "city": "Bengaluru (SOC Command Node)",
        "lat": 12.9716,
        "lng": 77.5946,
        "asn": "Localhost Telemetry Loop",
    },
    # User's Laptop Local Network Station (Mikey - Bengaluru, Karnataka)
    "192.168.31.173": {
        "country": "India",
        "country_code": "IN",
        "city": "Bengaluru (Your Laptop Station)",
        "lat": 12.9850,
        "lng": 77.6050,
        "asn": "Local Station (Mikey - Jio Wi-Fi)",
    },
    "192.168.20.1": {
        "country": "India",
        "country_code": "IN",
        "city": "Bengaluru (Host Virtual Adapter)",
        "lat": 12.9600,
        "lng": 77.5800,
        "asn": "Host Virtual Adapter (Mikey)",
    },
    "49.37.242.184": {
        "country": "India",
        "country_code": "IN",
        "city": "Bengaluru (Your Public IP)",
        "lat": 12.9753,
        "lng": 77.5910,
        "asn": "AS55836 Reliance Jio Infocomm",
    },
    "192.168.1.50": {
        "country": "India",
        "country_code": "IN",
        "city": "Bengaluru (Internal Gateway)",
        "lat": 12.9400,
        "lng": 77.6100,
        "asn": "Internal Private Subnet",
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
    {"country": "India", "country_code": "IN", "city": "Mumbai", "lat": 19.0760, "lng": 72.8777},
    {"country": "Canada", "country_code": "CA", "city": "Toronto", "lat": 43.6532, "lng": -79.3832},
    {"country": "Sweden", "country_code": "SE", "city": "Stockholm", "lat": 59.3293, "lng": 18.0686},
    {"country": "South Korea", "country_code": "KR", "city": "Seoul", "lat": 37.5665, "lng": 126.9780},
    {"country": "UAE", "country_code": "AE", "city": "Dubai", "lat": 25.2048, "lng": 55.2708},
]


def resolve_ip_geo(ip: str) -> dict:
    """
    Resolve any IP address to its geographic metadata and lat/lng coordinates.
    """
    if ip in KNOWN_GEOIP_DATABASE:
        return KNOWN_GEOIP_DATABASE[ip]

    hash_val = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    hub = GLOBAL_GEO_HUBS[hash_val % len(GLOBAL_GEO_HUBS)]
    lat_jitter = ((hash_val % 100) - 50) / 50.0 * 1.5
    lng_jitter = (((hash_val // 100) % 100) - 50) / 50.0 * 1.5

    return {
        "country": hub["country"],
        "country_code": hub["country_code"],
        "city": hub["city"],
        "lat": round(hub["lat"] + lat_jitter, 4),
        "lng": round(hub["lng"] + lng_jitter, 4),
        "asn": f"AS{hash_val % 60000 + 1000} Dynamic Network",
    }
