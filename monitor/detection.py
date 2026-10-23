import re
import math
import time
import threading
import urllib.parse
from collections import Counter, deque, defaultdict
from datetime import timedelta
from django.utils import timezone

# -------------------------------------------------------------
# 1. Thread-Safe Sliding Window Telemetry Cache
# Eliminates per-request ORM COUNT(*) scans in the hot request path
# -------------------------------------------------------------
class TelemetrySlidingWindowCache:
    def __init__(self, max_history_seconds=300):
        self._lock = threading.Lock()
        self.max_history_seconds = max_history_seconds
        # ip -> deque of (timestamp, path, status_code)
        self.ip_events = defaultdict(deque)

    def record_event(self, ip: str, path: str, status_code: int = 200, timestamp: float = None):
        now = timestamp if timestamp is not None else time.time()
        with self._lock:
            q = self.ip_events[ip]
            q.append((now, path, status_code))
            cutoff = now - self.max_history_seconds
            while q and q[0][0] < cutoff:
                q.popleft()

    def get_request_rate(self, ip: str, window_seconds: float = 60.0) -> float:
        now = time.time()
        cutoff = now - window_seconds
        with self._lock:
            q = self.ip_events.get(ip)
            if not q:
                return 0.0
            count = sum(1 for ts, _, _ in q if ts >= cutoff)
            return float(count)

    def is_recon_detected(self, ip: str, window_seconds: float = 120.0, unique_path_thresh: int = 8, not_found_thresh: int = 4) -> bool:
        now = time.time()
        cutoff = now - window_seconds
        with self._lock:
            q = self.ip_events.get(ip)
            if not q:
                return False
            recent = [(p, s) for ts, p, s in q if ts >= cutoff]
            if not recent:
                return False
            unique_paths = len(set(p for p, _ in recent))
            not_found_count = sum(1 for _, s in recent if s == 404)
            return unique_paths >= unique_path_thresh or not_found_count >= not_found_thresh

    def clear(self):
        with self._lock:
            self.ip_events.clear()

GLOBAL_TELEMETRY_CACHE = TelemetrySlidingWindowCache()


# -------------------------------------------------------------
# 2. Context-Aware SQL Injection Signatures
# Avoids matching bare single quotes (e.g. "O'Brien") or dashes
# -------------------------------------------------------------
SQLI_PATTERNS = [
    # 1. Classic SQL Keyword Injections following a quote or boundary
    r"['\"]\s*(?:or|and|union|select|insert|update|delete|drop|alter|exec|having)\b",
    # 2. UNION SELECT combinations (optionally with ALL)
    r"\bunion\s+(?:all\s+)?select\b",
    # 3. Direct SQL statement structures
    r"\bselect\s+[\w\*\s,`]+?\s+from\b",
    r"\binsert\s+into\s+[\w`]+",
    r"\bdrop\s+table\s+[\w`]+",
    r"\bupdate\s+[\w`]+\s+set\b",
    r"\bdelete\s+from\s+[\w`]+",
    # 4. Boolean tautology injections (e.g., OR 1=1, OR 'a'='a', 1' OR '1'='1)
    r"\b(?:or|and)\s+(?:\d+\s*=\s*\d+|['\"][a-zA-Z0-9_-]+['\"]\s*=\s*['\"][a-zA-Z0-9_-]+['\"])",
    r"['\"]\s*(?:or|and)\s+1\s*=\s*1",
    # 5. Comment termination following a quote, keyword, or semicolon
    r"(?:['\"]\s*--|\badmin['\"]\s*--|/\*.*?\*/|;\s*--)",
    # 6. Stacked execution queries
    r";\s*(?:drop|select|insert|update|delete|create|alter|exec|truncate|shutdown)\b",
    # 7. Authentication bypass patterns
    r"\badmin['\"]\s*(?:#|--|/\*|or\b)",
    # 8. SQL Sleep / Benchmark / Hex functions
    r"\b(?:sleep|benchmark|waitfor\s+delay|char|load_file|into\s+outfile)\s*\(",
]
SQLI_REGEX = re.compile("|".join(SQLI_PATTERNS), re.IGNORECASE)

# 2. Cross-Site Scripting (XSS) Signatures
XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"<script[^>]*>",
    r"</script>",
    r"javascript\s*:",
    r"vbscript\s*:",
    r"data\s*:\s*text/html",
    r"onerror\s*=",
    r"onload\s*=",
    r"onclick\s*=",
    r"onfocus\s*=",
    r"onblur\s*=",
    r"onmouseover\s*=",
    r"onmouseenter\s*=",
    r"ontoggle\s*=",
    r"onchange\s*=",
    r"onsubmit\s*=",
    r"onkeydown\s*=",
    r"onkeypress\s*=",
    r"onkeyup\s*=",
    r"<img[^>]+src[^\w]*=[^\w]*[\"']?javascript:",
    r"<img[^>]+onerror[^>]*>",
    r"<iframe[^>]*>",
    r"<svg[^>]*>",
    r"<details[^>]*>",
    r"<body[^>]*>",
    r"<input[^>]+(autofocus|onfocus)[^>]*>",
    r"document\.cookie",
    r"document\.location",
    r"document\.write",
    r"window\.location",
    r"alert\s*\(",
    r"prompt\s*\(",
    r"confirm\s*\(",
    r"eval\s*\(",
    r"setTimeout\s*\(",
    r"setInterval\s*\(",
    r"Function\s*\(",
    r"svg/onload",
    r"String\.fromCharCode",
]
XSS_REGEX = re.compile("|".join(XSS_PATTERNS), re.IGNORECASE)

# 3. Path Traversal & Local File Inclusion (LFI) Signatures
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%2e%2e/",
    r"\.\.%2f",
    r"%2e%2e%5c",
    r"/etc/passwd",
    r"/etc/shadow",
    r"c:[\\/]windows",
    r"boot\.ini",
    r"win\.ini",
]
PATH_TRAVERSAL_REGEX = re.compile("|".join(PATH_TRAVERSAL_PATTERNS), re.IGNORECASE)


def detect_sqli(request):
    """Detect SQL injection attempts across URL path, GET params, and POST body."""
    if isinstance(request, str):
        return bool(SQLI_REGEX.search(request) or SQLI_REGEX.search(urllib.parse.unquote(request)))

    full_path = request.get_full_path() if hasattr(request, 'get_full_path') else str(request)
    if SQLI_REGEX.search(full_path) or SQLI_REGEX.search(urllib.parse.unquote(full_path)):
        return True

    if hasattr(request, 'GET'):
        for key, value in request.GET.items():
            val_str = str(value)
            key_str = str(key)
            if (
                SQLI_REGEX.search(val_str) or
                SQLI_REGEX.search(urllib.parse.unquote(val_str)) or
                SQLI_REGEX.search(key_str) or
                SQLI_REGEX.search(urllib.parse.unquote(key_str))
            ):
                return True

    if getattr(request, 'method', 'GET') == 'POST':
        if hasattr(request, 'POST'):
            for key, value in request.POST.items():
                if key in ('csrfmiddlewaretoken', 'password'):
                    continue
                val_str = str(value)
                if SQLI_REGEX.search(val_str) or SQLI_REGEX.search(urllib.parse.unquote(val_str)):
                    return True

        # Support JSON / raw request bodies
        try:
            if getattr(request, 'body', None):
                body_text = request.body.decode('utf-8', errors='ignore')
                if SQLI_REGEX.search(body_text) or SQLI_REGEX.search(urllib.parse.unquote(body_text)):
                    return True
        except Exception:
            pass

    return False


def detect_xss(request):
    """Detect Cross-Site Scripting (XSS) attempts across URL path, GET params, POST body, and JSON payloads."""
    if isinstance(request, str):
        return bool(XSS_REGEX.search(request) or XSS_REGEX.search(urllib.parse.unquote(request)))

    full_path = request.get_full_path() if hasattr(request, 'get_full_path') else str(request)
    if XSS_REGEX.search(full_path) or XSS_REGEX.search(urllib.parse.unquote(full_path)):
        return True

    if hasattr(request, 'GET'):
        for key, value in request.GET.items():
            val_str = str(value)
            key_str = str(key)
            if (
                XSS_REGEX.search(val_str) or
                XSS_REGEX.search(urllib.parse.unquote(val_str)) or
                XSS_REGEX.search(key_str) or
                XSS_REGEX.search(urllib.parse.unquote(key_str))
            ):
                return True

    if getattr(request, 'method', 'GET') == 'POST':
        if hasattr(request, 'POST'):
            for key, value in request.POST.items():
                if key in ('csrfmiddlewaretoken', 'password'):
                    continue
                val_str = str(value)
                if XSS_REGEX.search(val_str) or XSS_REGEX.search(urllib.parse.unquote(val_str)):
                    return True

        # Support JSON / raw request bodies
        try:
            if getattr(request, 'body', None):
                body_text = request.body.decode('utf-8', errors='ignore')
                if XSS_REGEX.search(body_text) or XSS_REGEX.search(urllib.parse.unquote(body_text)):
                    return True
        except Exception:
            pass

    return False


def detect_path_traversal(request):
    """Detect Path Traversal / Local File Inclusion (LFI) attempts."""
    if isinstance(request, str):
        return bool(PATH_TRAVERSAL_REGEX.search(request) or PATH_TRAVERSAL_REGEX.search(urllib.parse.unquote(request)))

    full_path = request.get_full_path() if hasattr(request, 'get_full_path') else str(request)
    if PATH_TRAVERSAL_REGEX.search(full_path) or PATH_TRAVERSAL_REGEX.search(urllib.parse.unquote(full_path)):
        return True

    if hasattr(request, 'GET'):
        for key, value in request.GET.items():
            val_str = str(value)
            if PATH_TRAVERSAL_REGEX.search(val_str) or PATH_TRAVERSAL_REGEX.search(urllib.parse.unquote(val_str)):
                return True

    if getattr(request, 'method', 'GET') == 'POST':
        if hasattr(request, 'POST'):
            for key, value in request.POST.items():
                if key in ('csrfmiddlewaretoken', 'password'):
                    continue
                val_str = str(value)
                if PATH_TRAVERSAL_REGEX.search(val_str) or PATH_TRAVERSAL_REGEX.search(urllib.parse.unquote(val_str)):
                    return True

        try:
            if request.body:
                body_text = request.body.decode('utf-8', errors='ignore')
                if PATH_TRAVERSAL_REGEX.search(body_text) or PATH_TRAVERSAL_REGEX.search(urllib.parse.unquote(body_text)):
                    return True
        except Exception:
            pass

    return False


RECON_TIME_WINDOW_MINUTES = 2
RECON_UNIQUE_PATH_THRESHOLD = 8
RECON_404_THRESHOLD = 4


def detect_recon(request_log_model, ip, window_minutes=RECON_TIME_WINDOW_MINUTES):
    """
    Detect scanning / reconnaissance based on unique paths probed and 404 counts.
    Checks thread-safe in-memory sliding window cache first (<0.05ms) before falling back to ORM.
    """
    # 1. Fast path: sliding window cache check
    if GLOBAL_TELEMETRY_CACHE.is_recon_detected(
        ip,
        window_seconds=window_minutes * 60.0,
        unique_path_thresh=RECON_UNIQUE_PATH_THRESHOLD,
        not_found_thresh=RECON_404_THRESHOLD
    ):
        return True

    # 2. Fallback to database queries for cold cache or direct model queries
    window_start = timezone.now() - timedelta(minutes=window_minutes)
    recent_logs = request_log_model.objects.filter(
        ip_address=ip,
        timestamp__gte=window_start
    )

    unique_paths = recent_logs.values('path').distinct().count()
    not_found_count = recent_logs.filter(status_code=404).count()

    if unique_paths >= RECON_UNIQUE_PATH_THRESHOLD:
        return True
    if not_found_count >= RECON_404_THRESHOLD:
        return True

    return False


def calculate_entropy(text):
    """Calculate the Shannon Entropy of a string to detect encoded or high-randomness payloads."""
    if not text:
        return 0.0
    freqs = Counter(text)
    total_len = len(text)
    entropy = -sum((count / total_len) * math.log2(count / total_len) for count in freqs.values())
    return round(entropy, 3)


def calculate_request_rate(request_log_model, ip, window_minutes=1):
    """
    Calculate requests per minute for an entity.
    Uses in-memory sliding window cache when populated; falls back to ORM count.
    """
    cached_rate = GLOBAL_TELEMETRY_CACHE.get_request_rate(ip, window_seconds=window_minutes * 60.0)
    if cached_rate > 0:
        return float(cached_rate)

    window_start = timezone.now() - timedelta(minutes=window_minutes)
    count = request_log_model.objects.filter(
        ip_address=ip,
        timestamp__gte=window_start
    ).count()
    return float(count)


# -------------------------------------------------------------
# 5. Known Search Crawler Verification (Canary Protection)
# -------------------------------------------------------------
KNOWN_CRAWLER_SUBSTRINGS = [
    'googlebot', 'bingbot', 'yandexbot', 'duckduckbot', 'baiduspider',
    'slurp', 'sogou', 'exabot', 'facebot', 'ia_archiver'
]

def is_known_search_crawler(user_agent: str) -> bool:
    """
    Check if a User-Agent matches known legitimate search indexer crawlers.
    Prevents false-positive automatic quarantine of search engines.
    """
    if not user_agent:
        return False
    ua_lower = user_agent.lower()
    return any(crawler in ua_lower for crawler in KNOWN_CRAWLER_SUBSTRINGS)


# -------------------------------------------------------------
# 4. MITRE ATT&CK® Enterprise Taxonomy Mapping
# -------------------------------------------------------------
MITRE_ATTACK_MAPPING = {
    'Recon': {
        'id': 'T1595',
        'sub_id': 'T1595.002',
        'name': 'Active Scanning: Wordlist & Path Probing',
        'tactic': 'Reconnaissance',
        'severity': 'MEDIUM',
        'description': 'Adversary scans endpoints looking for exposed assets, hidden admin panels, and debug endpoints.',
    },
    'Brute Force': {
        'id': 'T1110',
        'sub_id': 'T1110.001',
        'name': 'Brute Force: Password Guessing & Stuffing',
        'tactic': 'Credential Access',
        'severity': 'HIGH',
        'description': 'Adversary attempts to gain unauthorized access by systematically testing passwords or credential lists.',
    },
    'SQL Injection': {
        'id': 'T1190',
        'sub_id': 'T1190.001',
        'name': 'Exploit Public-Facing Application: SQL Injection',
        'tactic': 'Initial Access',
        'severity': 'CRITICAL',
        'description': 'Adversary injects malicious database query statements to bypass auth or dump database records.',
    },
    'XSS': {
        'id': 'T1059',
        'sub_id': 'T1059.007',
        'name': 'Command and Scripting: JavaScript Injection (XSS)',
        'tactic': 'Execution',
        'severity': 'HIGH',
        'description': 'Adversary injects malicious script payloads into web parameters to execute client-side attacks.',
    },
    'Path Traversal': {
        'id': 'T1005',
        'sub_id': 'T1083',
        'name': 'Data from Local System / Path Traversal (LFI)',
        'tactic': 'Collection',
        'severity': 'CRITICAL',
        'description': 'Adversary uses directory escape sequences to read sensitive server configuration and system credentials.',
    },
    'Honeypot Decoy': {
        'id': 'T1595',
        'sub_id': 'T1083',
        'name': 'Canary Token & Decoy Honeypot Interception',
        'tactic': 'Reconnaissance',
        'severity': 'CRITICAL',
        'description': 'Automated bot scraper hit a zero-traffic canary endpoint, proving automated adversarial intent.',
    },
    'DDoS': {
        'id': 'T1498',
        'sub_id': 'T1498.001',
        'name': 'Network Denial of Service: Direct Volume Flood',
        'tactic': 'Impact',
        'severity': 'CRITICAL',
        'description': 'Adversary executes high packet-rate volumetric floods targeting network endpoints to saturate bandwidth and cause service outages.',
    },
    'Ransomware': {
        'id': 'T1486',
        'sub_id': 'T1048',
        'name': 'Data Encrypted for Impact & Exfiltration Over C2',
        'tactic': 'Impact',
        'severity': 'CRITICAL',
        'description': 'Adversary establishes command-and-control connection, encrypting critical file vaults and exfiltrating sensitive sub-flow payloads.',
    },
}

HONEYPOT_PATHS = {
    '/.env',
    '/backup.sql',
    '/.git/config',
    '/wp-login.php',
    '/api/v1/internal/config',
    '/phpmyadmin/',
    '/.aws/credentials',
    '/actuator/health',
}


def parse_device_info(user_agent: str) -> dict:
    """
    Parse a User-Agent string to extract precise Device Model, OS, Browser, and Icon.
    Supports all mobile manufacturers, tablets, workstations, and security attack engines.
    """
    if not user_agent:
        return {
            'device_name': 'Unknown Node',
            'device_type': 'Network Client',
            'os': 'Unknown OS',
            'browser': 'Direct Connection',
            'icon': 'fa-solid fa-microchip',
            'badge': '🛰️ Unknown Device',
            'display': 'Unknown Device &bull; Web Client'
        }

    ua = user_agent.lower()

    # 1. Specialized Attack Tools & CLI Engines
    if 'hydra' in ua:
        device_name = 'THC-Hydra Brute-Forcer'
        device_type = 'Adversary Tool'
        os_name = 'Security Tool'
        icon = 'fa-solid fa-key'
        badge = '⚡ THC-Hydra Cracker'
    elif 'sqlmap' in ua:
        device_name = 'sqlmap Attack Engine'
        device_type = 'Adversary Tool'
        os_name = 'Security Tool'
        icon = 'fa-solid fa-bug'
        badge = '👾 sqlmap Injection Tool'
    elif 'burp' in ua or 'burpsuite' in ua:
        device_name = 'Burp Suite Proxy'
        device_type = 'Adversary Tool'
        os_name = 'Security Tool'
        icon = 'fa-solid fa-shield-virus'
        badge = '🛡️ Burp Suite'
    elif 'dirbuster' in ua or 'gobuster' in ua or 'ffuf' in ua:
        device_name = 'Directory Fuzzing Scanner'
        device_type = 'Scanner'
        os_name = 'CLI Tool'
        icon = 'fa-solid fa-radar'
        badge = '🔍 Web Fuzz Scanner'
    elif 'nikto' in ua:
        device_name = 'Nikto Vulnerability Scanner'
        device_type = 'Scanner'
        os_name = 'CLI Tool'
        icon = 'fa-solid fa-satellite-dish'
        badge = '📡 Nikto Scanner'
    elif 'nmap' in ua:
        device_name = 'Nmap Security Scanner'
        device_type = 'Scanner'
        os_name = 'CLI Tool'
        icon = 'fa-solid fa-crosshairs'
        badge = '🎯 Nmap Scanner'
    elif 'metasploit' in ua:
        device_name = 'Metasploit Framework'
        device_type = 'Adversary Tool'
        os_name = 'Exploit Engine'
        icon = 'fa-solid fa-skull'
        badge = '☠️ Metasploit Node'
    elif 'curl' in ua:
        device_name = 'cURL HTTP Utility'
        device_type = 'CLI Client'
        os_name = 'Terminal'
        icon = 'fa-solid fa-terminal'
        badge = '💻 cURL CLI'
    elif 'postman' in ua:
        device_name = 'Postman API Client'
        device_type = 'API Tool'
        os_name = 'Developer Tool'
        icon = 'fa-solid fa-paper-plane'
        badge = '🚀 Postman Client'
    elif 'python-requests' in ua or 'python' in ua or 'httpclient' in ua:
        device_name = 'Python Automated Script'
        device_type = 'Script Bot'
        os_name = 'Python Runtime'
        icon = 'fa-brands fa-python'
        badge = '🐍 Python Script / Bot'
    # 2. Apple Devices
    elif 'iphone' in ua:
        device_name = 'Apple iPhone'
        device_type = 'Mobile'
        os_name = 'iOS'
        icon = 'fa-brands fa-apple'
        badge = '📱 iPhone'
    elif 'ipad' in ua:
        device_name = 'Apple iPad'
        device_type = 'Tablet'
        os_name = 'iPadOS'
        icon = 'fa-brands fa-apple'
        badge = '📱 iPad'
    elif 'macintosh' in ua or 'mac os x' in ua:
        device_name = 'Apple Mac'
        device_type = 'Desktop'
        os_name = 'macOS'
        icon = 'fa-brands fa-apple'
        badge = '💻 Mac'
    # 3. Android Mobile Brand Specifics
    elif 'android' in ua:
        device_type = 'Mobile'
        os_name = 'Android'
        icon = 'fa-brands fa-android'
        if 'samsung' in ua or 'sm-' in ua:
            device_name = 'Samsung Galaxy'
            badge = '📱 Samsung Galaxy'
        elif 'pixel' in ua:
            device_name = 'Google Pixel'
            badge = '📱 Google Pixel'
        elif 'xiaomi' in ua or 'redmi' in ua or 'mi ' in ua or 'poco' in ua:
            device_name = 'Xiaomi / Redmi'
            badge = '📱 Xiaomi / Redmi'
        elif 'oneplus' in ua:
            device_name = 'OnePlus Smartphone'
            badge = '📱 OnePlus Phone'
        elif 'vivo' in ua:
            device_name = 'Vivo Smartphone'
            badge = '📱 Vivo Mobile'
        elif 'oppo' in ua:
            device_name = 'Oppo Smartphone'
            badge = '📱 Oppo Mobile'
        elif 'realme' in ua:
            device_name = 'Realme Smartphone'
            badge = '📱 Realme Mobile'
        elif 'motorola' in ua or 'moto' in ua:
            device_name = 'Motorola Smartphone'
            badge = '📱 Moto Mobile'
        else:
            device_name = 'Android Smartphone'
            badge = '🤖 Android Phone'
    # 4. Windows
    elif 'windows nt 10.0' in ua or 'windows' in ua:
        device_name = 'Windows PC'
        device_type = 'Desktop'
        os_name = 'Windows 10/11'
        icon = 'fa-brands fa-windows'
        badge = '💻 Windows PC'
    # 5. Linux Distributions
    elif 'kali' in ua:
        device_name = 'Kali Linux PenTest Node'
        device_type = 'Security Station'
        os_name = 'Kali Linux'
        icon = 'fa-brands fa-linux'
        badge = '🐉 Kali Linux'
    elif 'ubuntu' in ua:
        device_name = 'Ubuntu Linux'
        device_type = 'Desktop'
        os_name = 'Ubuntu'
        icon = 'fa-brands fa-ubuntu'
        badge = '🐧 Ubuntu Linux'
    elif 'arch' in ua:
        device_name = 'Arch Linux'
        device_type = 'Desktop'
        os_name = 'Arch'
        icon = 'fa-brands fa-linux'
        badge = '🐧 Arch Linux'
    elif 'linux' in ua:
        device_name = 'Linux Station'
        device_type = 'Desktop'
        os_name = 'Linux'
        icon = 'fa-brands fa-linux'
        badge = '🐧 Linux Machine'
    else:
        device_name = 'Network Workstation'
        device_type = 'Client'
        os_name = 'Client Node'
        icon = 'fa-solid fa-laptop'
        badge = '💻 Client Station'

    # Browser Detection
    if 'edg/' in ua or 'edge/' in ua:
        browser = 'Microsoft Edge'
    elif 'chrome' in ua and 'safari' in ua and 'edg' not in ua and 'samsung' not in ua:
        browser = 'Google Chrome'
    elif 'safari' in ua and 'chrome' not in ua:
        browser = 'Apple Safari'
    elif 'firefox' in ua:
        browser = 'Mozilla Firefox'
    elif 'samsungbrowser' in ua:
        browser = 'Samsung Internet'
    elif 'opera' in ua or 'opr/' in ua:
        browser = 'Opera'
    elif 'brave' in ua:
        browser = 'Brave'
    elif 'curl' in ua:
        browser = 'cURL CLI'
    elif 'postman' in ua:
        browser = 'Postman Client'
    elif 'python' in ua:
        browser = 'Python HTTP'
    else:
        browser = 'Web Client'

    return {
        'device_name': device_name,
        'device_type': device_type,
        'os': os_name,
        'browser': browser,
        'icon': icon,
        'badge': badge,
        'display': f"{badge} &bull; {browser}"
    }