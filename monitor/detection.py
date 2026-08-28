import re
import math
from collections import Counter
from datetime import timedelta
from django.utils import timezone

# 1. SQL Injection Signatures
SQLI_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
    r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
    r"((\%27)|(\'))union",
    r"union.*select",
    r"select.*from",
    r"insert\s+into",
    r"drop\s+table",
    r"or\s+1\s*=\s*1",
    r"or\s+['\"]\w+['\"]\s*=\s*['\"]\w+['\"]",
    r"admin'\s*--",
    r"';",
]
SQLI_REGEX = re.compile("|".join(SQLI_PATTERNS), re.IGNORECASE)

# 2. Cross-Site Scripting (XSS) Signatures
XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"<script[^>]*>",
    r"javascript\s*:",
    r"onerror\s*=",
    r"onload\s*=",
    r"onclick\s*=",
    r"<img[^>]+src[^\w]*=[^\w]*[\"']?javascript:",
    r"<iframe[^>]*>",
    r"document\.cookie",
    r"alert\s*\(",
    r"eval\s*\(",
    r"window\.location",
    r"svg/onload",
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
    full_path = request.get_full_path()
    if SQLI_REGEX.search(full_path):
        return True

    for value in request.GET.values():
        if SQLI_REGEX.search(str(value)):
            return True

    if request.method == 'POST':
        for key, value in request.POST.items():
            if key in ('csrfmiddlewaretoken', 'password'):
                continue
            if SQLI_REGEX.search(str(value)):
                return True

    return False


def detect_xss(request):
    """Detect Cross-Site Scripting (XSS) attempts across URL path, GET params, and POST body."""
    full_path = request.get_full_path()
    if XSS_REGEX.search(full_path):
        return True

    for value in request.GET.values():
        if XSS_REGEX.search(str(value)):
            return True

    if request.method == 'POST':
        for key, value in request.POST.items():
            if key in ('csrfmiddlewaretoken', 'password'):
                continue
            if XSS_REGEX.search(str(value)):
                return True

    return False


def detect_path_traversal(request):
    """Detect Path Traversal / Local File Inclusion (LFI) attempts."""
    full_path = request.get_full_path()
    if PATH_TRAVERSAL_REGEX.search(full_path):
        return True

    for value in request.GET.values():
        if PATH_TRAVERSAL_REGEX.search(str(value)):
            return True

    if request.method == 'POST':
        for key, value in request.POST.items():
            if key in ('csrfmiddlewaretoken', 'password'):
                continue
            if PATH_TRAVERSAL_REGEX.search(str(value)):
                return True

    return False


RECON_TIME_WINDOW_MINUTES = 2
RECON_UNIQUE_PATH_THRESHOLD = 8
RECON_404_THRESHOLD = 4


def detect_recon(request_log_model, ip, window_minutes=RECON_TIME_WINDOW_MINUTES):
    """Detect scanning / reconnaissance based on unique paths probed and 404 counts."""
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
    """Calculate requests per minute for an entity."""
    window_start = timezone.now() - timedelta(minutes=window_minutes)
    count = request_log_model.objects.filter(
        ip_address=ip,
        timestamp__gte=window_start
    ).count()
    return float(count)


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