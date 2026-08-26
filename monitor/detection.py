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