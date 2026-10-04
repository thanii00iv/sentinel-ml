"""
Universal Batch Log & Telemetry Ingestion Engine for CyberOracle Intel
Parses external web access logs across all major industry formats:
- Nginx / Apache Combined Log Format (CLF) & Common Log Format
- JSON Lines (.jsonl) and JSON Array Telemetry (AWS CloudWatch, Suricata, Zeek, ELK)
- Tabular CSV, TSV, and Delimited Formats (, / ; / \t / |)
- Microsoft IIS / W3C Log Format
- Syslog-prefixed Web Server Logs
- Bare URL / Direct Attack Payload streams
"""

import re
import csv
import io
import json
import time
import urllib.parse
from django.utils import timezone
from .models import RequestLog, IPRiskProfile
from .detection import (
    SQLI_REGEX,
    XSS_REGEX,
    PATH_TRAVERSAL_REGEX,
    HONEYPOT_PATHS,
    calculate_entropy,
)
from .fusion_engine import evaluate_and_fuse_profile, infer_event_intent

# Combined Log Format / Common Log Format Regex
CLF_REGEX = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]{3,7})\s+(\S+)(?:\s+\S+)?"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?',
    re.IGNORECASE
)

# Simpler space-delimited fallback: IP METHOD PATH [STATUS]
SIMPLE_LOG_REGEX = re.compile(
    r'^(\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+)\s+([A-Z]{3,7})\s+(\S+)(?:\s+(\d{3}))?',
    re.IGNORECASE
)

# Syslog Prefix (e.g., "Oct  4 10:15:32 server01 nginx[1234]: ")
SYSLOG_PREFIX_REGEX = re.compile(
    r'^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+[\w.-]+\s+[\w.-]+(?:\[\d+\])?:\s*',
    re.IGNORECASE
)

# Generic Regexes for Fuzzy Log Extraction
IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
METHOD_REGEX = re.compile(r'\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b', re.IGNORECASE)
PATH_REGEX = re.compile(r'(/(?:[a-zA-Z0-9_\-.~%!$&\'()*+,;=:@/?#]|%[0-9a-fA-F]{2})*)')
STATUS_REGEX = re.compile(r'\b([1-5]\d{2})\b')


def extract_entry_from_dict(d):
    """Normalize dictionary/JSON fields into standard telemetry entry."""
    ip = (
        d.get('ip_address') or d.get('ip') or d.get('client_ip') or
        d.get('src_ip') or d.get('source_ip') or d.get('remote_addr') or
        d.get('c-ip') or '198.51.100.99'
    )
    method = (
        d.get('method') or d.get('http_method') or d.get('cs-method') or 'GET'
    ).strip().upper()

    stem = d.get('cs-uri-stem') or ''
    query = d.get('cs-uri-query') or ''
    if stem:
        path = stem + ('?' + query if query and query != '-' else '')
    else:
        path = (
            d.get('path') or d.get('url') or d.get('request_uri') or
            d.get('uri') or d.get('endpoint') or '/'
        ).strip()

    try:
        status_code = int(d.get('status_code') or d.get('status') or d.get('sc-status') or 200)
    except (ValueError, TypeError):
        status_code = 200

    ua = (
        d.get('user_agent') or d.get('agent') or d.get('cs(User-Agent)') or
        d.get('http_user_agent') or 'Custom Batch Telemetry Ingestion Agent'
    )
    user = (d.get('username') or d.get('user') or d.get('cs-username') or None)
    if user == '-': user = None

    return {
        'ip': str(ip).strip(),
        'method': method,
        'path': path,
        'status_code': status_code,
        'user_agent': str(ua).strip(),
        'username': user
    }


def parse_and_ingest_content(raw_text, auto_quarantine=True, max_records=1000):
    """
    Parse raw string content across all formats (CLF, JSON, CSV, W3C, Syslog)
    and ingest into CyberOracle Intel.
    """
    start_time = time.time()
    stripped_text = raw_text.strip()
    if not stripped_text:
        return {'status': 'ERROR', 'message': 'No valid log content provided.'}

    lines = [line.strip() for line in stripped_text.splitlines() if line.strip()]
    if not lines:
        return {'status': 'ERROR', 'message': 'Empty log content.'}

    if len(lines) > max_records:
        lines = lines[:max_records]

    parsed_entries = []

    # -------------------------------------------------------------
    # 1. Format Detection: JSON Array (e.g. [{"ip": ...}])
    # -------------------------------------------------------------
    if stripped_text.startswith('[') and stripped_text.endswith(']'):
        try:
            items = json.loads(stripped_text)
            if isinstance(items, list):
                for item in items[:max_records]:
                    if isinstance(item, dict):
                        parsed_entries.append(extract_entry_from_dict(item))
        except Exception:
            pass

    # -------------------------------------------------------------
    # 2. Format Detection: JSON Lines (e.g. {"ip": ...}\n{"ip": ...})
    # -------------------------------------------------------------
    if not parsed_entries and lines[0].startswith('{') and lines[0].endswith('}'):
        for line in lines:
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    parsed_entries.append(extract_entry_from_dict(item))
            except Exception:
                continue

    # -------------------------------------------------------------
    # 3. Format Detection: CSV / TSV / Semicolon Delimited
    # -------------------------------------------------------------
    if not parsed_entries:
        first_line = lines[0].lower()
        # Detect delimiter
        delimiter = None
        for delim in [',', '\t', ';', '|']:
            if delim in first_line and any(k in first_line for k in ['ip', 'path', 'url', 'uri', 'method', 'status']):
                delimiter = delim
                break

        if delimiter:
            reader = csv.DictReader(io.StringIO(raw_text), delimiter=delimiter)
            for row in reader:
                if row:
                    parsed_entries.append(extract_entry_from_dict(row))

    # -------------------------------------------------------------
    # 4. Format Detection: Microsoft IIS / W3C Log with #Fields
    # -------------------------------------------------------------
    if not parsed_entries and any(l.startswith('#Fields:') for l in lines[:10]):
        fields_header = None
        for line in lines:
            if line.startswith('#Fields:'):
                fields_header = line.replace('#Fields:', '').strip().split()
                continue
            if line.startswith('#') or not fields_header:
                continue
            parts = line.split()
            if len(parts) == len(fields_header):
                row_dict = dict(zip(fields_header, parts))
                parsed_entries.append(extract_entry_from_dict(row_dict))

    # -------------------------------------------------------------
    # 5. Format Detection: CLF, Syslog, Space-Delimited & Fuzzy Fallback
    # -------------------------------------------------------------
    if not parsed_entries:
        for line in lines:
            # Skip comments
            if line.startswith('#'):
                continue

            # Strip Syslog prefix if present
            clean_line = SYSLOG_PREFIX_REGEX.sub('', line)

            # Combined Log Format Match
            clf_match = CLF_REGEX.match(clean_line)
            if clf_match:
                ip, ts_str, method, path, status, bytes_sent, referer, ua = clf_match.groups()
                try:
                    status_code = int(status)
                except (ValueError, TypeError):
                    status_code = 200
                parsed_entries.append({
                    'ip': ip,
                    'method': method.upper(),
                    'path': path,
                    'status_code': status_code,
                    'user_agent': ua or 'Web Client Ingestion',
                    'username': None
                })
                continue

            # Simple space-delimited match: IP METHOD PATH [STATUS]
            simple_match = SIMPLE_LOG_REGEX.match(clean_line)
            if simple_match:
                ip, method, path, status = simple_match.groups()
                status_code = int(status) if status else 200
                parsed_entries.append({
                    'ip': ip,
                    'method': method.upper(),
                    'path': path,
                    'status_code': status_code,
                    'user_agent': 'Raw Telemetry Ingestion Node',
                    'username': None
                })
                continue

            # Bare URL fallback (e.g. /search/?q=<script>alert(1)</script>)
            if clean_line.startswith('/') or clean_line.startswith('http'):
                clean_path = clean_line if clean_line.startswith('/') else '/' + clean_line.split('/', 3)[-1]
                parsed_entries.append({
                    'ip': '198.51.100.75',
                    'method': 'GET',
                    'path': clean_path,
                    'status_code': 200,
                    'user_agent': 'Direct URL Probe Ingestion',
                    'username': None
                })
                continue

            # Universal Fuzzy Heuristic Extractor Fallback
            # Extracts IP, Method, Path, and Status from unstructured log lines
            ip_m = IP_REGEX.search(clean_line)
            method_m = METHOD_REGEX.search(clean_line)
            path_m = PATH_REGEX.search(clean_line)
            status_m = STATUS_REGEX.search(clean_line)

            if path_m:
                parsed_entries.append({
                    'ip': ip_m.group(0) if ip_m else '198.51.100.99',
                    'method': method_m.group(0).upper() if method_m else 'GET',
                    'path': path_m.group(0),
                    'status_code': int(status_m.group(0)) if status_m else 200,
                    'user_agent': 'Heuristic Extracted Log Entry',
                    'username': None
                })

    if not parsed_entries:
        return {'status': 'ERROR', 'message': 'Unable to parse recognized log format. Please check file format.'}

    # -------------------------------------------------------------
    # 6. Run ICMF Pipeline on Extracted Telemetry
    # -------------------------------------------------------------
    threat_counts = {
        'sqli': 0,
        'xss': 0,
        'path_traversal': 0,
        'recon': 0,
        'brute_force': 0,
        'honeypot': 0,
    }
    flagged_logs = []
    affected_ips = set()
    quarantined_ips = set()
    logs_created = 0

    for entry in parsed_entries:
        ip = entry['ip']
        path = entry['path']
        method = entry['method']
        status = entry['status_code']
        ua = entry['user_agent']
        user = entry['username']
        unquoted_path = urllib.parse.unquote(path)

        # 1. Signature Scanning
        is_sqli = bool(SQLI_REGEX.search(path) or SQLI_REGEX.search(unquoted_path))
        is_xss = bool(XSS_REGEX.search(path) or XSS_REGEX.search(unquoted_path))
        is_lfi = bool(PATH_TRAVERSAL_REGEX.search(path) or PATH_TRAVERSAL_REGEX.search(unquoted_path))

        # Honeypot & Recon check
        clean_route = path.split('?')[0]
        is_honeypot = (clean_route in HONEYPOT_PATHS or any(p in clean_route for p in ['/.env', '/backup.sql', '/wp-login.php']))
        is_recon = is_honeypot or (status == 404)

        # Brute-force check
        is_login = '/login' in clean_route or '/admin' in clean_route
        is_brute = (is_login and method == 'POST') or (is_login and status in (401, 403))

        # Tally metrics
        if is_sqli: threat_counts['sqli'] += 1
        if is_xss: threat_counts['xss'] += 1
        if is_lfi: threat_counts['path_traversal'] += 1
        if is_recon: threat_counts['recon'] += 1
        if is_brute: threat_counts['brute_force'] += 1
        if is_honeypot: threat_counts['honeypot'] += 1

        is_attack = is_sqli or is_xss or is_lfi or is_recon or is_brute or is_honeypot

        # Entropy & Rate calculations
        entropy = calculate_entropy(path)
        rate = 15.0 if is_attack else 2.0

        # Construct and infer intent
        temp_log = RequestLog(
            ip_address=ip,
            method=method,
            path=path[:500],
            status_code=status,
            username=user,
            is_login_attempt=is_login,
            login_success=False if is_login and status != 200 else (True if is_login else None),
            is_brute_force_suspect=is_brute,
            is_sqli_suspect=is_sqli,
            is_recon_suspect=is_recon,
            is_xss_suspect=is_xss,
            is_path_traversal_suspect=is_lfi,
            entropy_score=entropy,
            request_rate=rate,
        )
        inferred = infer_event_intent(temp_log)
        if is_honeypot:
            inferred = "Canary Honeypot Decoy Trap Triggered"

        log_obj = RequestLog.objects.create(
            ip_address=ip,
            method=method,
            path=path[:500],
            status_code=status,
            user_agent=ua[:500],
            response_time_ms=18.5 if not is_attack else 125.0,
            username=user,
            query_params=path.split('?', 1)[1][:500] if '?' in path else "",
            is_login_attempt=is_login,
            login_success=False if is_login and status != 200 else (True if is_login else None),
            is_brute_force_suspect=is_brute,
            is_sqli_suspect=is_sqli,
            is_recon_suspect=is_recon,
            is_xss_suspect=is_xss,
            is_path_traversal_suspect=is_lfi,
            inferred_intent=inferred,
            entropy_score=entropy,
            request_rate=rate,
        )
        logs_created += 1

        # Update entity profile
        profile, _ = IPRiskProfile.objects.get_or_create(ip_address=ip)
        if is_sqli: profile.sqli_count += 1
        if is_xss: profile.xss_count += 1
        if is_lfi: profile.path_traversal_count += 1
        if is_recon: profile.recon_count += 1
        if is_brute: profile.brute_force_count += 1
        if is_honeypot: profile.recon_count += 3

        # Run ICMF Multi-View Fusion on the profile
        evaluate_and_fuse_profile(profile, latest_log=log_obj)

        if is_attack:
            affected_ips.add(ip)
            if len(flagged_logs) < 20:
                flagged_logs.append(log_obj)

        # Enforce quarantine if threshold reached
        if auto_quarantine and profile.risk_score >= 70:
            if not profile.is_blocked:
                profile.is_blocked = True
                profile.save()
            quarantined_ips.add(ip)

    elapsed_time = round((time.time() - start_time) * 1000, 2)
    total_threats = sum(threat_counts.values())

    # Get updated profile objects for affected IPs
    top_profiles = list(
        IPRiskProfile.objects.filter(ip_address__in=affected_ips).order_by('-risk_score')[:10]
    )

    return {
        'status': 'SUCCESS',
        'total_parsed': len(parsed_entries),
        'logs_created': logs_created,
        'total_threats': total_threats,
        'threat_breakdown': threat_counts,
        'affected_ips_count': len(affected_ips),
        'quarantined_count': len(quarantined_ips),
        'quarantined_ips': list(quarantined_ips),
        'top_profiles': top_profiles,
        'flagged_logs': flagged_logs,
        'elapsed_ms': elapsed_time,
    }


def get_sample_access_log():
    """Generate a realistic sample Apache/Nginx web server access log with blended attacks."""
    return """192.168.1.10 - - [04/Oct/2026:10:01:05 +0000] "GET / HTTP/1.1" 200 4520 "https://google.com" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
198.51.100.44 - - [04/Oct/2026:10:01:12 +0000] "GET /api/search/?q=' UNION SELECT id, username, password FROM auth_user -- HTTP/1.1" 200 892 "-" "sqlmap/1.7.2#stable"
198.51.100.44 - - [04/Oct/2026:10:01:15 +0000] "POST /login/?user=admin' OR 1=1 -- HTTP/1.1" 500 240 "-" "sqlmap/1.7.2#stable"
192.168.1.15 - - [04/Oct/2026:10:02:00 +0000] "GET /dashboard/ HTTP/1.1" 200 12500 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
203.0.113.120 - - [04/Oct/2026:10:02:18 +0000] "GET /search/?q=%3Cscript%3Ealert('DOM_XSS')%3C%2Fscript%3E HTTP/1.1" 200 1150 "-" "Mozilla/5.0 (X11; Linux x86_64)"
203.0.113.120 - - [04/Oct/2026:10:02:22 +0000] "GET /products/?view=%3Cimg%20src=x%20onerror=alert(1)%3E HTTP/1.1" 200 1020 "-" "Mozilla/5.0 (X11; Linux x86_64)"
198.51.100.99 - - [04/Oct/2026:10:03:01 +0000] "GET /.env HTTP/1.1" 403 520 "-" "masscan/1.3.2"
198.51.100.99 - - [04/Oct/2026:10:03:04 +0000] "GET /backup.sql HTTP/1.1" 403 520 "-" "masscan/1.3.2"
198.51.100.99 - - [04/Oct/2026:10:03:07 +0000] "GET /wp-login.php HTTP/1.1" 403 520 "-" "masscan/1.3.2"
185.220.101.5 - - [04/Oct/2026:10:04:12 +0000] "GET /download/?file=../../../../etc/passwd HTTP/1.1" 200 2400 "-" "Nikto/2.1.6"
185.220.101.5 - - [04/Oct/2026:10:04:16 +0000] "GET /view/?doc=..%2f..%2fwindows%2fwin.ini HTTP/1.1" 200 1800 "-" "Nikto/2.1.6"
192.168.1.25 - - [04/Oct/2026:10:05:00 +0000] "GET /static/css/styles.css HTTP/1.1" 200 8420 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
"""


def get_sample_csv():
    """Generate a sample CSV telemetry export with multi-stage attack vectors."""
    return """ip_address,method,path,status_code,user_agent,username
192.168.1.50,GET,/landing/,200,Mozilla/5.0,
198.51.100.180,GET,/search/?q=' UNION SELECT 1,2,3 --,200,sqlmap/1.8,
198.51.100.180,POST,/login/,401,sqlmap/1.8,admin' OR '1'='1
203.0.113.77,GET,/forum/?thread=%3Cscript%3Ealert('XSS_DEMO')%3C%2Fscript%3E,200,Chrome/118,
203.0.113.77,GET,/profile/?user=%3Csvg%20onload=alert(1)%3E,200,Chrome/118,
185.190.22.4,GET,/.env,403,AutomatedScanner/2.0,
185.190.22.4,GET,/backup.sql,403,AutomatedScanner/2.0,
185.190.22.4,GET,/wp-login.php,403,AutomatedScanner/2.0,
185.190.22.4,GET,/server-status,404,AutomatedScanner/2.0,
192.0.2.14,GET,/view/?file=../../../../etc/passwd,200,Go-http-client/1.1,
192.0.2.14,GET,/download/?file=%2e%2e%2f%2e%2e%2fetc/shadow,403,Go-http-client/1.1,
192.168.1.50,GET,/dashboard/,200,Mozilla/5.0,
"""


def get_sample_json():
    """Generate sample JSON telemetry logs (e.g. AWS CloudWatch / Suricata / Zeek format)."""
    return json.dumps([
        {"ip": "192.168.1.10", "method": "GET", "path": "/dashboard/", "status_code": 200, "user_agent": "Mozilla/5.0"},
        {"ip": "198.51.100.88", "method": "GET", "path": "/search/?q=' UNION SELECT 1,2 --", "status_code": 200, "user_agent": "sqlmap/1.7"},
        {"ip": "203.0.113.44", "method": "GET", "path": "/view/?q=%3Cscript%3Ealert(1)%3C/script%3E", "status_code": 200, "user_agent": "Mozilla/5.0"},
        {"ip": "185.220.101.9", "method": "GET", "path": "/.env", "status_code": 403, "user_agent": "Masscan/1.0"},
        {"ip": "192.0.2.77", "method": "GET", "path": "/download/?file=../../../../etc/passwd", "status_code": 200, "user_agent": "Nikto/2.1"}
    ], indent=2)
