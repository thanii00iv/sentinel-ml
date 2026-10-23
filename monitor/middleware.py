import time
from datetime import timedelta
from django.utils import timezone
from django.utils.html import escape
from django.http import HttpResponseForbidden
from django.conf import settings
from .models import RequestLog, IPRiskProfile, EntityProfile
from .detection import (
    detect_sqli,
    detect_xss,
    detect_path_traversal,
    detect_recon,
    calculate_entropy,
    calculate_request_rate,
    GLOBAL_TELEMETRY_CACHE,
)
from .fusion_engine import evaluate_and_fuse_profile, infer_event_intent

FAILED_LOGIN_THRESHOLD = 5
TIME_WINDOW_MINUTES = 10


class RequestLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        client_ip = self.get_client_ip(request)
        whitelisted_ips = getattr(settings, 'WHITELISTED_IPS', {'127.0.0.1', '::1', 'localhost'})
        admin_allowlist = getattr(settings, 'ADMIN_ALLOWLIST', getattr(settings, 'ADMIN_IP_ALLOWLIST', set()))

        # -------------------------------------------------------------
        # 1. Automated Firewall Quarantine Enforcement
        # Exempt whitelisted IPs, static assets, toggle API, and explicit admin allowlist
        # -------------------------------------------------------------
        is_admin_path = request.path.startswith('/admin/')
        is_admin_allowed = is_admin_path and (client_ip in admin_allowlist or client_ip in whitelisted_ips)

        if (
            client_ip not in whitelisted_ips and
            not is_admin_allowed and
            not request.path.startswith('/static/') and
            not request.path.startswith('/api/toggle-block/')
        ):
            try:
                blocked_profile = IPRiskProfile.objects.filter(ip_address=client_ip, is_blocked=True).first()
                if blocked_profile:
                    is_xss_attempt = detect_xss(request)
                    is_sqli_attempt = detect_sqli(request)
                    is_path_attempt = detect_path_traversal(request)
                    
                    if is_xss_attempt:
                        blocked_profile.xss_count += 1
                        blocked_intent = "Quarantined IP Attack Intercepted (XSS)"
                    elif is_sqli_attempt:
                        blocked_profile.sqli_count += 1
                        blocked_intent = "Quarantined IP Attack Intercepted (SQLi)"
                    elif is_path_attempt:
                        blocked_profile.path_traversal_count += 1
                        blocked_intent = "Quarantined IP Attack Intercepted (Path Traversal)"
                    else:
                        blocked_intent = "Quarantined IP Request Intercepted"
                    blocked_profile.save()

                    RequestLog.objects.create(
                        ip_address=client_ip,
                        method=request.method,
                        path=request.path,
                        status_code=403,
                        user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
                        response_time_ms=2.0,
                        username=None,
                        query_params=request.META.get('QUERY_STRING', '')[:500],
                        is_sqli_suspect=is_sqli_attempt,
                        is_xss_suspect=is_xss_attempt,
                        is_path_traversal_suspect=is_path_attempt,
                        inferred_intent=blocked_intent,
                        entropy_score=calculate_entropy(request.get_full_path()),
                        request_rate=1.0,
                    )

                    escaped_ip = escape(client_ip)
                    escaped_risk = escape(str(blocked_profile.risk_score))

                    return HttpResponseForbidden(
                        f"""
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <title>403 Forbidden — CyberOracle Intel Cyber Quarantine</title>
                            <style>
                                body {{ font-family: system-ui, sans-serif; background: #060913; color: #f1f5f9; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 20px; box-sizing: border-box; }}
                                .card {{ background: #0d1526; border: 1px solid #ff4d6d; border-radius: 12px; padding: 2.5rem; max-width: 520px; text-align: center; box-shadow: 0 0 30px rgba(255, 77, 109, 0.25); }}
                                h1 {{ color: #ff4d6d; font-size: 1.5rem; margin-top: 0; }}
                                p {{ color: #94a3b8; font-size: 0.95rem; line-height: 1.6; }}
                                .badge {{ display: inline-block; background: rgba(255,77,109,0.15); color: #ff4d6d; border: 1px solid #ff4d6d; padding: 0.35rem 0.8rem; border-radius: 6px; font-weight: 700; font-family: monospace; font-size: 0.85rem; margin-bottom: 1rem; }}
                                .btn {{ display: inline-block; background: #0284c7; color: #fff; padding: 0.5rem 1rem; border-radius: 6px; text-decoration: none; font-weight: 600; font-size: 0.85rem; margin-top: 1rem; }}
                            </style>
                        </head>
                        <body>
                        <div class="card">
                                <div class="badge">ACCESS DENIED // IP QUARANTINED</div>
                                <h1>CyberOracle Intel Security Interception</h1>
                                <p>Your IP address (<strong>{escaped_ip}</strong>) has been quarantined due to critical risk scoring and autonomous threat hunting mitigation.</p>
                                <p style="font-size: 0.8rem; color: #64748b;">Risk Score: {escaped_risk}/100 &bull; Policy: Automated Threat Mitigation</p>
                            </div>
                        </body>
                        </html>
                        """
                    )
            except Exception:
                pass

        # -------------------------------------------------------------
        # 2. Telemetry Ingestion & Attack Signature Detections
        # -------------------------------------------------------------
        start_time = time.time()

        is_sqli_suspect = detect_sqli(request)
        is_xss_suspect = detect_xss(request)
        is_path_traversal_suspect = detect_path_traversal(request)

        response = self.get_response(request)

        duration_ms = (time.time() - start_time) * 1000

        # Login and Brute-force detection
        is_login_attempt = (request.path.rstrip('/') in ['/login', '/admin/login'] and request.method == 'POST')
        login_success = None
        is_brute_force_suspect = False
        attempted_username = None

        if is_login_attempt:
            # Capture attempted username from JSON body or standard form POST
            if request.content_type == 'application/json':
                try:
                    import json
                    body_data = json.loads(request.body.decode('utf-8'))
                    attempted_username = str(body_data.get('username', '')).strip() or None
                except Exception:
                    pass
            if not attempted_username and 'username' in request.POST:
                attempted_username = str(request.POST.get('username', '')).strip() or None

            login_success = request.user.is_authenticated
            if not login_success:
                window_start = timezone.now() - timedelta(minutes=TIME_WINDOW_MINUTES)
                recent_failures = RequestLog.objects.filter(
                    ip_address=client_ip,
                    is_login_attempt=True,
                    login_success=False,
                    timestamp__gte=window_start
                ).count()

                is_brute_force_suspect = True

        # Reconnaissance detection
        is_recon_suspect = detect_recon(RequestLog, client_ip)

        # Update in-memory sliding window cache for ultra-low overhead telemetry
        GLOBAL_TELEMETRY_CACHE.record_event(client_ip, request.path, response.status_code)

        # Feature & Entropy calculations
        full_url = request.get_full_path()

        # Ignore static files, internal streaming/polling APIs, and sample log downloads
        if (
            request.path.startswith('/static/') or
            request.path.startswith('/api/live-stream/') or
            request.path.startswith('/api/threat-map/') or
            request.path.startswith('/hunting/sample-log/') or
            request.path.startswith('/favicon')
        ):
            return response

        entropy = calculate_entropy(full_url)
        rate = calculate_request_rate(RequestLog, client_ip)

        try:
            # Query params string serialization
            query_str = "&".join(f"{k}={v}" for k, v in request.GET.items()) if request.GET else ""

            # Resolved target username
            user_obj = getattr(request, 'user', None)
            resolved_username = user_obj.username if (user_obj and getattr(user_obj, 'is_authenticated', False)) else attempted_username

            # Temporary log object to infer intent
            temp_log = RequestLog(
                ip_address=client_ip,
                method=request.method,
                path=request.path,
                status_code=response.status_code,
                username=resolved_username,
                is_login_attempt=is_login_attempt,
                login_success=login_success,
                is_brute_force_suspect=is_brute_force_suspect,
                is_sqli_suspect=is_sqli_suspect,
                is_recon_suspect=is_recon_suspect,
                is_xss_suspect=is_xss_suspect,
                is_path_traversal_suspect=is_path_traversal_suspect,
                entropy_score=entropy,
                request_rate=rate,
            )
            inferred_intent = infer_event_intent(temp_log)

            log = RequestLog.objects.create(
                ip_address=client_ip,
                method=request.method,
                path=request.path,
                status_code=response.status_code,
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
                response_time_ms=duration_ms,
                username=resolved_username,
                query_params=query_str,
                is_login_attempt=is_login_attempt,
                login_success=login_success,
                is_brute_force_suspect=is_brute_force_suspect,
                is_sqli_suspect=is_sqli_suspect,
                is_recon_suspect=is_recon_suspect,
                is_xss_suspect=is_xss_suspect,
                is_path_traversal_suspect=is_path_traversal_suspect,
                inferred_intent=inferred_intent,
                entropy_score=entropy,
                request_rate=rate,
            )

            # Update Profile and run ICMF Multi-Layer Fusion
            self.update_risk_profile(
                client_ip,
                is_brute_force_suspect,
                is_sqli_suspect,
                is_recon_suspect,
                is_xss_suspect,
                is_path_traversal_suspect,
                latest_log=log
            )

        except Exception as e:
            print(f"[CyberOracle Intel] Middleware logging error: {e}")

        return response

    def update_risk_profile(self, ip, brute_force, sqli, recon, xss, path_traversal, latest_log=None):
        profile, _ = IPRiskProfile.objects.get_or_create(ip_address=ip)
        entity_profile, _ = EntityProfile.objects.get_or_create(entity_type='IP', entity_id=ip)

        if brute_force:
            profile.brute_force_count += 1
            entity_profile.brute_force_count += 1
        if sqli:
            profile.sqli_count += 1
            entity_profile.sqli_count += 1
        if recon:
            profile.recon_count += 1
            entity_profile.recon_count += 1
        if xss:
            profile.xss_count += 1
            entity_profile.xss_count += 1
        if path_traversal:
            profile.path_traversal_count += 1
            entity_profile.path_traversal_count += 1

        profile.save()
        entity_profile.save()

        # Run Intent-Centric Multi-Layer Fusion (ICMF)
        evaluate_and_fuse_profile(profile, latest_log=latest_log)

        # Sync entity profile fields
        entity_profile.rule_score = profile.rule_score
        entity_profile.ml_score = profile.ml_score
        entity_profile.anomaly_score = profile.anomaly_score
        entity_profile.sequence_score = profile.sequence_score
        entity_profile.llm_score = profile.llm_score
        entity_profile.fused_score = profile.fused_score
        entity_profile.risk_score = profile.risk_score
        entity_profile.is_blocked = profile.is_blocked
        entity_profile.predicted_next_stage = profile.predicted_next_stage
        entity_profile.predicted_target_asset = profile.predicted_target_asset
        entity_profile.prediction_confidence = profile.prediction_confidence
        entity_profile.llm_explanation = profile.llm_explanation
        entity_profile.save()

    def get_client_ip(self, request):
        """
        Extract client IP address.
        Only trusts X-Forwarded-For if REMOTE_ADDR matches configured TRUSTED_PROXIES.
        """
        trusted_proxies = getattr(settings, 'TRUSTED_PROXIES', {'127.0.0.1', '::1', 'localhost'})
        remote_addr = request.META.get('REMOTE_ADDR', '127.0.0.1')
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')

        if x_forwarded_for and remote_addr in trusted_proxies:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = remote_addr
        return ip