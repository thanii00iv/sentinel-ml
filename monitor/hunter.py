"""
Autonomous Threat Hunting Orchestrator for CyberOracle Intelligence
Continuously scans security telemetry to identify stealthy, distributed, and emerging threats.
"""

import json
from datetime import timedelta
from django.utils import timezone
from django.db.models import Count, Q
from django.conf import settings
from .models import RequestLog, IPRiskProfile, ThreatHuntFinding, EntityProfile


def run_autonomous_threat_hunt():
    """
    Execute full autonomous threat hunting routines across recent telemetry streams.
    Ensures sweep idempotency, deduplication per (hunt_type, target_entity, window),
    and comprehensive attack surface filters (SQLi, Brute-Force, Recon, XSS, Path Traversal).
    """
    findings_created = 0
    quarantined_ips = []

    whitelisted_ips = set(getattr(settings, 'WHITELISTED_IPS', {'127.0.0.1', '::1', 'localhost'}))

    now = timezone.now()
    hunt_window = now - timedelta(minutes=60)
    dedup_window = now - timedelta(minutes=30)

    recent_logs = RequestLog.objects.filter(timestamp__gte=hunt_window)

    # -------------------------------------------------------------
    # Routine 1: Low-and-Slow Stealth Attack Hunter
    # Detects persistent attackers evading per-minute thresholds
    # -------------------------------------------------------------
    ip_stats = recent_logs.values('ip_address').annotate(
        total_reqs=Count('id'),
        unique_paths=Count('path', distinct=True),
        failed_logins=Count('id', filter=Q(is_login_attempt=True, login_success=False)),
        attacks=Count(
            'id',
            filter=Q(is_sqli_suspect=True) |
                   Q(is_brute_force_suspect=True) |
                   Q(is_recon_suspect=True) |
                   Q(is_xss_suspect=True) |
                   Q(is_path_traversal_suspect=True)
        )
    )

    for stat in ip_stats:
        ip = stat['ip_address']
        if ip in whitelisted_ips:
            continue

        # Low-and-slow profile: scattered requests (>=8) with repeated 404s/paths or stealth attempts
        if stat['total_reqs'] >= 8 and (stat['unique_paths'] >= 6 or stat['failed_logins'] >= 3 or stat['attacks'] >= 2):
            profile, _ = IPRiskProfile.objects.get_or_create(ip_address=ip)
            
            existing = ThreatHuntFinding.objects.filter(
                target_entity=ip,
                hunt_type='LOW_AND_SLOW',
                timestamp__gte=dedup_window
            ).exists()

            if not existing:
                finding = ThreatHuntFinding.objects.create(
                    hunt_type='LOW_AND_SLOW',
                    target_entity=ip,
                    severity='HIGH' if stat['attacks'] > 0 else 'MEDIUM',
                    description=f"Autonomous hunter detected low-and-slow probing from {ip}: {stat['total_reqs']} requests across {stat['unique_paths']} paths over 60m.",
                    evidence_data=json.dumps({
                        "total_requests": stat["total_reqs"],
                        "unique_paths": stat["unique_paths"],
                        "failed_logins": stat["failed_logins"],
                        "attacks": stat["attacks"]
                    }),
                    mitigation_action="Apply proactive rate-limiting and enforce enhanced behavioral scrutiny.",
                    status='ACTIVE'
                )
                findings_created += 1

                # Auto-quarantine if combined with high risk
                if profile.risk_score >= 70 or stat['attacks'] >= 3:
                    profile.is_blocked = True
                    profile.save()
                    quarantined_ips.append(ip)
                    finding.status = 'MITIGATED'
                    finding.mitigation_action = 'Automated IP quarantine enforced by CyberOracle Intel.'
                    finding.save()

    # -------------------------------------------------------------
    # Routine 2: Graph Community Campaign Hunter (Louvain / Modularity)
    # Detects multiple IPs systematically attacking identical asset clusters
    # -------------------------------------------------------------
    try:
        from .graph_analytics import SecurityKnowledgeGraph
        kg = SecurityKnowledgeGraph(time_window_hours=1)
        graph_campaigns = kg.detect_coordinated_campaigns(min_ips_per_campaign=2)

        for camp in graph_campaigns:
            primary_path = camp['primary_target']
            attackers = [ip for ip in camp['attacker_ips'] if ip not in whitelisted_ips]

            if len(attackers) < 2:
                continue

            existing = ThreatHuntFinding.objects.filter(
                target_entity=primary_path,
                hunt_type='DISTRIBUTED_PROBING',
                timestamp__gte=dedup_window
            ).exists()

            if not existing:
                ThreatHuntFinding.objects.create(
                    hunt_type='DISTRIBUTED_PROBING',
                    target_entity=primary_path,
                    severity=camp.get('severity', 'CRITICAL'),
                    description=(
                        f"Graph analytics identified coordinated multi-source campaign (Community {camp['community_id']}) "
                        f"targeting '{primary_path}' and {len(camp['targeted_paths'])} related paths across {len(attackers)} distinct IPs "
                        f"({camp['total_attacks']} total malicious vectors)."
                    ),
                    evidence_data=json.dumps({
                        "community_id": camp["community_id"],
                        "primary_target": primary_path,
                        "targeted_paths": camp["targeted_paths"],
                        "attacker_ips": attackers,
                        "total_hits": camp["total_attacks"]
                    }),
                    mitigation_action="Enforce strict rate limits, signature filters, and subnet isolation on targeted cluster.",
                    status='ACTIVE'
                )
                findings_created += 1
    except Exception as e:
        # Fallback to direct SQL group aggregation if graph module encounters an issue
        targeted_endpoints = recent_logs.filter(
            Q(is_sqli_suspect=True) |
            Q(is_recon_suspect=True) |
            Q(is_xss_suspect=True) |
            Q(is_path_traversal_suspect=True) |
            Q(is_brute_force_suspect=True)
        ).values('path').annotate(
            attacker_count=Count('ip_address', distinct=True),
            hit_count=Count('id')
        ).filter(attacker_count__gte=2)

        for target in targeted_endpoints:
            path = target['path']
            attackers = [
                ip for ip in recent_logs.filter(path=path).values_list('ip_address', flat=True).distinct()
                if ip not in whitelisted_ips
            ]
            if len(attackers) < 2:
                continue
            existing = ThreatHuntFinding.objects.filter(
                target_entity=path,
                hunt_type='DISTRIBUTED_PROBING',
                timestamp__gte=dedup_window
            ).exists()
            if not existing:
                ThreatHuntFinding.objects.create(
                    hunt_type='DISTRIBUTED_PROBING',
                    target_entity=path,
                    severity='CRITICAL',
                    description=f"Coordinated multi-source campaign detected targeting endpoint '{path}' from {len(attackers)} distinct IPs.",
                    evidence_data=json.dumps({
                        "target_path": path,
                        "attacker_ips": attackers,
                        "total_hits": target["hit_count"]
                    }),
                    mitigation_action="Enforce strict rate limits and signature filters on targeted path.",
                    status='ACTIVE'
                )
                findings_created += 1

    # -------------------------------------------------------------
    # Routine 3: Anomalous High-Frequency Bursts
    # -------------------------------------------------------------
    burst_ips = recent_logs.values('ip_address').annotate(
        req_count=Count('id')
    ).filter(req_count__gte=25)

    for burst in burst_ips:
        ip = burst['ip_address']
        if ip in whitelisted_ips:
            continue

        existing = ThreatHuntFinding.objects.filter(
            target_entity=ip,
            hunt_type='ANOMALOUS_BURST',
            timestamp__gte=dedup_window
        ).exists()

        if not existing:
            ThreatHuntFinding.objects.create(
                hunt_type='ANOMALOUS_BURST',
                target_entity=ip,
                severity='HIGH',
                description=f"Volumetric anomaly burst detected from {ip}: {burst['req_count']} requests inside 60m.",
                evidence_data=json.dumps({"request_volume": burst["req_count"]}),
                mitigation_action="Temporary connection throttling and bot challenge activated.",
                status='ACTIVE'
            )
            findings_created += 1

    return {
        'status': 'SUCCESS',
        'findings_created': findings_created,
        'quarantined_ips': list(set(quarantined_ips)),
        'timestamp': now.isoformat()
    }
