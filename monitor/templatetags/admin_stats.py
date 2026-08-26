from django import template
from django.db.models import Q
from monitor.models import RequestLog, IPRiskProfile, ThreatHuntFinding, PredictiveAlert

register = template.Library()

@register.simple_tag
def get_soc_db_stats():
    return {
        'total_requests': RequestLog.objects.count(),
        'malicious_count': RequestLog.objects.filter(
            Q(is_sqli_suspect=True) | Q(is_brute_force_suspect=True) | Q(is_recon_suspect=True) | Q(is_xss_suspect=True) | Q(is_path_traversal_suspect=True)
        ).count(),
        'quarantined_count': IPRiskProfile.objects.filter(is_blocked=True).count(),
        'active_findings': ThreatHuntFinding.objects.filter(status='ACTIVE').count(),
        'total_profiles': IPRiskProfile.objects.count(),
    }
