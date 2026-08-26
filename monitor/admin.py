import csv
from django.contrib import admin
from django.http import HttpResponse
from django.utils.html import format_html
from .models import RequestLog, IPRiskProfile, ThreatHuntFinding, PredictiveAlert


# Customize Global Django Admin Site Header & Titles
admin.site.site_header = "SentinelML — SOC Master Administration"
admin.site.site_title = "SentinelML Admin Portal"
admin.site.index_title = "SOC Database & Security Entity Management"


def export_as_csv_action(description="Export Selected Records to CSV"):
    """Generic CSV exporter action for any Django ModelAdmin."""
    def export_as_csv(modeladmin, request, queryset):
        opts = modeladmin.model._meta
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename={opts.verbose_name_plural}.csv'
        writer = csv.writer(response)
        fields = [field.name for field in opts.fields]
        writer.writerow(fields)
        for obj in queryset:
            row = [getattr(obj, field) for field in fields]
            writer.writerow(row)
        return response
    export_as_csv.short_description = description
    return export_as_csv


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'method_badge', 'path', 'status_code_badge', 'inferred_intent_badge', 'brute_force_flag', 'sqli_flag', 'xss_flag', 'path_traversal_flag', 'timestamp')
    list_filter = ('is_brute_force_suspect', 'is_sqli_suspect', 'is_recon_suspect', 'is_xss_suspect', 'is_path_traversal_suspect', 'is_login_attempt', 'method', 'status_code')
    search_fields = ('ip_address', 'path', 'username', 'inferred_intent')
    ordering = ('-timestamp',)
    list_per_page = 25
    actions = [export_as_csv_action("Export Selected Logs to CSV"), 'purge_benign_logs_action']

    def method_badge(self, obj):
        color = '#38bdf8' if obj.method == 'GET' else ('#fb923c' if obj.method == 'POST' else '#c084fc')
        return format_html('<span style="color: {}; font-weight: 800; font-family: monospace;">{}</span>', color, obj.method)
    method_badge.short_description = "Method"

    def status_code_badge(self, obj):
        bg = 'rgba(255, 77, 109, 0.15)' if obj.status_code >= 400 else 'rgba(16, 185, 129, 0.15)'
        color = '#ff4d6d' if obj.status_code >= 400 else '#10b981'
        return format_html('<span style="background: {}; color: {}; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-family: monospace;">{}</span>', bg, color, obj.status_code)
    status_code_badge.short_description = "Status"

    def inferred_intent_badge(self, obj):
        intent = obj.inferred_intent or "Normal Traffic"
        color = '#ff4d6d' if ('SQL' in intent or 'Injection' in intent) else ('#fb923c' if 'Brute' in intent else ('#c084fc' if 'Recon' in intent else '#94a3b8'))
        return format_html('<span style="color: {}; font-weight: 700;">{}</span>', color, intent)
    inferred_intent_badge.short_description = "Inferred Intent"

    def brute_force_flag(self, obj):
        if obj.is_brute_force_suspect:
            return format_html('<span style="background: rgba(251,146,60,0.15); color: #fb923c; padding: 2px 6px; border-radius: 4px; font-weight: bold;">⚠ BRUTE</span>')
        return ""
    brute_force_flag.short_description = "Brute"

    def sqli_flag(self, obj):
        if obj.is_sqli_suspect:
            return format_html('<span style="background: rgba(255,77,109,0.15); color: #ff4d6d; padding: 2px 6px; border-radius: 4px; font-weight: bold;">⚠ SQLi</span>')
        return ""
    sqli_flag.short_description = "SQLi"

    def xss_flag(self, obj):
        if obj.is_xss_suspect:
            return format_html('<span style="background: rgba(56,189,248,0.15); color: #38bdf8; padding: 2px 6px; border-radius: 4px; font-weight: bold;">⚠ XSS</span>')
        return ""
    xss_flag.short_description = "XSS"

    def path_traversal_flag(self, obj):
        if obj.is_path_traversal_suspect:
            return format_html('<span style="background: rgba(225,29,72,0.15); color: #e11d48; padding: 2px 6px; border-radius: 4px; font-weight: bold;">⚠ LFI</span>')
        return ""
    path_traversal_flag.short_description = "LFI"

    @admin.action(description="Purge Selected Benign Traffic Logs (Preserves Attack Telemetry)")
    def purge_benign_logs_action(self, request, queryset):
        benign = queryset.filter(
            is_sqli_suspect=False,
            is_brute_force_suspect=False,
            is_recon_suspect=False,
            is_xss_suspect=False,
            is_path_traversal_suspect=False,
            status_code=200
        )
        count = benign.count()
        benign.delete()
        self.message_user(request, f"Successfully purged {count} benign traffic logs.")


@admin.register(IPRiskProfile)
class IPRiskProfileAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'risk_score_badge', 'threat_level_badge', 'quarantine_status_badge', 'predicted_next_stage', 'total_attacks_count', 'forensic_dossier_link', 'last_seen')
    list_filter = ('is_blocked',)
    ordering = ('-risk_score',)
    search_fields = ('ip_address',)
    readonly_fields = ('llm_explanation', 'first_seen', 'last_seen')
    actions = ['enforce_quarantine_action', 'lift_quarantine_action', export_as_csv_action("Export Selected IP Profiles to CSV")]

    def risk_score_badge(self, obj):
        score = obj.fused_score if obj.fused_score > 0 else obj.risk_score
        color = '#ff4d6d' if score >= 70 else ('#fb923c' if score >= 40 else ('#facc15' if score >= 15 else '#38bdf8'))
        return format_html('<span style="font-family: monospace; font-weight: 800; font-size: 1.05rem; color: {};">{}/100</span>', color, score)
    risk_score_badge.short_description = "Fused Risk"

    def threat_level_badge(self, obj):
        level = obj.threat_level()
        colors = {'CRITICAL': '#ff4d6d', 'HIGH': '#fb923c', 'MEDIUM': '#facc15', 'LOW': '#38bdf8'}
        color = colors.get(level, '#94a3b8')
        return format_html('<span style="border: 1px solid {}; color: {}; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 0.78rem;">{}</span>', color, color, level)
    threat_level_badge.short_description = "Threat Tier"

    def quarantine_status_badge(self, obj):
        if obj.is_blocked:
            return format_html('<span style="background: rgba(255, 77, 109, 0.2); color: #ff4d6d; border: 1px solid #ff4d6d; padding: 2px 8px; border-radius: 4px; font-weight: bold;">⛔ QUARANTINED</span>')
        return format_html('<span style="color: #10b981; font-weight: 600;">ACTIVE (ALLOWED)</span>')
    quarantine_status_badge.short_description = "Firewall Status"

    def total_attacks_count(self, obj):
        return obj.total_attack_count()
    total_attacks_count.short_description = "Attacks"

    def forensic_dossier_link(self, obj):
        return format_html(
            '<a href="/threats/{}/" target="_blank" style="color: #38bdf8; font-weight: bold; text-decoration: underline;"><i class="fa-solid fa-arrow-up-right-from-square"></i> Dossier</a>',
            obj.ip_address
        )
    forensic_dossier_link.short_description = "SOC Dossier"

    @admin.action(description="Enforce Instant Firewall Quarantine on Selected IPs")
    def enforce_quarantine_action(self, request, queryset):
        count = queryset.update(is_blocked=True)
        self.message_user(request, f"Successfully quarantined {count} IP entities.")

    @admin.action(description="Lift Firewall Quarantine on Selected IPs")
    def lift_quarantine_action(self, request, queryset):
        count = queryset.update(is_blocked=False)
        self.message_user(request, f"Successfully lifted quarantine for {count} IP entities.")


@admin.register(ThreatHuntFinding)
class ThreatHuntFindingAdmin(admin.ModelAdmin):
    list_display = ('hunt_type', 'target_entity', 'severity_badge', 'status_badge', 'mitigation_action', 'timestamp')
    list_filter = ('hunt_type', 'severity', 'status')
    search_fields = ('target_entity', 'description')
    ordering = ('-timestamp',)
    actions = [export_as_csv_action("Export Selected Hunt Findings to CSV")]

    def severity_badge(self, obj):
        colors = {'CRITICAL': '#ff4d6d', 'HIGH': '#fb923c', 'MEDIUM': '#facc15', 'LOW': '#38bdf8'}
        color = colors.get(obj.severity, '#94a3b8')
        return format_html('<span style="color: {}; font-weight: bold;">{}</span>', color, obj.severity)
    severity_badge.short_description = "Severity"

    def status_badge(self, obj):
        color = '#10b981' if obj.status == 'MITIGATED' else ('#fb923c' if obj.status == 'INVESTIGATING' else '#ff4d6d')
        return format_html('<span style="border: 1px solid {}; color: {}; padding: 2px 6px; border-radius: 4px; font-size: 0.75rem; font-weight: bold;">{}</span>', color, color, obj.status)
    status_badge.short_description = "Status"


@admin.register(PredictiveAlert)
class PredictiveAlertAdmin(admin.ModelAdmin):
    list_display = ('target_ip', 'predicted_stage', 'predicted_asset', 'confidence_badge', 'is_active', 'timestamp')
    list_filter = ('confidence', 'is_active')
    search_fields = ('target_ip', 'predicted_stage', 'predicted_asset')
    ordering = ('-timestamp',)
    actions = [export_as_csv_action("Export Selected Predictive Alerts to CSV")]

    def confidence_badge(self, obj):
        colors = {'CRITICAL': '#ff4d6d', 'HIGH': '#fb923c', 'MEDIUM': '#facc15', 'LOW': '#38bdf8'}
        color = colors.get(obj.confidence, '#94a3b8')
        return format_html('<span style="color: {}; font-weight: 800;">{}</span>', color, obj.confidence)
    confidence_badge.short_description = "Confidence"