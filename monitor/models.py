from django.db import models
from django.conf import settings


class DemonstrationSession(models.Model):
    session_id = models.CharField(max_length=64, unique=True, db_index=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True, db_index=True)
    description = models.CharField(max_length=255, blank=True, default="Attack Simulation Demonstration")

    def __str__(self):
        status = "ACTIVE" if self.is_active else "CLOSED"
        return f"DemoSession {self.session_id[:12]} ({status})"

    class Meta:
        ordering = ['-created_at']


class RequestLog(models.Model):
    EVENT_SOURCE_CHOICES = [
        ('SIMULATED', 'Simulated Event'),
        ('LIVE_DETECTED', 'Live Detected Event'),
        ('THREAT_INTELLIGENCE', 'Threat Intelligence Indicator'),
    ]

    ip_address = models.GenericIPAddressField()
    method = models.CharField(max_length=10)
    path = models.CharField(max_length=500)
    status_code = models.IntegerField(null=True, blank=True)
    user_agent = models.CharField(max_length=500, blank=True, null=True)
    response_time_ms = models.FloatField(null=True, blank=True)
    username = models.CharField(max_length=150, blank=True, null=True)
    query_params = models.TextField(blank=True, default="")
    
    # Attack vector suspect flags
    is_login_attempt = models.BooleanField(default=False)
    login_success = models.BooleanField(null=True, blank=True)
    is_brute_force_suspect = models.BooleanField(default=False)
    is_sqli_suspect = models.BooleanField(default=False)
    is_recon_suspect = models.BooleanField(default=False)
    is_xss_suspect = models.BooleanField(default=False)
    is_path_traversal_suspect = models.BooleanField(default=False)
    
    # Behavioral and contextual telemetry
    inferred_intent = models.CharField(max_length=100, default="Legitimate Traffic")
    entropy_score = models.FloatField(default=0.0)
    request_rate = models.FloatField(default=0.0)

    # Event classification and demonstration session isolation
    event_source = models.CharField(
        max_length=30,
        default='LIVE_DETECTED',
        choices=EVENT_SOURCE_CHOICES,
        db_index=True
    )
    simulation_id = models.CharField(max_length=100, blank=True, default='')
    simulation_module = models.CharField(max_length=100, blank=True, default='')
    demo_session = models.ForeignKey(
        DemonstrationSession,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='request_logs'
    )
    demo_active = models.BooleanField(default=True, db_index=True)
    
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} {self.method} {self.path} ({self.status_code}) - Intent: {self.inferred_intent}"

    class Meta:
        ordering = ['-timestamp']


class IPRiskProfile(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    risk_score = models.IntegerField(default=0)
    
    # Vector counts
    brute_force_count = models.IntegerField(default=0)
    sqli_count = models.IntegerField(default=0)
    recon_count = models.IntegerField(default=0)
    xss_count = models.IntegerField(default=0)
    path_traversal_count = models.IntegerField(default=0)
    
    # ICMF Multi-View Analytical Scores (0-100)
    rule_score = models.FloatField(default=0.0)
    ml_score = models.FloatField(default=0.0)
    anomaly_score = models.FloatField(default=0.0)
    sequence_score = models.FloatField(default=0.0)
    llm_score = models.FloatField(default=0.0)
    fused_score = models.FloatField(default=0.0)
    
    # Predictive Analytics
    predicted_next_stage = models.CharField(max_length=200, blank=True, default="Unknown — Monitoring")
    predicted_target_asset = models.CharField(max_length=200, blank=True, default="/login/")
    prediction_confidence = models.CharField(max_length=50, blank=True, default="LOW")
    
    # Automated Threat Hunting & Quarantine
    is_blocked = models.BooleanField(default=False)
    llm_explanation = models.TextField(blank=True, default="")
    
    last_seen = models.DateTimeField(auto_now=True)
    first_seen = models.DateTimeField(auto_now_add=True)

    def threat_level(self):
        score = self.fused_score if self.fused_score > 0 else self.risk_score
        if score >= 70:
            return "CRITICAL"
        elif score >= 40:
            return "HIGH"
        elif score >= 15:
            return "MEDIUM"
        else:
            return "LOW"

    def total_attack_count(self):
        return (
            self.brute_force_count +
            self.sqli_count +
            self.recon_count +
            self.xss_count +
            self.path_traversal_count
        )

    def __str__(self):
        return f"{self.ip_address} - Risk: {self.risk_score} ({self.threat_level()}) [Blocked: {self.is_blocked}]"

    class Meta:
        ordering = ['-risk_score']


class EntityProfile(models.Model):
    ENTITY_TYPE_CHOICES = [
        ('IP', 'IP Address'),
        ('USER', 'User Account'),
        ('SESSION', 'Session Identifier'),
        ('API_KEY', 'API Key / Token'),
    ]

    entity_type = models.CharField(max_length=20, choices=ENTITY_TYPE_CHOICES, default='IP', db_index=True)
    entity_id = models.CharField(max_length=255, db_index=True)
    risk_score = models.IntegerField(default=0)

    # Vector counts
    brute_force_count = models.IntegerField(default=0)
    sqli_count = models.IntegerField(default=0)
    recon_count = models.IntegerField(default=0)
    xss_count = models.IntegerField(default=0)
    path_traversal_count = models.IntegerField(default=0)

    # ICMF Multi-View Analytical Scores (0-100)
    rule_score = models.FloatField(default=0.0)
    ml_score = models.FloatField(default=0.0)
    anomaly_score = models.FloatField(default=0.0)
    sequence_score = models.FloatField(default=0.0)
    llm_score = models.FloatField(default=0.0)
    fused_score = models.FloatField(default=0.0)

    # Predictive Analytics
    predicted_next_stage = models.CharField(max_length=200, blank=True, default="Unknown — Monitoring")
    predicted_target_asset = models.CharField(max_length=200, blank=True, default="/login/")
    prediction_confidence = models.CharField(max_length=50, blank=True, default="LOW")

    # Automated Threat Hunting & Quarantine
    is_blocked = models.BooleanField(default=False)
    llm_explanation = models.TextField(blank=True, default="")

    last_seen = models.DateTimeField(auto_now=True)
    first_seen = models.DateTimeField(auto_now_add=True)

    def threat_level(self):
        score = self.fused_score if self.fused_score > 0 else self.risk_score
        if score >= 70:
            return "CRITICAL"
        elif score >= 40:
            return "HIGH"
        elif score >= 15:
            return "MEDIUM"
        else:
            return "LOW"

    def total_attack_count(self):
        return (
            self.brute_force_count +
            self.sqli_count +
            self.recon_count +
            self.xss_count +
            self.path_traversal_count
        )

    def __str__(self):
        return f"[{self.entity_type}] {self.entity_id} - Risk: {self.risk_score} ({self.threat_level()})"

    class Meta:
        ordering = ['-risk_score']
        unique_together = ('entity_type', 'entity_id')


class ThreatHuntFinding(models.Model):
    HUNT_TYPE_CHOICES = [
        ('LOW_AND_SLOW', 'Low-and-Slow Stealth Attack'),
        ('DISTRIBUTED_PROBING', 'Coordinated Multi-IP Probing'),
        ('ANOMALOUS_BURST', 'Anomalous Request Frequency Burst'),
        ('CREDENTIAL_STUFFING', 'Distributed Credential Stuffing'),
        ('ZERO_DAY_ANOMALY', 'High-Deviation Zero-Day Anomaly'),
    ]
    
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
    ]
    
    STATUS_CHOICES = [
        ('ACTIVE', 'Active Finding'),
        ('MITIGATED', 'Mitigated / IP Quarantined'),
        ('RESOLVED', 'Resolved / Cleared'),
    ]

    hunt_type = models.CharField(max_length=50, choices=HUNT_TYPE_CHOICES)
    target_entity = models.CharField(max_length=150)  # IP or User
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='MEDIUM')
    description = models.TextField()
    evidence_data = models.TextField(blank=True, default="{}")  # JSON metadata
    mitigation_action = models.CharField(max_length=200, default="Monitor and evaluate entity")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='ACTIVE')
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"[{self.severity}] {self.hunt_type} on {self.target_entity} ({self.status})"

    class Meta:
        ordering = ['-timestamp']


class PredictiveAlert(models.Model):
    target_ip = models.GenericIPAddressField()
    predicted_stage = models.CharField(max_length=200)
    predicted_asset = models.CharField(max_length=200)
    confidence = models.CharField(max_length=50, default="MEDIUM")
    reasoning = models.TextField()
    recommended_action = models.TextField()
    is_active = models.BooleanField(default=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Predictive Alert for {self.target_ip}: {self.predicted_stage} -> {self.predicted_asset} ({self.confidence})"

    class Meta:
        ordering = ['-timestamp']


class AnalystFeedback(models.Model):
    FEEDBACK_CHOICES = [
        ('TRUE_POSITIVE', 'True Positive (Confirmed Attack)'),
        ('FALSE_POSITIVE', 'False Positive (Benign Traffic)'),
    ]

    request_log = models.ForeignKey(RequestLog, on_delete=models.CASCADE, null=True, blank=True, related_name='feedbacks')
    entity_id = models.CharField(max_length=255, db_index=True)
    feedback_label = models.CharField(max_length=30, choices=FEEDBACK_CHOICES)
    analyst_username = models.CharField(max_length=150, default='analyst')
    notes = models.TextField(blank=True, default="")
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.feedback_label} by {self.analyst_username} on {self.entity_id} ({self.timestamp})"

    class Meta:
        ordering = ['-timestamp']