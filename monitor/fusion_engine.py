"""
Intent-Centric Multi-Layer Fusion (ICMF) Engine for SentinelML
Unifies Rule View, Supervised ML View, Anomaly View, Sequence View, and LLM View.
"""

from .ml_model import predict, predict_anomaly
from .prediction import predict_next_stage_and_asset
from .llm_reasoning import generate_threat_explanation

# ICMF Multi-Layer Fusion Weights (sum = 1.0)
WEIGHT_RULE = 0.25
WEIGHT_ML = 0.25
WEIGHT_ANOMALY = 0.15
WEIGHT_SEQUENCE = 0.20
WEIGHT_LLM = 0.15


def infer_event_intent(log):
    """Infer high-level attacker intent from request telemetry and signatures."""
    target_user = getattr(log, 'username', None)
    user_suffix = f" (Target: {target_user})" if target_user else ""
    path = getattr(log, 'path', '') or ''
    is_login = getattr(log, 'is_login_attempt', False) or '/login' in path

    if getattr(log, 'is_sqli_suspect', False):
        if is_login:
            return f"SQL Injection (Auth Bypass){user_suffix}"
        return "SQL Injection Attempt"
    if getattr(log, 'is_brute_force_suspect', False):
        return f"Brute Force / Credential Guessing{user_suffix}"
    if getattr(log, 'is_xss_suspect', False):
        return "Cross-Site Scripting (XSS)"
    if getattr(log, 'is_path_traversal_suspect', False):
        return "Path Traversal / Local File Inclusion"
    if getattr(log, 'is_recon_suspect', False):
        return "Reconnaissance & Directory Fuzzing"
    if getattr(log, 'is_login_attempt', False) and not getattr(log, 'login_success', False):
        return f"Brute Force Attempt{user_suffix}"
    if getattr(log, 'entropy_score', 0) > 4.5:
        return "High-Entropy Payload Probe"
    return "Legitimate Web Traffic"


def calculate_rule_score(profile):
    """Compute deterministic signature score (0-100) from observed vector counts."""
    score = 0
    if profile.brute_force_count > 0:
        score += 40
    if profile.sqli_count > 0:
        score += 35
    if profile.recon_count > 0:
        score += 25
    if profile.xss_count > 0:
        score += 35
    if profile.path_traversal_count > 0:
        score += 35

    # Frequency multiplier bonus (up to +10 pts each)
    score += min(profile.brute_force_count, 5) * 2
    score += min(profile.sqli_count, 5) * 2
    score += min(profile.recon_count, 5) * 2
    score += min(profile.xss_count, 5) * 2
    score += min(profile.path_traversal_count, 5) * 2

    return min(100.0, float(score))


def calculate_llm_view_score(profile):
    """Estimate LLM intent severity score (0-100) based on contextual signals."""
    total_attacks = profile.total_attack_count()
    if total_attacks == 0:
        return 0.0
    
    base = min(90.0, total_attacks * 18.0)
    if profile.sqli_count > 0 and profile.brute_force_count > 0:
        base = max(base, 85.0)
    if profile.recon_count > 0 and profile.brute_force_count > 0:
        base = max(base, 70.0)
    return min(100.0, float(base))


def evaluate_and_fuse_profile(profile, latest_log=None):
    """
    Execute Intent-Centric Multi-Layer Fusion (ICMF) across all 5 analytical views.
    Updates the profile's individual view scores and calculates the unified fused_score.
    """
    # 1. Rule View
    rule_score = calculate_rule_score(profile)

    # 2. Supervised ML View (Random Forest)
    ml_score = 0.0
    if latest_log:
        _, ml_prob = predict(latest_log)
        if ml_prob is not None:
            ml_score = float(ml_prob)
        else:
            ml_score = rule_score

    # 3. Unsupervised Anomaly View (Isolation Forest)
    anomaly_score = 0.0
    if latest_log:
        _, _, norm_anomaly = predict_anomaly(latest_log)
        anomaly_score = float(norm_anomaly)

    # 4. Sequence / Graph View (Markov Next-Stage Engine)
    next_stage, target_asset, confidence, seq_score, reasoning, action = predict_next_stage_and_asset(profile)
    profile.predicted_next_stage = next_stage
    profile.predicted_target_asset = target_asset
    profile.prediction_confidence = confidence

    # 5. LLM View
    llm_score = calculate_llm_view_score(profile)

    # Multi-Layer Weighted Fusion
    fused = (
        WEIGHT_RULE * rule_score +
        WEIGHT_ML * ml_score +
        WEIGHT_ANOMALY * anomaly_score +
        WEIGHT_SEQUENCE * seq_score +
        WEIGHT_LLM * llm_score
    )
    fused_score = round(min(100.0, max(0.0, fused)), 1)

    # Assign scores to profile
    profile.rule_score = round(rule_score, 1)
    profile.ml_score = round(ml_score, 1)
    profile.anomaly_score = round(anomaly_score, 1)
    profile.sequence_score = round(seq_score, 1)
    profile.llm_score = round(llm_score, 1)
    profile.fused_score = fused_score
    profile.risk_score = int(round(fused_score))

    # Trigger LLM threat explanation synthesis if tier escalated or empty
    if not profile.llm_explanation or fused_score >= 40:
        try:
            profile.llm_explanation = generate_threat_explanation(profile)
        except Exception as e:
            print(f"[SentinelML] LLM explanation synthesis error: {e}")

    profile.save()
    return profile
