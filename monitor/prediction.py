"""
Predictive Analytics & Kill-Chain State Forecasting for CyberOracle Intelligence
Powered by learned 1st-order/2nd-order Markov transition matrices, HMM, and PyTorch LSTM
with cold-start heuristic fallback.
"""

from .models import PredictiveAlert, RequestLog
from .sequence_model import (
    predict_next_attack_stage,
    extract_entity_sequence,
    STAGE_TARGET_ASSET_MAP,
    STAGE_ACTION_MAP,
)

# Cold-Start Static Transition Lookup Table (Preserved strictly as baseline fallback)
STAGE_TRANSITIONS = {
    'RECON': {
        'next_stage': 'Credential Brute-Force & Authentication Attack',
        'target_asset': '/login/',
        'confidence': 'MEDIUM',
        'sequence_score': 35.0,
        'reasoning': 'Entity completed reconnaissance path probing. The next empirical stage in the web kill-chain is authentication fuzzing or brute-force password guessing.',
        'recommended_action': 'Enable rate-limiting on /login/ endpoint and monitor for multi-attempt failures.',
    },
    'BRUTE_FORCE': {
        'next_stage': 'Application Injection (SQLi / XSS / LFI)',
        'target_asset': '/api/search/ or query parameters',
        'confidence': 'HIGH',
        'sequence_score': 65.0,
        'reasoning': 'Entity performed repeated credential attacks. Failing authentication typically drives attackers to injection vulnerabilities or token forging.',
        'recommended_action': 'Enforce CAPTCHA, challenge IP identity, and monitor parameter-bound database endpoints.',
    },
    'RECON_BRUTE': {
        'next_stage': 'SQL Injection & Privilege Escalation',
        'target_asset': '/admin/ or data-bearing endpoints',
        'confidence': 'HIGH',
        'sequence_score': 80.0,
        'reasoning': 'Entity executed both reconnaissance and credential attacks. Attacker has mapped application attack surface and is actively seeking privilege elevation.',
        'recommended_action': 'Preemptively inspect database query logs and temporarily quarantine high-risk requests from this entity.',
    },
    'INJECTION_ONLY': {
        'next_stage': 'Automated Tool-Assisted Data Extraction',
        'target_asset': 'Database Tables & Application Storage',
        'confidence': 'HIGH',
        'sequence_score': 75.0,
        'reasoning': 'Direct injection syntax observed without prior probing indicates automated exploitation tooling (e.g., SQLMap, Havij). Rapid exfiltration imminent.',
        'recommended_action': 'Block offending IP immediately and verify WAF parameter sanitization.',
    },
    'FULL_KILLCHAIN': {
        'next_stage': 'Mass Data Exfiltration & System Compromise',
        'target_asset': 'All Sensitive User & Internal Data Assets',
        'confidence': 'CRITICAL',
        'sequence_score': 95.0,
        'reasoning': 'All pre-attack stages completed (Reconnaissance + Brute-Force + Injection). Attacker possesses complete attack chain capability. Data loss or takeover is underway.',
        'recommended_action': 'URGENT: Quarantine IP instantly, invalidate current sessions, and initiate SOC Incident Response protocol.',
    },
    'BASELINE': {
        'next_stage': 'Baseline Monitoring / Potential Recon',
        'target_asset': 'Public Web Endpoints',
        'confidence': 'LOW',
        'sequence_score': 10.0,
        'reasoning': 'No significant multi-stage attack transitions observed. Entity is operating within normal traffic distribution bounds.',
        'recommended_action': 'Continue passive telemetry logging.',
    }
}

EVENT_STAGE_DESCRIPTIONS = {
    'NORMAL': 'Baseline Monitoring / Routine Traffic',
    'RECON': 'Active Reconnaissance & Wordlist Scanning',
    'BRUTE': 'Credential Brute-Force & Authentication Fuzzing',
    'SQLI': 'SQL Injection & Database Privilege Escalation',
    'XSS': 'Cross-Site Scripting (XSS) Client Execution',
    'LFI': 'Path Traversal & Local File Inclusion (LFI)',
    'EXFIL': 'Mass Data Exfiltration & System Compromise',
}


def predict_next_stage_and_asset(profile):
    """
    Predict the likely next attack stage, targeted asset, confidence level, and sequence risk score.
    Runs learned sequence models (Markov 2nd-order + HMM + LSTM) on the entity's observed events,
    with graceful fallback to cold-start lookup if history is minimal.
    Returns (next_stage, target_asset, confidence, sequence_score, reasoning, recommended_action)
    """
    ip = getattr(profile, 'ip_address', None)

    # 1. Extract observed event sequence from RequestLog or synthesize from profile counters
    events = []
    if ip:
        events = extract_entity_sequence(ip, max_events=20)

    if not events or events == ['NORMAL']:
        # Synthesize sequence tokens from observed profile vector counts
        synth = []
        if profile.recon_count > 0:
            synth.extend(['RECON'] * min(profile.recon_count, 3))
        if profile.brute_force_count > 0:
            synth.extend(['BRUTE'] * min(profile.brute_force_count, 3))
        if profile.sqli_count > 0:
            synth.extend(['SQLI'] * min(profile.sqli_count, 3))
        if profile.xss_count > 0:
            synth.extend(['XSS'] * min(profile.xss_count, 2))
        if profile.path_traversal_count > 0:
            synth.extend(['LFI'] * min(profile.path_traversal_count, 2))
        events = synth if synth else ['NORMAL']

    try:
        # Run learned sequence models
        pred_dict = predict_next_attack_stage(events)
        top_event = pred_dict['predicted_next_stage']
        
        next_stage_desc = EVENT_STAGE_DESCRIPTIONS.get(top_event, top_event)
        target_asset = pred_dict['target_asset']
        confidence = pred_dict['confidence']
        sequence_score = pred_dict['sequence_risk_score']
        reasoning = pred_dict['reasoning']
        recommended_action = pred_dict['recommended_action']

    except Exception as e:
        print(f"[CyberOracle Sequence] Prediction fallback to static lookup: {e}")
        # Static cold-start fallback
        has_recon = profile.recon_count > 0
        has_brute = profile.brute_force_count > 0
        has_injection = (profile.sqli_count > 0 or profile.xss_count > 0 or profile.path_traversal_count > 0)

        if (has_recon or has_brute) and has_injection and profile.total_attack_count() >= 5:
            key = 'FULL_KILLCHAIN'
        elif has_recon and has_brute and not has_injection:
            key = 'RECON_BRUTE'
        elif has_brute and not has_recon and not has_injection:
            key = 'BRUTE_FORCE'
        elif has_recon and not has_brute and not has_injection:
            key = 'RECON'
        elif has_injection and not has_recon and not has_brute:
            key = 'INJECTION_ONLY'
        elif has_injection:
            key = 'FULL_KILLCHAIN'
        else:
            key = 'BASELINE'

        fallback_pred = STAGE_TRANSITIONS[key]
        next_stage_desc = fallback_pred['next_stage']
        target_asset = fallback_pred['target_asset']
        confidence = fallback_pred['confidence']
        sequence_score = fallback_pred['sequence_score']
        reasoning = fallback_pred['reasoning']
        recommended_action = fallback_pred['recommended_action']

    # Create persistent PredictiveAlert if confidence is HIGH or CRITICAL
    if confidence in ('HIGH', 'CRITICAL') and ip:
        try:
            PredictiveAlert.objects.get_or_create(
                target_ip=ip,
                predicted_stage=next_stage_desc,
                predicted_asset=target_asset,
                defaults={
                    'confidence': confidence,
                    'reasoning': reasoning,
                    'recommended_action': recommended_action,
                }
            )
        except Exception:
            pass

    return (
        next_stage_desc,
        target_asset,
        confidence,
        sequence_score,
        reasoning,
        recommended_action
    )