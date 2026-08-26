from .models import PredictiveAlert


# Markov-like Transition Probability Matrix across Cyber Attack Stages
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


def predict_next_stage_and_asset(profile):
    """
    Predict the likely next attack stage, targeted asset, confidence level, and sequence risk score.
    Returns (next_stage, target_asset, confidence, sequence_score, reasoning, recommended_action)
    """
    has_recon = profile.recon_count > 0
    has_brute = profile.brute_force_count > 0
    has_injection = (profile.sqli_count > 0 or profile.xss_count > 0 or profile.path_traversal_count > 0)

    # 1. Full Kill-Chain Completed
    if (has_recon or has_brute) and has_injection and profile.total_attack_count() >= 5:
        key = 'FULL_KILLCHAIN'
    # 2. Recon + Brute Force Done, Injection pending
    elif has_recon and has_brute and not has_injection:
        key = 'RECON_BRUTE'
    # 3. Brute Force only
    elif has_brute and not has_recon and not has_injection:
        key = 'BRUTE_FORCE'
    # 4. Recon only
    elif has_recon and not has_brute and not has_injection:
        key = 'RECON'
    # 5. Injection directly without prior stages
    elif has_injection and not has_recon and not has_brute:
        key = 'INJECTION_ONLY'
    # 6. Combined multiple vectors
    elif has_injection:
        key = 'FULL_KILLCHAIN'
    else:
        key = 'BASELINE'

    pred = STAGE_TRANSITIONS[key]

    # Create persistent PredictiveAlert if confidence is HIGH or CRITICAL
    if pred['confidence'] in ('HIGH', 'CRITICAL'):
        try:
            PredictiveAlert.objects.get_or_create(
                target_ip=profile.ip_address,
                predicted_stage=pred['next_stage'],
                predicted_asset=pred['target_asset'],
                defaults={
                    'confidence': pred['confidence'],
                    'reasoning': pred['reasoning'],
                    'recommended_action': pred['recommended_action'],
                }
            )
        except Exception:
            pass

    return (
        pred['next_stage'],
        pred['target_asset'],
        pred['confidence'],
        pred['sequence_score'],
        pred['reasoning'],
        pred['recommended_action']
    )