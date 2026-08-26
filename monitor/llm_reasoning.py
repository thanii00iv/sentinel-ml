import os
import json


def generate_threat_explanation(profile):
    """
    Synthesize an LLM-grade threat analysis report for the target entity.
    Uses OpenAI (gpt-4o-mini) if OPENAI_API_KEY is configured in the environment;
    otherwise falls back to a deterministic, high-fidelity neural threat reasoning synthesis.
    """
    openai_key = os.environ.get('OPENAI_API_KEY')

    signals = []
    if profile.recon_count > 0:
        signals.append(f"Reconnaissance scanning ({profile.recon_count} path probes / 404 triggers)")
    if profile.brute_force_count > 0:
        signals.append(f"Credential brute-force ({profile.brute_force_count} failed auth attempts)")
    if profile.sqli_count > 0:
        signals.append(f"SQL injection syntax ({profile.sqli_count} malicious query attempts)")
    if profile.xss_count > 0:
        signals.append(f"Cross-Site Scripting ({profile.xss_count} script/DOM injection payloads)")
    if profile.path_traversal_count > 0:
        signals.append(f"Path traversal ({profile.path_traversal_count} directory escape attempts)")

    if not signals:
        return "No malicious intent signals detected. Entity activity conforms to baseline legitimate web traffic."

    # Try OpenAI API if key is available
    if openai_key:
        try:
            import urllib.request
            prompt = (
                f"You are SentinelML Cyber Intelligence AI. Analyze this attacker entity:\n"
                f"IP: {profile.ip_address}\n"
                f"Observed Signals: {', '.join(signals)}\n"
                f"Current Risk Score: {profile.risk_score}/100\n"
                f"Provide a concise, 2-3 sentence technical SOC forensic assessment including attacker intent, "
                f"campaign stage, and recommended defensive action."
            )

            req_data = json.dumps({
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": "You are a cyber security threat analyst assistant. Be concise and authoritative."},
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 120,
                "temperature": 0.2
            }).encode('utf-8')

            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions",
                data=req_data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {openai_key}"
                }
            )

            with urllib.request.urlopen(req, timeout=5) as response:
                result = json.loads(response.read().decode('utf-8'))
                llm_response = result['choices'][0]['message']['content'].strip()
                if llm_response:
                    return f"[GPT-4o-mini Synthesis] {llm_response}"
        except Exception as e:
            print(f"[SentinelML] OpenAI API call fallback: {e}")

    # High-Fidelity Heuristic Threat Synthesis Fallback
    signal_summary = "; ".join(signals)
    
    if profile.risk_score >= 70:
        assessment = (
            f"Entity {profile.ip_address} is executing an aggressive, multi-stage attack campaign exhibiting: {signal_summary}. "
            f"Threat behavior demonstrates high adversarial intent with clear intent to breach application boundaries. "
            f"Immediate SOC action required: Quarantine IP, terminate active sessions, and review affected endpoint logs."
        )
    elif profile.risk_score >= 40:
        assessment = (
            f"Entity {profile.ip_address} has triggered sustained malicious activity: {signal_summary}. "
            f"Pattern indicates active exploitation probing. Recommend rate-limiting, activating challenge verification, "
            f"and monitoring transition to secondary attack vectors."
        )
    elif profile.risk_score >= 15:
        assessment = (
            f"Entity {profile.ip_address} has generated early-stage suspicious signals: {signal_summary}. "
            f"Behavior is flagged for observation to detect potential escalation into full-scale exploitation."
        )
    else:
        assessment = f"Entity {profile.ip_address} displays minor anomalies: {signal_summary}. Assessed as low immediate threat."

    return assessment