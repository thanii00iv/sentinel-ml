"""
Adaptive Incident Response & Contextual Bandit (LinUCB) Simulation Benchmark
Simulates 2,000 security incidents comparing Static Binary Threshold vs Static Tiered vs Adaptive LinUCB
across Harm Reduction, False-Positive Friction Cost, and Net Cumulative Utility.
Outputs results to /experiments/results/response_benchmark.json and response_benchmark.csv.
"""

import os
import sys
import json
import time
import numpy as np
import pandas as pd
from pathlib import Path

# Django setup
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'iml_core.settings')

import django
django.setup()

from monitor.adaptive_response import (
    LinUCBResponseEngine,
    compute_reward,
    ACTION_METADATA,
    BANDIT_STATE_PATH
)

RESULTS_DIR = BASE_DIR / 'experiments' / 'results'
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def generate_incident_stream(n_steps: int = 2000, random_state: int = 42):
    """
    Generate chronological stream of security incidents with realistic cohort dynamics.
    Returns: list of dicts with (context: np.ndarray [6], is_malicious: bool, cohort: str, severity: float)
    """
    np.random.seed(random_state)
    stream = []

    for _ in range(n_steps):
        # 40% Malicious, 60% Benign
        cohort_choice = np.random.choice([
            'aggressive_attacker', 'stealth_bot', 'power_api_client', 'regular_user'
        ], p=[0.25, 0.15, 0.25, 0.35])

        if cohort_choice == 'aggressive_attacker':
            # High scores across all views
            r = np.random.uniform(0.70, 0.98)
            m = np.random.uniform(0.75, 0.98)
            a = np.random.uniform(0.60, 0.95)
            s = np.random.uniform(0.80, 0.99)
            l = np.random.uniform(0.75, 0.98)
            rate = np.random.uniform(0.60, 1.0)
            is_mal = True
            sev = 1.0
        elif cohort_choice == 'stealth_bot':
            # Low rule, high sequence/anomaly, low rate
            r = np.random.uniform(0.10, 0.35)
            m = np.random.uniform(0.35, 0.65)
            a = np.random.uniform(0.50, 0.80)
            s = np.random.uniform(0.65, 0.90)
            l = np.random.uniform(0.40, 0.70)
            rate = np.random.uniform(0.05, 0.25)
            is_mal = True
            sev = 0.8
        elif cohort_choice == 'power_api_client':
            # High rate & high anomaly (large uploads), but clean rule/ML/seq/LLM
            r = np.random.uniform(0.0, 0.15)
            m = np.random.uniform(0.0, 0.20)
            a = np.random.uniform(0.65, 0.90)  # High entropy/volume trigger
            s = np.random.uniform(0.0, 0.15)
            l = np.random.uniform(0.0, 0.10)
            rate = np.random.uniform(0.70, 1.0)
            is_mal = False
            sev = 0.0
        else: # regular_user
            r = np.random.uniform(0.0, 0.10)
            m = np.random.uniform(0.0, 0.10)
            a = np.random.uniform(0.0, 0.20)
            s = np.random.uniform(0.0, 0.10)
            l = np.random.uniform(0.0, 0.05)
            rate = np.random.uniform(0.05, 0.20)
            is_mal = False
            sev = 0.0

        ctx = np.array([r, m, a, s, l, rate], dtype=float)
        stream.append({
            'context': ctx,
            'is_malicious': is_mal,
            'cohort': cohort_choice,
            'severity': sev
        })

    return stream


def run_response_simulation():
    print("=" * 75)
    print(" CyberOracle Intel: Adaptive Incident Response & LinUCB Benchmark")
    print("=" * 75)

    n_incidents = 2000
    incidents = generate_incident_stream(n_steps=n_incidents, random_state=42)
    total_mal = sum(1 for inc in incidents if inc['is_malicious'])
    total_benign = sum(1 for inc in incidents if not inc['is_malicious'])
    print(f"[*] Total Incident Events: {n_incidents} (Malicious: {total_mal}, Benign: {total_benign})")

    policies = [
        "Static Binary Threshold (Block >= 70 else Allow)",
        "Static Tiered Policy (Block >= 75, RateLimit >= 50, Monitor >= 30)",
        "Adaptive Contextual Bandit (LinUCB Engine)",
    ]

    results = {}

    for policy_name in policies:
        bandit = LinUCBResponseEngine(alpha=0.4)
        cumulative_reward = 0.0
        total_friction_cost = 0.0
        total_harm_incurred = 0.0
        benign_blocked_count = 0
        attacks_mitigated_count = 0
        action_distribution = {a: 0 for a in ACTION_METADATA.keys()}

        for inc in incidents:
            ctx = inc['context']
            is_mal = inc['is_malicious']
            sev = inc['severity']
            avg_score = float(np.mean(ctx[:5]) * 100.0)

            # Policy Action Selection
            if policy_name == "Static Binary Threshold (Block >= 70 else Allow)":
                action = 'BLOCK_QUARANTINE' if avg_score >= 60.0 else 'ALLOW'
            elif policy_name == "Static Tiered Policy (Block >= 75, RateLimit >= 50, Monitor >= 30)":
                if avg_score >= 70.0:
                    action = 'BLOCK_QUARANTINE'
                elif avg_score >= 45.0:
                    action = 'RATE_LIMIT'
                elif avg_score >= 25.0:
                    action = 'MONITOR'
                else:
                    action = 'ALLOW'
            elif policy_name == "Adaptive Contextual Bandit (LinUCB Engine)":
                action, _, _ = bandit.select_action(ctx)

            action_distribution[action] += 1

            # Compute environment payoff
            reward = compute_reward(action, is_mal, severity=sev)
            cumulative_reward += reward

            # Track friction and containment metrics
            friction = ACTION_METADATA[action]['friction_cost']
            if not is_mal:
                total_friction_cost += friction
                if action in ('BLOCK_QUARANTINE', 'TARPIT'):
                    benign_blocked_count += 1
            else:
                if action in ('BLOCK_QUARANTINE', 'TARPIT', 'CHALLENGE_CAPTCHA', 'RATE_LIMIT'):
                    attacks_mitigated_count += 1
                else:
                    total_harm_incurred += 100.0 * sev

            # Online learning update for Bandit
            if policy_name == "Adaptive Contextual Bandit (LinUCB Engine)":
                bandit.update(ctx, action, reward)

        containment_rate = round(attacks_mitigated_count / total_mal * 100.0, 2)
        mean_reward_per_event = round(cumulative_reward / n_incidents, 4)

        results[policy_name] = {
            'cumulative_reward': round(cumulative_reward, 2),
            'mean_reward_per_decision': mean_reward_per_event,
            'total_friction_cost': round(total_friction_cost, 1),
            'total_harm_incurred': round(total_harm_incurred, 1),
            'attack_containment_rate': containment_rate,
            'false_positive_blocks': benign_blocked_count,
            'action_distribution': action_distribution
        }

        print(f"\n[+] {policy_name}:")
        print(f"    - Net Cumulative Utility: {round(cumulative_reward, 1)} (Mean Payoff: {mean_reward_per_event})")
        print(f"    - Attack Containment Rate: {containment_rate}% | Harm Incurred: {round(total_harm_incurred, 1)}")
        print(f"    - False-Positive User Friction Cost: {round(total_friction_cost, 1)} (Benign Disrupted: {benign_blocked_count})")
        print(f"    - Action Breakdown: {action_distribution}")

        if policy_name == "Adaptive Contextual Bandit (LinUCB Engine)":
            bandit.save_state(BANDIT_STATE_PATH)
            print(f"    [+] Saved trained LinUCB policy state to {BANDIT_STATE_PATH}")

    # Save to JSON
    json_path = RESULTS_DIR / 'response_benchmark.json'
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    print(f"\n[SAVED] JSON response benchmark report to {json_path}")

    # Save to CSV
    rows = []
    for pol_name, p_data in results.items():
        rows.append({
            'Response Policy': pol_name,
            'Net Utility (Cumulative Reward)': p_data['cumulative_reward'],
            'Mean Payoff / Decision': p_data['mean_reward_per_decision'],
            'Attack Containment Rate (%)': p_data['attack_containment_rate'],
            'Total Harm Incurred': p_data['total_harm_incurred'],
            'User Friction Cost': p_data['total_friction_cost'],
            'False Positive Disruptions': p_data['false_positive_blocks']
        })
    df_response = pd.DataFrame(rows)
    csv_path = RESULTS_DIR / 'response_benchmark.csv'
    df_response.to_csv(csv_path, index=False)
    print(f"[SAVED] CSV response benchmark table to {csv_path}")

    return results


if __name__ == '__main__':
    run_response_simulation()
