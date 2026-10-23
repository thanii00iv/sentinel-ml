"""
Adaptive Response Engine with Contextual Multi-Armed Bandits (LinUCB)
Replaces rigid binary blocking with cost-sensitive, risk-calibrated mitigation actions:
[ALLOW, MONITOR, RATE_LIMIT, CHALLENGE_CAPTCHA, TARPIT, BLOCK_QUARANTINE].
Optimizes the trade-off between false-positive friction cost and attacker harm reduction.
"""

import os
import json
import numpy as np
from pathlib import Path
from django.conf import settings

BANDIT_STATE_PATH = os.path.join(settings.BASE_DIR, 'monitor', 'data', 'bandit_state.json')

ACTION_SPACE = [
    'ALLOW',
    'MONITOR',
    'RATE_LIMIT',
    'CHALLENGE_CAPTCHA',
    'TARPIT',
    'BLOCK_QUARANTINE'
]

# Action definitions & defaults
ACTION_METADATA = {
    'ALLOW': {'id': 0, 'friction_cost': 0.0, 'description': 'Permit request to backend with baseline telemetry logging.'},
    'MONITOR': {'id': 1, 'friction_cost': 1.0, 'description': 'Silent forensic recording and increased telemetry sampling.'},
    'RATE_LIMIT': {'id': 2, 'friction_cost': 5.0, 'description': 'Throttle connection rate to 1 req/sec per entity.'},
    'CHALLENGE_CAPTCHA': {'id': 3, 'friction_cost': 15.0, 'description': 'Issue challenge page or verification token.'},
    'TARPIT': {'id': 4, 'friction_cost': 25.0, 'description': 'Introduce delayed streaming response (5000ms) to exhaust bot sockets.'},
    'BLOCK_QUARANTINE': {'id': 5, 'friction_cost': 100.0, 'description': 'Immediate HTTP 403 termination and IP quarantine.'},
}


class LinUCBResponseEngine:
    """
    Linear Upper Confidence Bound (LinUCB) contextual bandit for adaptive incident response.
    Context dimension d=6: [S_rule, S_ml, S_anomaly, S_seq, S_llm, request_rate]
    """
    def __init__(self, alpha: float = 0.5, dim: int = 6, state_path: str = BANDIT_STATE_PATH):
        self.alpha = alpha
        self.dim = dim
        self.state_path = state_path
        self.actions = ACTION_SPACE
        self.n_actions = len(self.actions)

        # Initialize A_a = I_d, b_a = 0_d for each action
        self.A = {a: np.identity(self.dim).tolist() for a in self.actions}
        self.b = {a: np.zeros(self.dim).tolist() for a in self.actions}
        self.total_decisions = 0

        if os.path.exists(self.state_path):
            self.load_state(self.state_path)

    def extract_context(self, profile, request_rate: float = 1.0) -> np.ndarray:
        """Extract normalized 6-dimensional context vector from entity telemetry."""
        r = float(getattr(profile, 'rule_score', 0) or 0) / 100.0
        m = float(getattr(profile, 'ml_score', 0) or 0) / 100.0
        a = float(getattr(profile, 'anomaly_score', 0) or 0) / 100.0
        s = float(getattr(profile, 'sequence_score', 0) or 0) / 100.0
        l = float(getattr(profile, 'llm_score', 0) or 0) / 100.0
        rate = min(1.0, float(request_rate or 1.0) / 20.0)

        vec = np.array([r, m, a, s, l, rate], dtype=float)
        return np.clip(vec, 0.0, 1.0)

    def select_action(self, context: np.ndarray) -> tuple:
        """
        Select optimal mitigation action using LinUCB exploration-exploitation.
        Returns: (selected_action: str, ucb_scores: dict, expected_reward: float)
        """
        x = np.array(context, dtype=float).reshape(-1, 1)
        ucb_scores = {}

        for a in self.actions:
            A_mat = np.array(self.A[a])
            b_vec = np.array(self.b[a]).reshape(-1, 1)

            A_inv = np.linalg.inv(A_mat)
            theta_hat = np.dot(A_inv, b_vec)

            # Expected payoff + upper confidence bound bonus
            mean = float(np.dot(theta_hat.T, x)[0, 0])
            variance = float(np.sqrt(np.dot(np.dot(x.T, A_inv), x))[0, 0])
            ucb = mean + self.alpha * variance
            ucb_scores[a] = round(ucb, 4)

        # Select action maximizing UCB
        best_action = max(ucb_scores, key=ucb_scores.get)
        self.total_decisions += 1

        return best_action, ucb_scores, ucb_scores[best_action]

    def update(self, context: np.ndarray, action: str, reward: float):
        """
        Update bandit parameters after observing reward / analyst feedback.
        reward: float [-1.0, +1.0] (positive for harm reduction / zero friction, negative for false friction)
        """
        if action not in self.actions:
            return

        x = np.array(context, dtype=float).reshape(-1, 1)
        A_mat = np.array(self.A[action])
        b_vec = np.array(self.b[action]).reshape(-1, 1)

        # A_a <- A_a + x * x^T
        A_mat += np.dot(x, x.T)
        # b_a <- b_a + reward * x
        b_vec += reward * x

        self.A[action] = A_mat.tolist()
        self.b[action] = b_vec.flatten().tolist()

    def save_state(self, path: str = None):
        """Persist bandit parameters to JSON file."""
        target_path = path or self.state_path
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, 'w', encoding='utf-8') as f:
            json.dump({
                'alpha': self.alpha,
                'dim': self.dim,
                'total_decisions': self.total_decisions,
                'A': self.A,
                'b': self.b
            }, f, indent=2)

    def load_state(self, path: str = None):
        """Load bandit parameters from JSON file."""
        target_path = path or self.state_path
        if os.path.exists(target_path):
            try:
                with open(target_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.alpha = data.get('alpha', 0.5)
                self.dim = data.get('dim', 6)
                self.total_decisions = data.get('total_decisions', 0)
                self.A = data.get('A', self.A)
                self.b = data.get('b', self.b)
            except Exception as e:
                print(f"[CyberOracle AdaptiveResponse] Error loading state: {e}")


def compute_reward(action: str, is_actually_malicious: bool, severity: float = 1.0) -> float:
    """
    Simulate environmental payoff for an action given ground-truth maliciousness.
    Balancing harm reduction (+reward) vs friction cost (-reward).
    """
    cost_meta = ACTION_METADATA.get(action, {'friction_cost': 0})
    friction = cost_meta['friction_cost']

    if is_actually_malicious:
        # Malicious entity
        if action == 'BLOCK_QUARANTINE':
            return +1.0 * severity  # Complete containment
        elif action == 'TARPIT':
            return +0.8 * severity  # Severe degradation
        elif action == 'CHALLENGE_CAPTCHA':
            return +0.7 * severity  # Bot stopped
        elif action == 'RATE_LIMIT':
            return +0.4 * severity  # Velocity reduced
        elif action == 'MONITOR':
            return -0.4 * severity  # Forensic trace but allowed damage
        else: # ALLOW
            return -1.0 * severity  # Full damage incurred
    else:
        # Legitimate entity
        if action == 'ALLOW':
            return +1.0  # Perfect frictionless experience
        elif action == 'MONITOR':
            return +0.9  # Silent trace, zero user impact
        elif action == 'RATE_LIMIT':
            return -0.2  # Minor friction
        elif action == 'CHALLENGE_CAPTCHA':
            return -0.5  # Significant user annoyance
        elif action == 'TARPIT':
            return -0.8  # Broken user experience
        else: # BLOCK_QUARANTINE
            return -1.0  # False positive denial of service


_GLOBAL_RESPONSE_ENGINE = None


def get_response_engine() -> LinUCBResponseEngine:
    """Singleton accessor for LinUCBResponseEngine."""
    global _GLOBAL_RESPONSE_ENGINE
    if _GLOBAL_RESPONSE_ENGINE is None:
        _GLOBAL_RESPONSE_ENGINE = LinUCBResponseEngine()
    return _GLOBAL_RESPONSE_ENGINE


def recommend_mitigation_action(profile, request_rate: float = 1.0) -> dict:
    """
    Public API: Selects the optimal mitigation action and returns actionable recommendation metadata.
    """
    engine = get_response_engine()
    context = engine.extract_context(profile, request_rate=request_rate)
    action, ucb_scores, ucb_val = engine.select_action(context)

    meta = ACTION_METADATA.get(action, {})
    return {
        'recommended_action': action,
        'description': meta.get('description', ''),
        'friction_cost': meta.get('friction_cost', 0),
        'ucb_confidence_score': round(ucb_val, 3),
        'candidate_scores': ucb_scores
    }
