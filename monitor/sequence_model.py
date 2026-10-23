"""
Learned Sequence Modeling Engine for CyberOracle Intelligence
Replaces static lookup tables with empirical 1st-order & 2nd-order Markov transition matrices,
Hidden Markov Models (HMM), and lightweight PyTorch CPU LSTM next-stage predictors.
"""

import os
import math
import joblib
import numpy as np
import pandas as pd
from collections import defaultdict, Counter
from django.conf import settings
from .models import RequestLog, IPRiskProfile

SEQUENCE_MODEL_PATH = os.path.join(settings.BASE_DIR, 'monitor', 'sequence_models.pkl')
KILL_CHAIN_CSV = os.path.join(settings.BASE_DIR, 'monitor', 'data', 'kill_chain_data.csv')
SECURITY_LOGS_CSV = os.path.join(settings.BASE_DIR, 'monitor', 'data', 'network_security_logs.csv')

# Event Vocabulary
EVENT_VOCAB = ['NORMAL', 'RECON', 'BRUTE', 'SQLI', 'XSS', 'LFI', 'EXFIL']
EVENT_TO_IDX = {ev: i for i, ev in enumerate(EVENT_VOCAB)}
IDX_TO_EVENT = {i: ev for i, ev in enumerate(EVENT_VOCAB)}

# Default Risk Weights per Stage
STAGE_RISK_MAP = {
    'NORMAL': 5.0,
    'RECON': 30.0,
    'BRUTE': 60.0,
    'SQLI': 85.0,
    'XSS': 80.0,
    'LFI': 85.0,
    'EXFIL': 95.0,
}

# Target Asset Mapping
STAGE_TARGET_ASSET_MAP = {
    'NORMAL': 'Public Content Endpoints (/landing, /dashboard)',
    'RECON': 'Hidden Configuration & Decoys (/.env, /wp-login.php, /backup.sql)',
    'BRUTE': 'Authentication Gateway (/login/, /admin/login/)',
    'SQLI': 'Data-Bearing API Endpoints (/api/search/, /products/?category=)',
    'XSS': 'Interactive Client-Facing Inputs (/comment/, /search/?q=)',
    'LFI': 'Server File System (/download/?file=, /view_log/?file=)',
    'EXFIL': 'Database Vaults & Sensitive Export (/internal/data/export/)',
}

# Recommended Defensive Actions
STAGE_ACTION_MAP = {
    'NORMAL': 'Continue passive baseline telemetry logging.',
    'RECON': 'Activate decoy honeypots and monitor for path fuzzing escalation.',
    'BRUTE': 'Enforce CAPTCHA challenge, connection rate limits, and monitor auth failures.',
    'SQLI': 'Enforce strict WAF parameter inspection and quarantine offending entity.',
    'XSS': 'Enforce Content Security Policy (CSP) and sanitize input reflect vectors.',
    'LFI': 'Restrict directory traversal permissions and verify path sanitization.',
    'EXFIL': 'URGENT: Quarantine IP instantly, invalidate active sessions, and alert SOC tier-3.',
}

# Cold-Start Static Transitions (Fallback Baseline)
STATIC_COLD_START_TRANSITIONS = {
    'NORMAL': {'NORMAL': 0.70, 'RECON': 0.15, 'BRUTE': 0.05, 'SQLI': 0.04, 'XSS': 0.03, 'LFI': 0.02, 'EXFIL': 0.01},
    'RECON': {'RECON': 0.20, 'BRUTE': 0.45, 'SQLI': 0.15, 'XSS': 0.10, 'LFI': 0.05, 'EXFIL': 0.03, 'NORMAL': 0.02},
    'BRUTE': {'BRUTE': 0.25, 'SQLI': 0.40, 'XSS': 0.15, 'LFI': 0.10, 'EXFIL': 0.06, 'RECON': 0.02, 'NORMAL': 0.02},
    'SQLI': {'SQLI': 0.20, 'EXFIL': 0.55, 'LFI': 0.10, 'XSS': 0.05, 'BRUTE': 0.05, 'RECON': 0.03, 'NORMAL': 0.02},
    'XSS': {'XSS': 0.20, 'BRUTE': 0.35, 'SQLI': 0.25, 'EXFIL': 0.10, 'LFI': 0.05, 'RECON': 0.03, 'NORMAL': 0.02},
    'LFI': {'LFI': 0.15, 'EXFIL': 0.60, 'SQLI': 0.15, 'BRUTE': 0.05, 'XSS': 0.02, 'RECON': 0.02, 'NORMAL': 0.01},
    'EXFIL': {'EXFIL': 0.65, 'NORMAL': 0.15, 'RECON': 0.08, 'BRUTE': 0.05, 'SQLI': 0.04, 'XSS': 0.02, 'LFI': 0.01},
}

_CACHED_SEQUENCE_BUNDLE = None


def extract_event_from_log(log) -> str:
    """Classify an individual RequestLog into an event vocabulary token."""
    if getattr(log, 'is_sqli_suspect', False):
        return 'SQLI'
    if getattr(log, 'is_brute_force_suspect', False) or (getattr(log, 'is_login_attempt', False) and getattr(log, 'login_success', None) is False):
        return 'BRUTE'
    if getattr(log, 'is_xss_suspect', False):
        return 'XSS'
    if getattr(log, 'is_path_traversal_suspect', False):
        return 'LFI'
    if getattr(log, 'is_recon_suspect', False):
        return 'RECON'
    if getattr(log, 'status_code', 200) in (403, 500) and getattr(log, 'entropy_score', 0) > 4.2:
        return 'EXFIL'
    return 'NORMAL'


def extract_entity_sequence(ip_address: str, max_events: int = 20) -> list:
    """Retrieve ordered event sequence for a target entity from recent RequestLog history."""
    logs = RequestLog.objects.filter(ip_address=ip_address).order_by('timestamp')
    if not logs.exists():
        return ['NORMAL']
    events = [extract_event_from_log(l) for l in logs[:max_events]]
    return events if events else ['NORMAL']


# -------------------------------------------------------------
# 1. Empirical Markov Model (1st & 2nd Order with Laplace Smoothing)
# -------------------------------------------------------------
class EmpiricalMarkovModel:
    def __init__(self, alpha: float = 1.0):
        self.alpha = alpha  # Laplace smoothing factor
        self.vocab = EVENT_VOCAB
        self.vocab_size = len(self.vocab)
        self.first_order_counts = defaultdict(Counter)
        self.second_order_counts = defaultdict(Counter)
        self.first_order_matrix = {}
        self.second_order_matrix = {}
        self.unigram_counts = Counter()

    def train_on_sequences(self, sequences: list):
        """Fit bigram and trigram frequency distributions across training attack chains."""
        for seq in sequences:
            if not seq:
                continue
            for ev in seq:
                self.unigram_counts[ev] += 1

            # 1st-order transitions (bigrams)
            for i in range(len(seq) - 1):
                prev_ev, next_ev = seq[i], seq[i + 1]
                self.first_order_counts[prev_ev][next_ev] += 1

            # 2nd-order transitions (trigrams)
            for i in range(len(seq) - 2):
                pair = (seq[i], seq[i + 1])
                next_ev = seq[i + 2]
                self.second_order_counts[pair][next_ev] += 1

        # Calculate Laplace-smoothed probabilities
        for u in self.vocab:
            total_u = sum(self.first_order_counts[u].values())
            self.first_order_matrix[u] = {}
            for v in self.vocab:
                prob = (self.first_order_counts[u][v] + self.alpha) / (total_u + self.alpha * self.vocab_size)
                self.first_order_matrix[u][v] = float(prob)

        for u in self.vocab:
            for v in self.vocab:
                pair = (u, v)
                total_uv = sum(self.second_order_counts[pair].values())
                self.second_order_matrix[pair] = {}
                for w in self.vocab:
                    if total_uv > 0:
                        prob = (self.second_order_counts[pair][w] + self.alpha) / (total_uv + self.alpha * self.vocab_size)
                    else:
                        prob = self.first_order_matrix[v].get(w, 1.0 / self.vocab_size)
                    self.second_order_matrix[pair][w] = float(prob)

    def predict_next(self, sequence: list, order: int = 2) -> dict:
        """Predict next-stage probability distribution given entity event history."""
        if not sequence:
            return {ev: 1.0 / self.vocab_size for ev in self.vocab}

        if order >= 2 and len(sequence) >= 2:
            pair = (sequence[-2], sequence[-1])
            if pair in self.second_order_matrix:
                return self.second_order_matrix[pair]

        last_ev = sequence[-1]
        if last_ev in self.first_order_matrix:
            return self.first_order_matrix[last_ev]

        return STATIC_COLD_START_TRANSITIONS.get(last_ev, {ev: 1.0 / self.vocab_size for ev in self.vocab})


# -------------------------------------------------------------
# 2. Hidden Markov Model (HMM) Next-Stage Predictor
# -------------------------------------------------------------
class KillChainHMM:
    def __init__(self, n_hidden_states: int = 5):
        self.n_hidden_states = n_hidden_states
        self.vocab = EVENT_VOCAB
        self.model = None

    def fit(self, sequences: list):
        try:
            from hmmlearn import hmm
            encoded_seqs = []
            lengths = []
            for seq in sequences:
                if len(seq) >= 2:
                    enc = [EVENT_TO_IDX.get(e, 0) for e in seq]
                    encoded_seqs.extend(enc)
                    lengths.append(len(enc))

            if not lengths:
                return

            X = np.array(encoded_seqs).reshape(-1, 1)
            self.model = hmm.CategoricalHMM(
                n_components=self.n_hidden_states,
                n_iter=40,
                random_state=42,
                init_params='ste'
            )
            self.model.fit(X, lengths)
        except Exception as e:
            print(f"[CyberOracle Sequence] HMM fit notice: {e}")

    def predict_next_distribution(self, sequence: list) -> dict:
        if not self.model or len(sequence) == 0:
            return {ev: 1.0 / len(self.vocab) for ev in self.vocab}
        try:
            obs = np.array([EVENT_TO_IDX.get(e, 0) for e in sequence]).reshape(-1, 1)
            hidden_states = self.model.predict(obs)
            last_state = hidden_states[-1]

            next_state_probs = self.model.transmat_[last_state]
            obs_probs = np.dot(next_state_probs, self.model.emissionprob_)
            obs_probs = obs_probs / (np.sum(obs_probs) or 1.0)

            return {self.vocab[i]: float(obs_probs[i]) for i in range(len(self.vocab))}
        except Exception:
            return {ev: 1.0 / len(self.vocab) for ev in self.vocab}


# -------------------------------------------------------------
# 3. PyTorch CPU Lightweight LSTM Sequence Forecaster
# -------------------------------------------------------------
class LightweightLSTM:
    def __init__(self, embedding_dim: int = 16, hidden_dim: int = 32):
        self.embedding_dim = embedding_dim
        self.hidden_dim = hidden_dim
        self.vocab_size = len(EVENT_VOCAB)
        self.torch_model = None

    def fit(self, sequences: list, epochs: int = 15):
        try:
            import torch
            import torch.nn as nn
            import torch.optim as optim

            class SequenceLSTMModel(nn.Module):
                def __init__(self, vocab_size, emb_dim, hid_dim):
                    super().__init__()
                    self.emb = nn.Embedding(vocab_size, emb_dim)
                    self.lstm = nn.LSTM(emb_dim, hid_dim, batch_first=True)
                    self.fc = nn.Linear(hid_dim, vocab_size)

                def forward(self, x):
                    embeds = self.emb(x)
                    out, _ = self.lstm(embeds)
                    logits = self.fc(out[:, -1, :])
                    return logits

            X_train, y_train = [], []
            for seq in sequences:
                if len(seq) >= 2:
                    for i in range(1, len(seq)):
                        sub = [EVENT_TO_IDX.get(e, 0) for e in seq[max(0, i - 4):i]]
                        target = EVENT_TO_IDX.get(seq[i], 0)
                        X_train.append(sub)
                        y_train.append(target)

            if not X_train:
                return

            max_len = max(len(x) for x in X_train)
            X_padded = [([0] * (max_len - len(x))) + x for x in X_train]

            X_tensor = torch.tensor(X_padded, dtype=torch.long)
            y_tensor = torch.tensor(y_train, dtype=torch.long)

            model = SequenceLSTMModel(self.vocab_size, self.embedding_dim, self.hidden_dim)
            criterion = nn.CrossEntropyLoss()
            optimizer = optim.Adam(model.parameters(), lr=0.015)

            model.train()
            for _ in range(epochs):
                optimizer.zero_grad()
                out = model(X_tensor)
                loss = criterion(out, y_tensor)
                loss.backward()
                optimizer.step()

            model.eval()
            self.torch_model = model
        except Exception as e:
            print(f"[CyberOracle Sequence] PyTorch LSTM note: {e}")

    def predict_next(self, sequence: list) -> dict:
        if not self.torch_model or not sequence:
            return {ev: 1.0 / self.vocab_size for ev in EVENT_VOCAB}
        try:
            import torch
            enc = [EVENT_TO_IDX.get(e, 0) for e in sequence[-4:]]
            X_in = torch.tensor([enc], dtype=torch.long)
            with torch.no_grad():
                logits = self.torch_model(X_in)
                probs = torch.softmax(logits, dim=-1).squeeze(0).numpy()
            return {IDX_TO_EVENT[i]: float(probs[i]) for i in range(self.vocab_size)}
        except Exception:
            return {ev: 1.0 / self.vocab_size for ev in EVENT_VOCAB}


# -------------------------------------------------------------
# 4. Sequence Training Corpus Generation & Model Serialization
# -------------------------------------------------------------
def build_training_sequences() -> list:
    """Extract multi-step incident sequences from dataset corpus and security logs."""
    sequences = [
        ['NORMAL', 'RECON', 'RECON', 'BRUTE', 'BRUTE', 'SQLI', 'EXFIL'],
        ['NORMAL', 'RECON', 'BRUTE', 'SQLI', 'EXFIL'],
        ['RECON', 'LFI', 'EXFIL'],
        ['NORMAL', 'RECON', 'XSS', 'BRUTE', 'SQLI'],
        ['BRUTE', 'BRUTE', 'BRUTE', 'SQLI', 'EXFIL'],
        ['NORMAL', 'NORMAL', 'RECON', 'RECON', 'LFI'],
        ['SQLI', 'SQLI', 'EXFIL'],
        ['NORMAL', 'NORMAL', 'NORMAL', 'NORMAL'],
        ['RECON', 'XSS', 'NORMAL'],
        ['NORMAL', 'BRUTE', 'NORMAL'],
        ['NORMAL', 'RECON', 'BRUTE', 'SQLI'],
        ['RECON', 'BRUTE', 'EXFIL'],
        ['NORMAL', 'NORMAL', 'RECON', 'SQLI', 'EXFIL'],
    ]

    # Ingest from network_security_logs.csv
    if os.path.exists(SECURITY_LOGS_CSV):
        try:
            df_sec = pd.read_csv(SECURITY_LOGS_CSV, nrows=10000)
            def parse_sec_row(row):
                path = str(row.get('request_path', '')).lower()
                ua = str(row.get('user_agent', '')).lower()
                lbl = str(row.get('threat_label', '')).lower()
                if 'sqlmap' in path or 'drop table' in path or 'union select' in path or 'sqlmap' in ua:
                    return 'SQLI'
                if 'hydra' in path or 'hydra' in ua:
                    return 'BRUTE'
                if 'etc/passwd' in path or '..\..' in path:
                    return 'LFI'
                if 'admin' in path or 'phpmyadmin' in path or 'backup.sql' in path or 'nmap' in ua:
                    return 'RECON'
                if lbl == 'malicious':
                    return 'EXFIL'
                return 'NORMAL'

            df_sec['event'] = df_sec.apply(parse_sec_row, axis=1)
            for _, group in df_sec.groupby('source_ip'):
                evs = group['event'].tolist()
                if len(evs) >= 2:
                    sequences.append(evs[:8])
        except Exception as e:
            print(f"[CyberOracle Sequence] network_security_logs parsing note: {e}")

    # Ingest from kill_chain_data.csv if present
    if os.path.exists(KILL_CHAIN_CSV):
        try:
            df = pd.read_csv(KILL_CHAIN_CSV, nrows=5000)
            stage_map = {
                'Reconnaissance': 'RECON',
                'Initial Access': 'BRUTE',
                'Execution': 'SQLI',
                'Persistence': 'LFI',
                'Impact': 'EXFIL'
            }
            for _, group in df.groupby(['Country', 'Industry']):
                stages = [stage_map.get(s, 'NORMAL') for s in group['Attack_Stage'].tolist()[:8]]
                if len(stages) >= 2:
                    sequences.append(stages)
        except Exception as e:
            print(f"[CyberOracle Sequence] kill_chain_data parsing warning: {e}")

    return sequences


def train_sequence_models():
    """Train empirical 1st-order Markov, 2nd-order Markov, HMM, and PyTorch LSTM models."""
    global _CACHED_SEQUENCE_BUNDLE
    sequences = build_training_sequences()

    markov = EmpiricalMarkovModel(alpha=0.5)
    markov.train_on_sequences(sequences)

    hmm_model = KillChainHMM(n_hidden_states=5)
    hmm_model.fit(sequences)

    lstm_model = LightweightLSTM()
    lstm_model.fit(sequences, epochs=15)

    bundle = {
        'markov': markov,
        'hmm': hmm_model,
        'lstm': lstm_model,
        'vocab': EVENT_VOCAB,
        'trained_sequences': len(sequences),
    }

    try:
        joblib.dump(bundle, SEQUENCE_MODEL_PATH)
    except Exception:
        pass

    _CACHED_SEQUENCE_BUNDLE = bundle
    return bundle


def load_sequence_models():
    """Load cached sequence models bundle."""
    global _CACHED_SEQUENCE_BUNDLE
    if _CACHED_SEQUENCE_BUNDLE is not None:
        return _CACHED_SEQUENCE_BUNDLE

    if os.path.exists(SEQUENCE_MODEL_PATH):
        try:
            _CACHED_SEQUENCE_BUNDLE = joblib.load(SEQUENCE_MODEL_PATH)
            return _CACHED_SEQUENCE_BUNDLE
        except Exception:
            pass

    return train_sequence_models()


# -------------------------------------------------------------
# 5. Core Live Forecasting API
# -------------------------------------------------------------
def predict_next_attack_stage(entity_events: list) -> dict:
    """
    Predict next attack stage distribution, forecasted asset, Shannon entropy confidence,
    and sequence risk score using ensemble of learned Markov, HMM, and LSTM models.
    """
    bundle = load_sequence_models()
    markov = bundle['markov']
    lstm = bundle['lstm']
    hmm_mod = bundle['hmm']

    # 1. Obtain distributions from all three models
    markov_dist = markov.predict_next(entity_events, order=2)
    lstm_dist = lstm.predict_next(entity_events)
    hmm_dist = hmm_mod.predict_next_distribution(entity_events)

    # 2. Ensemble Blending (0.45 2nd-Order Markov + 0.35 LSTM + 0.20 HMM)
    blended_dist = {}
    for ev in EVENT_VOCAB:
        p_m = markov_dist.get(ev, 0.0)
        p_l = lstm_dist.get(ev, 0.0)
        p_h = hmm_dist.get(ev, 0.0)
        blended_dist[ev] = float(0.45 * p_m + 0.35 * p_l + 0.20 * p_h)

    # Normalize distribution
    total_p = sum(blended_dist.values()) or 1.0
    blended_dist = {k: round(v / total_p, 4) for k, v in blended_dist.items()}

    # 3. Top-1 Predicted Stage
    sorted_stages = sorted(blended_dist.items(), key=lambda x: x[1], reverse=True)
    top_stage, top_prob = sorted_stages[0]

    # 4. Confidence via Shannon Entropy
    probs = np.array(list(blended_dist.values()))
    probs = probs[probs > 0]
    entropy = -np.sum(probs * np.log2(probs + 1e-12))
    max_entropy = np.log2(len(EVENT_VOCAB))
    norm_entropy = float(entropy / max_entropy)
    confidence_score = round(max(0.0, min(1.0, 1.0 - norm_entropy)), 3)

    if confidence_score >= 0.65 or top_prob >= 0.70:
        confidence_label = 'CRITICAL'
    elif confidence_score >= 0.45 or top_prob >= 0.50:
        confidence_label = 'HIGH'
    elif confidence_score >= 0.25:
        confidence_label = 'MEDIUM'
    else:
        confidence_label = 'LOW'

    # 5. Sequence Risk Scoring (Expected Value of Risk)
    sequence_risk = sum(blended_dist[ev] * STAGE_RISK_MAP.get(ev, 10.0) for ev in EVENT_VOCAB)
    sequence_risk = round(min(100.0, max(0.0, sequence_risk)), 1)

    # Human-readable reasoning
    reasoning = (
        f"Sequence trajectory analysis across [{', '.join(entity_events[-4:])}] forecasts '{top_stage}' "
        f"with {round(top_prob * 100, 1)}% probability (Confidence: {confidence_label}, Shannon Entropy: {round(entropy, 2)} bits)."
    )

    return {
        'predicted_next_stage': top_stage,
        'probability_distribution': blended_dist,
        'top_prob': top_prob,
        'confidence': confidence_label,
        'confidence_score': confidence_score,
        'sequence_risk_score': sequence_risk,
        'target_asset': STAGE_TARGET_ASSET_MAP.get(top_stage, '/api/'),
        'recommended_action': STAGE_ACTION_MAP.get(top_stage, 'Monitor entity.'),
        'reasoning': reasoning,
    }
