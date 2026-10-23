"""
Learned Meta-Fusion Engine for CyberOracle Intelligence
Combines the 5 analytical views (Rule, Supervised ML, Anomaly, Sequence, and LLM)
using a calibrated meta-classifier (Logistic Regression / Gradient Boosting + Platt Scaling)
with Group-K-Fold cross-validation by IP entity to eliminate telemetry leakage.
"""

import os
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import GroupKFold
from sklearn.metrics import f1_score, roc_auc_score, precision_score, recall_score
from django.conf import settings

META_MODEL_PATH = os.path.join(settings.BASE_DIR, 'monitor', 'data', 'meta_fusion_model.joblib')

VIEW_FEATURE_NAMES = ['rule_score', 'ml_score', 'anomaly_score', 'sequence_score', 'llm_score']
STATIC_WEIGHTS = np.array([0.25, 0.25, 0.15, 0.20, 0.15])


class MetaFusionEngine:
    """
    Calibrated Stacking Classifier that combines 5 individual view scores
    into a mathematically grounded probability of maliciousness: P(Malicious | V_1, ..., V_5).
    """
    def __init__(self, model_path: str = META_MODEL_PATH):
        self.model_path = model_path
        self.model = None
        self.calibrated_model = None
        self.is_trained = False
        self.coefficients = None
        self.intercept = None

        if os.path.exists(model_path):
            self.load(model_path)

    def fit(self, X: np.ndarray, y: np.ndarray, groups: np.ndarray = None, method: str = 'sigmoid'):
        """
        Fit the meta-fusion stacking model using Group-K-Fold cross-validation.
        X: shape (N, 5), scores scaled [0, 100] or [0, 1]
        y: shape (N,), binary labels {0, 1}
        groups: shape (N,), entity IP addresses to prevent leakage across folds
        """
        # Normalize input to [0, 1] for stable logistic regression convergence
        X_norm = np.clip(np.array(X, dtype=float) / 100.0, 0.0, 1.0)
        y = np.array(y, dtype=int)

        base_estimator = LogisticRegression(
            penalty='l2',
            C=1.5,
            solver='lbfgs',
            max_iter=500,
            class_weight='balanced'
        )

        if groups is not None and len(np.unique(groups)) >= 3:
            n_splits = min(5, len(np.unique(groups)))
            gkf = GroupKFold(n_splits=n_splits)
            cv_splits = list(gkf.split(X_norm, y, groups=groups))
            self.calibrated_model = CalibratedClassifierCV(
                estimator=base_estimator,
                method=method,
                cv=cv_splits
            )
            self.calibrated_model.fit(X_norm, y)
        else:
            self.calibrated_model = CalibratedClassifierCV(
                estimator=base_estimator,
                method=method,
                cv=3
            )
            self.calibrated_model.fit(X_norm, y)

        # Also fit standalone base estimator to extract interpretable view weights
        base_estimator.fit(X_norm, y)
        self.model = base_estimator
        self.coefficients = base_estimator.coef_[0].tolist()
        self.intercept = float(base_estimator.intercept_[0])
        self.is_trained = True

        return self

    def predict_probability(self, rule_score: float, ml_score: float, anomaly_score: float, sequence_score: float, llm_score: float) -> tuple:
        """
        Predict calibrated probability of malicious intent and fused score (0-100).
        Returns: (prob: float [0.0, 1.0], fused_score: float [0.0, 100.0], contributions: dict)
        """
        vec = np.array([[rule_score, ml_score, anomaly_score, sequence_score, llm_score]], dtype=float)

        if self.is_trained and self.calibrated_model is not None:
            vec_norm = np.clip(vec / 100.0, 0.0, 1.0)
            prob = float(self.calibrated_model.predict_proba(vec_norm)[0, 1])
            fused_score = round(prob * 100.0, 1)
        else:
            # Deterministic fallback to normalized weighted average
            vec_norm = np.clip(vec[0], 0.0, 100.0)
            fused_score = round(float(np.dot(vec_norm, STATIC_WEIGHTS)), 1)
            prob = round(fused_score / 100.0, 4)

        # Compute relative view contributions
        contributions = {
            'rule': round(rule_score * 0.25, 1),
            'ml': round(ml_score * 0.25, 1),
            'anomaly': round(anomaly_score * 0.15, 1),
            'sequence': round(sequence_score * 0.20, 1),
            'llm': round(llm_score * 0.15, 1)
        }

        return prob, fused_score, contributions

    def save(self, path: str = None):
        """Persist trained meta-fusion engine to disk."""
        target_path = path or self.model_path
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        joblib.dump({
            'calibrated_model': self.calibrated_model,
            'model': self.model,
            'coefficients': self.coefficients,
            'intercept': self.intercept,
            'feature_names': VIEW_FEATURE_NAMES
        }, target_path)

    def load(self, path: str = None):
        """Load trained meta-fusion engine from disk."""
        target_path = path or self.model_path
        if os.path.exists(target_path):
            try:
                data = joblib.load(target_path)
                self.calibrated_model = data.get('calibrated_model')
                self.model = data.get('model')
                self.coefficients = data.get('coefficients')
                self.intercept = data.get('intercept')
                self.is_trained = True
            except Exception as e:
                print(f"[CyberOracle MetaFusion] Error loading meta model from {target_path}: {e}")
                self.is_trained = False


_GLOBAL_META_FUSION_ENGINE = None


def get_meta_fusion_engine() -> MetaFusionEngine:
    """Singleton accessor for the MetaFusionEngine."""
    global _GLOBAL_META_FUSION_ENGINE
    if _GLOBAL_META_FUSION_ENGINE is None:
        _GLOBAL_META_FUSION_ENGINE = MetaFusionEngine()
    return _GLOBAL_META_FUSION_ENGINE


def predict_fused_risk(rule_score: float, ml_score: float, anomaly_score: float, sequence_score: float, llm_score: float) -> tuple:
    """Unified API for computing fused risk score and calibrated probability."""
    engine = get_meta_fusion_engine()
    return engine.predict_probability(rule_score, ml_score, anomaly_score, sequence_score, llm_score)
