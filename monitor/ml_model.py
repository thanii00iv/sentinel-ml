import os
import joblib
import numpy as np
import warnings
from django.conf import settings

# Suppress sklearn version warnings across environments
try:
    from sklearn.exceptions import InconsistentVersionWarning
    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
except ImportError:
    pass

RF_MODEL_PATH = os.path.join(settings.BASE_DIR, 'monitor', 'rf_model.pkl')
ANOMALY_MODEL_PATH = os.path.join(settings.BASE_DIR, 'monitor', 'isolation_forest.pkl')

# In-memory cached model singletons to eliminate repeated disk I/O and latency
_CACHED_RF_MODEL = None
_CACHED_ANOMALY_MODEL = None


def get_features(log):
    """
    Extract 12-dimensional engineered feature vector from a RequestLog instance:
    1. is_sqli_suspect (0/1)
    2. is_brute_force_suspect (0/1)
    3. is_recon_suspect (0/1)
    4. is_xss_suspect (0/1)
    5. is_path_traversal_suspect (0/1)
    6. is_login_attempt (0/1)
    7. login_success (0/1)
    8. response_time_ms (float)
    9. status_code (int)
    10. len(path) (int)
    11. is_post_method (0/1)
    12. entropy_score (float)
    """
    return [
        1 if getattr(log, 'is_sqli_suspect', False) else 0,
        1 if getattr(log, 'is_brute_force_suspect', False) else 0,
        1 if getattr(log, 'is_recon_suspect', False) else 0,
        1 if getattr(log, 'is_xss_suspect', False) else 0,
        1 if getattr(log, 'is_path_traversal_suspect', False) else 0,
        1 if getattr(log, 'is_login_attempt', False) else 0,
        1 if getattr(log, 'login_success', False) else 0,
        float(getattr(log, 'response_time_ms', 0) or 0),
        int(getattr(log, 'status_code', 200) or 200),
        len(getattr(log, 'path', '') or ''),
        1 if getattr(log, 'method', 'GET') == 'POST' else 0,
        float(getattr(log, 'entropy_score', 0.0) or 0.0),
    ]


def train_model():
    """Train a supervised Random Forest Classifier on historical RequestLog telemetry."""
    global _CACHED_RF_MODEL
    from sklearn.ensemble import RandomForestClassifier
    from .models import RequestLog

    logs = RequestLog.objects.all()
    if logs.count() < 6:
        return None

    X, y = [], []
    for log in logs:
        features = get_features(log)
        is_malicious = (
            log.is_sqli_suspect or
            log.is_brute_force_suspect or
            log.is_recon_suspect or
            log.is_xss_suspect or
            log.is_path_traversal_suspect
        )
        label = 1 if is_malicious else 0
        X.append(features)
        y.append(label)

    X, y = np.array(X), np.array(y)

    clf = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
    clf.fit(X, y)

    joblib.dump(clf, RF_MODEL_PATH)
    _CACHED_RF_MODEL = clf
    print(f"[SentinelML] Random Forest model trained on {len(X)} samples.")
    return clf


def load_model():
    """Load cached in-memory Random Forest model (instantaneous, 0 disk I/O)."""
    global _CACHED_RF_MODEL
    if _CACHED_RF_MODEL is not None:
        return _CACHED_RF_MODEL

    if os.path.exists(RF_MODEL_PATH):
        try:
            _CACHED_RF_MODEL = joblib.load(RF_MODEL_PATH)
            return _CACHED_RF_MODEL
        except Exception:
            pass
    _CACHED_RF_MODEL = train_model()
    return _CACHED_RF_MODEL


def predict(log):
    """
    Predict if a single RequestLog is malicious.
    Returns (label: 0 or 1, malicious_probability: 0.0 to 100.0)
    """
    clf = load_model()
    if clf is None:
        return None, None
    try:
        features = np.array([get_features(log)])
        label = int(clf.predict(features)[0])
        probabilities = clf.predict_proba(features)[0]
        prob = round(float(probabilities[1] if len(probabilities) > 1 else label) * 100, 1)
        return label, prob
    except Exception as e:
        print(f"[SentinelML] RF prediction error: {e}")
        return None, None


def train_anomaly_model():
    """Train unsupervised Isolation Forest on clean (baseline) traffic only."""
    global _CACHED_ANOMALY_MODEL
    from sklearn.ensemble import IsolationForest
    from .models import RequestLog

    clean_logs = RequestLog.objects.filter(
        is_sqli_suspect=False,
        is_brute_force_suspect=False,
        is_recon_suspect=False,
        is_xss_suspect=False,
        is_path_traversal_suspect=False
    )

    if clean_logs.count() < 6:
        clean_logs = RequestLog.objects.all()
        if clean_logs.count() < 6:
            return None

    X = np.array([get_features(log) for log in clean_logs])

    clf = IsolationForest(contamination=0.08, n_estimators=150, random_state=42)
    clf.fit(X)

    joblib.dump(clf, ANOMALY_MODEL_PATH)
    _CACHED_ANOMALY_MODEL = clf
    print(f"[SentinelML] Isolation Forest anomaly model trained on {len(X)} samples.")
    return clf


def load_anomaly_model():
    """Load cached in-memory Isolation Forest model (instantaneous, 0 disk I/O)."""
    global _CACHED_ANOMALY_MODEL
    if _CACHED_ANOMALY_MODEL is not None:
        return _CACHED_ANOMALY_MODEL

    if os.path.exists(ANOMALY_MODEL_PATH):
        try:
            _CACHED_ANOMALY_MODEL = joblib.load(ANOMALY_MODEL_PATH)
            return _CACHED_ANOMALY_MODEL
        except Exception:
            pass
    _CACHED_ANOMALY_MODEL = train_anomaly_model()
    return _CACHED_ANOMALY_MODEL


def predict_anomaly(log):
    """
    Predict if a log is anomalous.
    Returns (is_anomaly: bool, anomaly_score: float, normalized_score: 0-100)
    """
    clf = load_anomaly_model()
    if clf is None:
        return False, 0.0, 0.0
    try:
        features = np.array([get_features(log)])
        prediction = clf.predict(features)[0]  # -1 = anomaly, 1 = normal
        raw_score = round(float(clf.decision_function(features)[0]), 3)
        is_anomaly = bool(prediction == -1)
        normalized = max(0.0, min(100.0, (0.25 - raw_score) * 160.0))
        return is_anomaly, raw_score, round(normalized, 1)
    except Exception as e:
        print(f"[SentinelML] Isolation Forest anomaly error: {e}")
        return False, 0.0, 0.0


def retrain_all_models():
    """Programmatically retrain both Random Forest and Isolation Forest models."""
    rf = train_model()
    iso = train_anomaly_model()
    return rf is not None and iso is not None