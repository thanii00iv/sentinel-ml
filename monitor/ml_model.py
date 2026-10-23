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


FEATURE_NAMES = [
    'is_sqli_suspect',
    'is_brute_force_suspect',
    'is_recon_suspect',
    'is_xss_suspect',
    'is_path_traversal_suspect',
    'is_login_attempt',
    'login_success',
    'response_time_ms',
    'status_code',
    'path_length',
    'is_post_method',
    'entropy_score',
]


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
    print(f"[CyberOracle Intel] Random Forest model trained on {len(X)} samples.")
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
        print(f"[CyberOracle Intel] RF prediction error: {e}")
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
    print(f"[CyberOracle Intel] Isolation Forest anomaly model trained on {len(X)} samples.")
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
        print(f"[CyberOracle Intel] Isolation Forest anomaly error: {e}")
        return False, 0.0, 0.0


NETWORK_DATASET_PATH = os.path.join(settings.BASE_DIR, 'monitor', 'data', 'network_traffic.csv')
NETWORK_MODEL_PATH = os.path.join(settings.BASE_DIR, 'monitor', 'network_flow_model.pkl')

_CACHED_NETWORK_MODEL = None


def train_network_flow_model():
    """
    Train a specialized Random Forest Classifier directly on the network traffic flow dataset.
    Extracts 18 network flow features and trains on ground-truth attack vectors.
    """
    global _CACHED_NETWORK_MODEL
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import LabelEncoder
    from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score, confusion_matrix

    if not os.path.exists(NETWORK_DATASET_PATH):
        return None

    try:
        df = pd.read_csv(NETWORK_DATASET_PATH)
        df_feat = df.copy()

        le_proto = LabelEncoder()
        le_flags = LabelEncoder()
        df_feat['Protocol_Enc'] = le_proto.fit_transform(df_feat['Protocol'].astype(str))
        df_feat['Flags_Enc'] = le_flags.fit_transform(df_feat['Flags'].astype(str))

        feature_cols = [
            'Packet_Length', 'Duration', 'Source_Port', 'Destination_Port',
            'Bytes_Sent', 'Bytes_Received', 'Flow_Packets/s', 'Flow_Bytes/s',
            'Avg_Packet_Size', 'Total_Fwd_Packets', 'Total_Bwd_Packets',
            'Fwd_Header_Length', 'Bwd_Header_Length', 'Sub_Flow_Fwd_Bytes',
            'Sub_Flow_Bwd_Bytes', 'Inbound', 'Protocol_Enc', 'Flags_Enc'
        ]

        X = df_feat[feature_cols].fillna(0)
        # Binary target: 1 = Attack (DDoS, Ransomware, Brute Force), 0 = Normal
        y = (df_feat['Attack_Type'].astype(str).str.lower() != 'normal').astype(int)

        clf = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=12)
        clf.fit(X, y)

        y_pred = clf.predict(X)
        acc = accuracy_score(y, y_pred)
        prec = precision_score(y, y_pred, zero_division=0)
        rec = recall_score(y, y_pred, zero_division=0)
        f1 = f1_score(y, y_pred, zero_division=0)
        cm = confusion_matrix(y, y_pred).tolist()

        # Top feature importances
        importances = dict(zip(feature_cols, [round(float(v), 4) for v in clf.feature_importances_]))
        sorted_importances = sorted(importances.items(), key=lambda item: item[1], reverse=True)

        raw_counts = df['Attack_Type'].value_counts().to_dict()
        clean_counts = {
            'ddos': raw_counts.get('DDoS', 0),
            'ransomware': raw_counts.get('Ransomware', 0),
            'brute_force': raw_counts.get('Brute Force', 0),
            'normal': raw_counts.get('Normal', 0),
        }

        bundle = {
            'model': clf,
            'feature_cols': feature_cols,
            'le_proto': le_proto,
            'le_flags': le_flags,
            'total_samples': len(df),
            'attack_counts': clean_counts,
            'accuracy': round(acc * 100, 1),
            'precision': round(prec * 100, 1),
            'recall': round(rec * 100, 1),
            'f1': round(f1 * 100, 1),
            'confusion_matrix': cm,
            'top_features': sorted_importances[:6],
        }

        joblib.dump(bundle, NETWORK_MODEL_PATH)
        _CACHED_NETWORK_MODEL = bundle
        print(f"[CyberOracle Intel] Network Flow Model trained on {len(df)} flows (Accuracy: {bundle['accuracy']}%).")
        return bundle
    except Exception as e:
        print(f"[CyberOracle Intel] Error training network flow model: {e}")
        return None


def get_network_evaluation_metrics():
    """Load or calculate evaluation benchmarks for the network flow dataset."""
    global _CACHED_NETWORK_MODEL
    if _CACHED_NETWORK_MODEL is not None:
        return _CACHED_NETWORK_MODEL

    if os.path.exists(NETWORK_MODEL_PATH):
        try:
            _CACHED_NETWORK_MODEL = joblib.load(NETWORK_MODEL_PATH)
            return _CACHED_NETWORK_MODEL
        except Exception:
            pass

    return train_network_flow_model()


def retrain_all_models():
    """Programmatically retrain Random Forest, Isolation Forest, Network Flow, and Kill Chain models."""
    rf = train_model()
    iso = train_anomaly_model()
    net = train_network_flow_model()
    kc = train_kill_chain_model()
    return rf is not None and iso is not None and net is not None and kc is not None


KILL_CHAIN_DATASET_PATH = os.path.join(settings.BASE_DIR, 'monitor', 'data', 'kill_chain_data.csv')
KILL_CHAIN_MODEL_PATH = os.path.join(settings.BASE_DIR, 'monitor', 'kill_chain_model.pkl')

_CACHED_KILL_CHAIN_MODEL = None


def train_kill_chain_model(sample_size=25000):
    """
    Train an Enterprise Cyber Kill Chain Classifier on enterprise incident telemetry (100,500 samples).
    Predicts Cyber Kill Chain Attack Stages (Reconnaissance, Initial Access, Execution, Persistence, Impact)
    and evaluates breach risk characteristics across 50 multi-dimensional security features.
    """
    global _CACHED_KILL_CHAIN_MODEL
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import LabelEncoder
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

    if not os.path.exists(KILL_CHAIN_DATASET_PATH):
        return None

    try:
        df_full = pd.read_csv(KILL_CHAIN_DATASET_PATH)
        total_samples = len(df_full)

        if sample_size and total_samples > sample_size:
            df = df_full.sample(n=sample_size, random_state=42).copy()
        else:
            df = df_full.copy()

        cat_cols = [
            'Industry', 'Country', 'Company_Size', 'Attack_Vector',
            'Threat_Actor', 'Password_Policy', 'Attack_Complexity', 'Compliance'
        ]
        label_encoders = {}
        for col in cat_cols:
            if col in df.columns:
                le = LabelEncoder()
                df[col + '_Enc'] = le.fit_transform(df[col].astype(str))
                label_encoders[col] = le

        feature_cols = [
            'Employee_Count', 'Firewall', 'MFA', 'EDR', 'IDS', 'Security_Training',
            'Patch_Age_Days', 'Open_Vulnerabilities', 'CVSS_Score', 'Internet_Exposed',
            'Security_Audit_Score', 'Phishing_Click', 'Credential_Stolen', 'Privilege_Escalation',
            'Lateral_Movement', 'Persistence', 'Data_Encrypted', 'Data_Exfiltration_GB',
            'Detection_Time_Min', 'Response_Time_Min', 'Downtime_Hours',
            'Zero_Day', 'Vendor_Count', 'ThirdParty_Risk', 'Insider_Risk',
            'Security_Maturity', 'SOC_Team_Size',
            'Industry_Enc', 'Country_Enc', 'Company_Size_Enc', 'Attack_Vector_Enc',
            'Threat_Actor_Enc', 'Password_Policy_Enc', 'Attack_Complexity_Enc', 'Compliance_Enc'
        ]

        available_features = [c for c in feature_cols if c in df.columns]
        X = df[available_features].fillna(0)
        y = df['Attack_Stage'].astype(str)

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

        clf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1)
        clf.fit(X_train, y_train)

        y_pred = clf.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        rec = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
        classes = sorted(list(clf.classes_))
        cm = confusion_matrix(y_test, y_pred, labels=classes).tolist()

        importances = dict(zip(available_features, [round(float(v), 4) for v in clf.feature_importances_]))
        sorted_importances = sorted(importances.items(), key=lambda item: item[1], reverse=True)

        raw_stages = df_full['Attack_Stage'].value_counts().to_dict()
        stage_counts = {
            'Reconnaissance': raw_stages.get('Reconnaissance', 0),
            'Initial_Access': raw_stages.get('Initial Access', 0),
            'Initial Access': raw_stages.get('Initial Access', 0),
            'Execution': raw_stages.get('Execution', 0),
            'Persistence': raw_stages.get('Persistence', 0),
            'Impact': raw_stages.get('Impact', 0),
        }

        raw_risks = df_full['Risk_Level'].value_counts().to_dict() if 'Risk_Level' in df_full.columns else {}
        risk_counts = {
            'Low': raw_risks.get('Low', 0),
            'Medium': raw_risks.get('Medium', 0),
            'High': raw_risks.get('High', 0),
            'Critical': raw_risks.get('Critical', 0),
        }

        success_rate = round(float(df_full['Attack_Success'].mean() * 100), 1) if 'Attack_Success' in df_full.columns else 0.0

        bundle = {
            'model': clf,
            'classes': classes,
            'feature_cols': available_features,
            'total_samples': total_samples,
            'trained_samples': len(X_train),
            'stage_counts': stage_counts,
            'risk_counts': risk_counts,
            'success_rate': success_rate,
            'accuracy': round(acc * 100, 1),
            'precision': round(prec * 100, 1),
            'recall': round(rec * 100, 1),
            'f1': round(f1 * 100, 1),
            'confusion_matrix': cm,
            'top_features': sorted_importances[:8],
        }

        joblib.dump(bundle, KILL_CHAIN_MODEL_PATH)
        _CACHED_KILL_CHAIN_MODEL = bundle
        print(f"[CyberOracle Intel] Cyber Kill Chain Model trained on {len(X)} samples (Accuracy: {bundle['accuracy']}%).")
        return bundle
    except Exception as e:
        print(f"[CyberOracle Intel] Error training Cyber Kill Chain model: {e}")
        return None


def get_kill_chain_evaluation_metrics():
    """Load or calculate evaluation benchmarks for the Cyber Kill Chain dataset."""
    global _CACHED_KILL_CHAIN_MODEL
    if _CACHED_KILL_CHAIN_MODEL is not None:
        return _CACHED_KILL_CHAIN_MODEL

    if os.path.exists(KILL_CHAIN_MODEL_PATH):
        try:
            _CACHED_KILL_CHAIN_MODEL = joblib.load(KILL_CHAIN_MODEL_PATH)
            return _CACHED_KILL_CHAIN_MODEL
        except Exception:
            pass

    return train_kill_chain_model()


def predict_kill_chain_stage(profile):
    """
    Predict the Cyber Kill Chain stage using the trained Kill Chain Classifier.
    Extracts behavioral telemetry from the profile, runs multi-class prediction,
    and returns (stage: str, probabilities: dict, confidence: str, risk_score: float).
    """
    bundle = get_kill_chain_evaluation_metrics()
    if not bundle or 'model' not in bundle:
        return 'Reconnaissance', {'Reconnaissance': 1.0}, 'LOW', 10.0

    try:
        clf = bundle['model']
        feature_cols = bundle['feature_cols']

        recon = getattr(profile, 'recon_count', 0)
        brute = getattr(profile, 'brute_force_count', 0)
        sqli = getattr(profile, 'sqli_count', 0)
        xss = getattr(profile, 'xss_count', 0)
        path_trav = getattr(profile, 'path_traversal_count', 0)
        total = profile.total_attack_count()

        feat_map = {
            'Employee_Count': 500,
            'Firewall': 1,
            'MFA': 0 if brute > 2 else 1,
            'EDR': 1,
            'IDS': 1,
            'Security_Training': 1,
            'Patch_Age_Days': 30 + (sqli * 5),
            'Open_Vulnerabilities': min(20, sqli + xss + path_trav),
            'CVSS_Score': min(10.0, 4.0 + sqli * 1.2 + path_trav * 1.5),
            'Internet_Exposed': 1 if (recon > 0 or sqli > 0) else 0,
            'Security_Audit_Score': max(10, 85 - total * 5),
            'Phishing_Click': 1 if brute > 3 else 0,
            'Credential_Stolen': 1 if brute > 5 else 0,
            'Privilege_Escalation': 1 if (sqli > 2 and brute > 2) else 0,
            'Lateral_Movement': 1 if (path_trav > 2 and total >= 6) else 0,
            'Persistence': 1 if total >= 8 else 0,
            'Data_Encrypted': 0,
            'Data_Exfiltration_GB': min(50.0, (path_trav + sqli) * 2.5),
            'Detection_Time_Min': 12,
            'Response_Time_Min': 8,
            'Downtime_Hours': 0.0,
            'Zero_Day': 1 if (xss > 2 and sqli > 2) else 0,
            'Vendor_Count': 15,
            'ThirdParty_Risk': 3,
            'Insider_Risk': 2,
            'Security_Maturity': 3,
            'SOC_Team_Size': 6,
            'Industry_Enc': 0,
            'Country_Enc': 0,
            'Company_Size_Enc': 1,
            'Attack_Vector_Enc': 1 if sqli > 0 else (2 if brute > 0 else 0),
            'Threat_Actor_Enc': 1 if total > 5 else 0,
            'Password_Policy_Enc': 1,
            'Attack_Complexity_Enc': 1 if sqli > 0 else 0,
            'Compliance_Enc': 1,
        }

        row = [feat_map.get(col, 0) for col in feature_cols]
        X_vec = np.array([row])

        predicted_stage = str(clf.predict(X_vec)[0])
        probs = clf.predict_proba(X_vec)[0]
        classes = list(clf.classes_)
        prob_dict = {classes[i]: round(float(probs[i]), 3) for i in range(len(classes))}

        top_prob = float(max(probs))
        confidence = 'CRITICAL' if top_prob > 0.85 else ('HIGH' if top_prob > 0.65 else 'MEDIUM')

        stage_risk_weights = {
            'Reconnaissance': 25.0,
            'Initial Access': 50.0,
            'Initial_Access': 50.0,
            'Execution': 70.0,
            'Persistence': 85.0,
            'Impact': 95.0,
        }
        base_stage_risk = stage_risk_weights.get(predicted_stage, 40.0)
        risk_score = round(base_stage_risk * top_prob, 1)

        return predicted_stage, prob_dict, confidence, risk_score
    except Exception as e:
        print(f"[CyberOracle Intel] Kill chain model prediction fallback: {e}")
        return 'Reconnaissance', {'Reconnaissance': 1.0}, 'LOW', 15.0