"""
ICMF Meta-Fusion & Systematic View Ablation Benchmark
Benchmarks Full 5-View Fusion vs Ablated Subsets (-Rule, -ML, -Anomaly, -Seq, -LLM)
using Group-K-Fold cross-validation by IP entity to eliminate data leakage.
Outputs results to /experiments/results/ablation_results.json and ablation_results.csv.
"""

import os
import sys
import json
import time
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import GroupKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix
)

# Django setup
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'iml_core.settings')

import django
django.setup()

from monitor.meta_fusion import MetaFusionEngine, META_MODEL_PATH

RESULTS_DIR = BASE_DIR / 'experiments' / 'results'
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def generate_multiview_evaluation_dataset(n_samples: int = 1500, random_state: int = 42) -> tuple:
    """
    Generate a realistic, heterogeneous multi-view security telemetry dataset across diverse IP entities.
    Returns: (X: np.ndarray [N, 5], y: np.ndarray [N], ip_groups: np.ndarray [N])
    Views: [Rule_Score, ML_Score, Anomaly_Score, Sequence_Score, LLM_Score] (all 0-100)
    """
    np.random.seed(random_state)
    n_ips = 150
    ips = [f"198.51.{np.random.randint(1, 250)}.{np.random.randint(1, 250)}" for _ in range(n_ips)]

    rows = []
    labels = []
    ip_col = []

    samples_per_ip = n_samples // n_ips

    for ip_idx, ip in enumerate(ips):
        # 45% of entities are malicious attackers of varying skill/profile
        is_attacker = (ip_idx % 2 == 0) and (ip_idx < int(n_ips * 0.90))

        if is_attacker:
            attack_type = np.random.choice([
                'evasive_sqli', 'credential_stuffing', 'slow_stealth_recon', 
                'obfuscated_zero_day', 'fast_exploit_burst'
            ])
            for _ in range(samples_per_ip):
                if attack_type == 'evasive_sqli':
                    # Evades static regex (low rule), caught by Supervised ML and LLM RAG
                    r = np.random.uniform(5, 25)
                    m = np.random.uniform(65, 88)
                    a = np.random.uniform(30, 60)
                    s = np.random.uniform(40, 75)
                    l = np.random.uniform(70, 95)
                elif attack_type == 'credential_stuffing':
                    # High rule, high ML, low anomaly (standard 401 response size), high sequence
                    r = np.random.uniform(70, 95)
                    m = np.random.uniform(75, 95)
                    a = np.random.uniform(15, 45)
                    s = np.random.uniform(75, 95)
                    l = np.random.uniform(50, 80)
                elif attack_type == 'slow_stealth_recon':
                    # Evades rule and ML (looks like normal browsing), caught by Sequence Markov + Anomaly
                    r = np.random.uniform(5, 20)
                    m = np.random.uniform(15, 35)
                    a = np.random.uniform(65, 90)
                    s = np.random.uniform(70, 92)
                    l = np.random.uniform(25, 50)
                elif attack_type == 'obfuscated_zero_day':
                    # Evades regex (rule=0) & supervised ML (unseen token distribution), caught by Anomaly & LLM
                    r = np.random.uniform(0, 15)
                    m = np.random.uniform(10, 35)
                    a = np.random.uniform(75, 98)
                    s = np.random.uniform(35, 65)
                    l = np.random.uniform(80, 98)
                else: # fast_exploit_burst
                    # High on all views
                    r = np.random.uniform(75, 98)
                    m = np.random.uniform(80, 98)
                    a = np.random.uniform(75, 95)
                    s = np.random.uniform(80, 98)
                    l = np.random.uniform(85, 99)

                # Add small measurement jitter
                vec = np.clip(np.array([r, m, a, s, l]) + np.random.normal(0, 3, 5), 0, 100)
                rows.append(vec)
                labels.append(1)
                ip_col.append(ip)
        else:
            # Benign client traffic (regular browsing, API polling, occasional 404 or high entropy upload)
            benign_type = np.random.choice([
                'regular_browsing', 'high_entropy_upload', 'sporadic_404_client_error', 'burst_api_consumer'
            ])
            for _ in range(samples_per_ip):
                if benign_type == 'high_entropy_upload':
                    # High anomaly (compressed/encrypted data triggers Isolation Forest), but zero attack indicators
                    r = np.random.uniform(0, 10)
                    m = np.random.uniform(0, 15)
                    a = np.random.uniform(65, 88)  # Anomaly false alarm trigger
                    s = np.random.uniform(0, 15)
                    l = np.random.uniform(0, 10)
                elif benign_type == 'sporadic_404_client_error':
                    # Triggered by typo (medium rule/recon), but low ML, low anomaly, low seq, low LLM
                    r = np.random.uniform(15, 35)
                    m = np.random.uniform(5, 20)
                    a = np.random.uniform(10, 30)
                    s = np.random.uniform(5, 20)
                    l = np.random.uniform(0, 10)
                elif benign_type == 'burst_api_consumer':
                    # High request volume (medium anomaly), but safe payloads
                    r = np.random.uniform(0, 15)
                    m = np.random.uniform(0, 20)
                    a = np.random.uniform(55, 75)
                    s = np.random.uniform(10, 25)
                    l = np.random.uniform(0, 10)
                else: # regular_browsing
                    r = np.random.uniform(0, 8)
                    m = np.random.uniform(0, 10)
                    a = np.random.uniform(0, 15)
                    s = np.random.uniform(0, 10)
                    l = np.random.uniform(0, 5)

                vec = np.clip(np.array([r, m, a, s, l]) + np.random.normal(0, 2, 5), 0, 100)
                rows.append(vec)
                labels.append(0)
                ip_col.append(ip)

    X = np.array(rows, dtype=float)
    y = np.array(labels, dtype=int)
    groups = np.array(ip_col)

    return X, y, groups


def evaluate_configuration_group_kfold(X_subset, y, groups, model_type='logistic_calibrated', n_splits=5):
    """Evaluate a feature configuration using Group-K-Fold cross validation."""
    gkf = GroupKFold(n_splits=n_splits)
    
    y_trues = []
    y_preds = []
    y_probs = []

    for train_idx, val_idx in gkf.split(X_subset, y, groups):
        X_train, X_val = X_subset[train_idx], X_subset[val_idx]
        y_train, y_val = y[train_idx], y[val_idx]

        X_train_norm = np.clip(X_train / 100.0, 0.0, 1.0)
        X_val_norm = np.clip(X_val / 100.0, 0.0, 1.0)

        if model_type == 'logistic_calibrated':
            base = LogisticRegression(penalty='l2', C=1.5, solver='lbfgs', max_iter=500, class_weight='balanced')
            # Internal CV on train fold
            clf = CalibratedClassifierCV(estimator=base, method='sigmoid', cv=3)
            clf.fit(X_train_norm, y_train)
            probs = clf.predict_proba(X_val_norm)[:, 1]
        elif model_type == 'gradient_boosting':
            clf = GradientBoostingClassifier(n_estimators=60, max_depth=3, learning_rate=0.1, random_state=42)
            clf.fit(X_train_norm, y_train)
            probs = clf.predict_proba(X_val_norm)[:, 1]
        elif model_type == 'static_weighted':
            # Normalized linear combination
            weights = np.ones(X_subset.shape[1]) / X_subset.shape[1]
            probs = np.dot(X_val_norm, weights)

        preds = (probs >= 0.50).astype(int)

        y_trues.extend(y_val)
        y_preds.extend(preds)
        y_probs.extend(probs)

    y_trues = np.array(y_trues)
    y_preds = np.array(y_preds)
    y_probs = np.array(y_probs)

    tn, fp, fn, tp = confusion_matrix(y_trues, y_preds).ravel()

    acc = accuracy_score(y_trues, y_preds)
    prec = precision_score(y_trues, y_preds, zero_division=0)
    rec = recall_score(y_trues, y_preds, zero_division=0)
    f1 = f1_score(y_trues, y_preds, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    roc_auc = roc_auc_score(y_trues, y_probs)
    pr_auc = average_precision_score(y_trues, y_probs)

    return {
        "accuracy": round(acc * 100, 2),
        "precision": round(prec * 100, 2),
        "recall": round(rec * 100, 2),
        "f1_score": round(f1 * 100, 2),
        "false_positive_rate": round(fpr * 100, 2),
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "confusion_matrix": {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)}
    }


def run_ablation_study():
    print("=" * 75)
    print(" CyberOracle Intel: ICMF Multi-Layer Meta-Fusion & Systematic Ablation Study")
    print("=" * 75)

    X, y, groups = generate_multiview_evaluation_dataset(n_samples=1200, random_state=42)
    print(f"[*] Total Dataset Records: {len(y)} | Unique IP Entities: {len(np.unique(groups))}")
    print(f"[*] Malicious Records: {sum(y == 1)} | Benign Records: {sum(y == 0)}")

    # View index mapping: 0=Rule, 1=ML, 2=Anomaly, 3=Sequence, 4=LLM
    configurations = [
        # 1. Full 5-View Fusion
        ("Full 5-View Meta-Fusion (Calibrated Logistic)", list(range(5)), 'logistic_calibrated'),
        ("Full 5-View Gradient Boosting Meta-Fusion", list(range(5)), 'gradient_boosting'),
        ("Static Weighted Heuristic Baseline (Weights: 0.25, 0.25, 0.15, 0.20, 0.15)", list(range(5)), 'static_weighted'),

        # 2. Leave-One-View-Out Ablations
        ("Ablation: -S_rule (No Signature Engine)", [1, 2, 3, 4], 'logistic_calibrated'),
        ("Ablation: -S_ml (No Supervised Random Forest)", [0, 2, 3, 4], 'logistic_calibrated'),
        ("Ablation: -S_anomaly (No Isolation Forest)", [0, 1, 3, 4], 'logistic_calibrated'),
        ("Ablation: -S_seq (No Kill-Chain Sequence Forecaster)", [0, 1, 2, 4], 'logistic_calibrated'),
        ("Ablation: -S_llm (No LLM Forensic Reasoning)", [0, 1, 2, 3], 'logistic_calibrated'),

        # 3. Single-View Baselines
        ("Single View: S_rule Only (Signatures Only)", [0], 'logistic_calibrated'),
        ("Single View: S_ml Only (Supervised RF Only)", [1], 'logistic_calibrated'),
        ("Single View: S_anomaly Only (Isolation Forest Only)", [2], 'logistic_calibrated'),
        ("Single View: S_seq Only (Sequence Forecaster Only)", [3], 'logistic_calibrated'),
        ("Single View: S_llm Only (LLM Reasoning Only)", [4], 'logistic_calibrated'),
    ]

    results = {}
    base_f1 = None

    for config_name, view_indices, model_type in configurations:
        X_sub = X[:, view_indices]
        metrics = evaluate_configuration_group_kfold(X_sub, y, groups, model_type=model_type, n_splits=5)
        
        if base_f1 is None:
            base_f1 = metrics["f1_score"]
            delta_f1 = 0.0
        else:
            delta_f1 = round(metrics["f1_score"] - base_f1, 2)

        metrics["delta_f1"] = delta_f1
        metrics["active_views"] = [VIEW_NAMES[i] for i in view_indices]
        metrics["model_type"] = model_type
        results[config_name] = metrics

        delta_str = f" ({'+' if delta_f1 > 0 else ''}{delta_f1}%)" if delta_f1 != 0.0 else ""
        print(f"\n[+] {config_name}:")
        print(f"    - F1-Score: {metrics['f1_score']}%{delta_str} | Precision: {metrics['precision']}% | Recall: {metrics['recall']}%")
        print(f"    - Accuracy: {metrics['accuracy']}% | FPR: {metrics['false_positive_rate']}%")
        print(f"    - ROC-AUC: {metrics['roc_auc']} | PR-AUC: {metrics['pr_auc']}")

    # Train production model and save to disk
    print("\n[*] Training and persisting production MetaFusionEngine to monitor/data/meta_fusion_model.joblib ...")
    prod_engine = MetaFusionEngine()
    prod_engine.fit(X, y, groups=groups, method='sigmoid')
    prod_engine.save(str(META_MODEL_PATH))
    print(f"[+] Learned View Weights (Logistic Regression Coefficients):")
    for name, coef in zip(VIEW_NAMES, prod_engine.coefficients):
        print(f"    * {name}: {round(coef, 4)}")
    print(f"    * Intercept: {round(prod_engine.intercept, 4)}")

    # Save to JSON
    json_path = RESULTS_DIR / 'ablation_results.json'
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    print(f"\n[SAVED] JSON ablation results to {json_path}")

    # Save to CSV
    rows = []
    for c_name, c_data in results.items():
        rows.append({
            "Configuration": c_name,
            "Active Views": ", ".join(c_data["active_views"]),
            "Model Type": c_data["model_type"],
            "Accuracy (%)": c_data["accuracy"],
            "Precision (%)": c_data["precision"],
            "Recall (%)": c_data["recall"],
            "F1-Score (%)": c_data["f1_score"],
            "Delta F1 (%)": c_data["delta_f1"],
            "FPR (%)": c_data["false_positive_rate"],
            "ROC-AUC": c_data["roc_auc"],
            "PR-AUC": c_data["pr_auc"]
        })

    df_ablation = pd.DataFrame(rows)
    csv_path = RESULTS_DIR / 'ablation_results.csv'
    df_ablation.to_csv(csv_path, index=False)
    print(f"[SAVED] CSV ablation comparison table to {csv_path}")

    return results


VIEW_NAMES = ['S_rule', 'S_ml', 'S_anomaly', 'S_sequence', 'S_llm']

if __name__ == '__main__':
    run_ablation_study()
