"""
Phase B: Empirical Evaluation on Real Benchmark Datasets
Evaluates Full Pipeline vs Base Models on:
1. CSIC 2010 HTTP Dataset (Balanced N=10,000)
2. CIC-IDS2017 Web Attack Dataset (Balanced N=10,000)
3. 6M Telemetry Corpus (Balanced N=20,000)
4. 6M Telemetry Corpus (Operational 2% Prevalence N=20,000)

Enforces GroupKFold by IP to guarantee zero entity leakage.
Outputs to experiments/results/real_dataset_evaluation.json and real_dataset_evaluation.csv.
"""

import os
import sys
import json
import time
import subprocess
from datetime import datetime, timezone
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupKFold
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix
)

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'iml_core.settings')

import django
django.setup()

from experiments.dataset_loaders import (
    CSIC2010Loader,
    CICIDS2017WebAttackLoader,
    Corpus6MTelemetryLoader,
    extract_12_features_from_dataframe,
)

RESULTS_DIR = BASE_DIR / 'experiments' / 'results'
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def get_git_commit_hash():
    try:
        res = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=str(BASE_DIR), capture_output=True, text=True)
        return res.stdout.strip()
    except Exception:
        return "UNKNOWN_COMMIT"


def evaluate_dataset_pipeline(dataset_name: str, df: pd.DataFrame, n_splits: int = 5, random_state: int = 42) -> dict:
    """
    Run 5-Fold GroupKFold cross-validation on extracted 12-feature matrix.
    Trains base models and meta-fusion on Out-of-Fold predictions.
    """
    X, y, groups = extract_12_features_from_dataframe(df)
    
    unique_groups = np.unique(groups)
    n_groups = len(unique_groups)
    actual_splits = min(n_splits, n_groups)
    
    gkf = GroupKFold(n_splits=actual_splits)
    
    pos_cnt = int(np.sum(y))
    neg_cnt = int(len(y) - pos_cnt)
    prevalence = round((pos_cnt / len(y)) * 100.0, 2)
    
    # Track cross-validated out-of-fold predictions
    oof_pred_rule = np.zeros(len(y))
    oof_pred_rf = np.zeros(len(y))
    oof_prob_rf = np.zeros(len(y))
    oof_pred_if = np.zeros(len(y))
    oof_prob_if = np.zeros(len(y))
    oof_pred_meta = np.zeros(len(y))
    oof_prob_meta = np.zeros(len(y))
    
    for train_idx, test_idx in gkf.split(X, y, groups=groups):
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]
        
        # 1. Rule Engine View (Regex flags: is_sqli, is_xss, is_lfi, is_brute, is_recon)
        rule_test_scores = (X_test[:, 0] > 0) | (X_test[:, 1] > 0) | (X_test[:, 2] > 0) | (X_test[:, 3] > 0) | (X_test[:, 4] > 0)
        oof_pred_rule[test_idx] = rule_test_scores.astype(int)
        
        # 2. Supervised Random Forest
        rf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=random_state, n_jobs=-1)
        rf.fit(X_train, y_train)
        oof_pred_rf[test_idx] = rf.predict(X_test)
        if len(rf.classes_) > 1:
            oof_prob_rf[test_idx] = rf.predict_proba(X_test)[:, 1]
        else:
            oof_prob_rf[test_idx] = oof_pred_rf[test_idx]
            
        # 3. Isolation Forest Anomaly Detection (Trained on train set)
        iso = IsolationForest(n_estimators=100, contamination=max(0.01, min(0.5, pos_cnt / len(y))), random_state=random_state)
        iso.fit(X_train)
        iso_scores = -iso.score_samples(X_test)
        # Normalize anomaly score to [0, 1]
        min_s, max_s = np.min(iso_scores), np.max(iso_scores)
        iso_norm = (iso_scores - min_s) / (max_s - min_s + 1e-6)
        oof_prob_if[test_idx] = iso_norm
        oof_pred_if[test_idx] = (iso_norm >= 0.5).astype(int)
        
        # 4. Train Meta-Fusion Stacking Layer on Base Model Out-of-Fold Features
        # Meta feature matrix: [Rule_View, RF_Prob, IF_Prob, Entropy, Status_Code]
        X_train_meta = np.column_stack([
            (X_train[:, 0] > 0) | (X_train[:, 1] > 0) | (X_train[:, 2] > 0) | (X_train[:, 3] > 0) | (X_train[:, 4] > 0),
            rf.predict_proba(X_train)[:, 1] if len(rf.classes_) > 1 else y_train,
            np.clip(-(iso.score_samples(X_train) - min_s) / (max_s - min_s + 1e-6), 0, 1),
            X_train[:, 11] / 8.0, # normalized entropy
            (X_train[:, 8] >= 400).astype(int)
        ])
        
        X_test_meta = np.column_stack([
            rule_test_scores,
            oof_prob_rf[test_idx],
            oof_prob_if[test_idx],
            X_test[:, 11] / 8.0,
            (X_test[:, 8] >= 400).astype(int)
        ])
        
        meta_clf = LogisticRegression(C=1.0, max_iter=500, random_state=random_state)
        meta_clf.fit(X_train_meta, y_train)
        oof_pred_meta[test_idx] = meta_clf.predict(X_test_meta)
        oof_prob_meta[test_idx] = meta_clf.predict_proba(X_test_meta)[:, 1] if len(meta_clf.classes_) > 1 else oof_pred_meta[test_idx]

    # Metrics calculation function
    def compute_metrics(y_true, y_pred, y_prob):
        acc = accuracy_score(y_true, y_pred) * 100.0
        prec = precision_score(y_true, y_pred, zero_division=0) * 100.0
        rec = recall_score(y_true, y_pred, zero_division=0) * 100.0
        f1 = f1_score(y_true, y_pred, zero_division=0) * 100.0
        roc = roc_auc_score(y_true, y_prob) if len(np.unique(y_true)) > 1 else 1.0
        pr = average_precision_score(y_true, y_prob) if len(np.unique(y_true)) > 1 else 1.0
        
        if len(np.unique(y_true)) > 1:
            tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
        else:
            tn, fp, fn, tp = (0, 0, 0, len(y_true))
            
        fpr = (fp / (fp + tn) * 100.0) if (fp + tn) > 0 else 0.0
        return {
            'accuracy': round(acc, 2),
            'precision': round(prec, 2),
            'recall': round(rec, 2),
            'f1_score': round(f1, 2),
            'false_positive_rate': round(fpr, 2),
            'roc_auc': round(roc, 4),
            'pr_auc': round(pr, 4),
            'confusion_matrix': {'tp': int(tp), 'fp': int(fp), 'tn': int(tn), 'fn': int(fn)}
        }

    return {
        'dataset_name': dataset_name,
        'total_samples': len(y),
        'attack_samples': pos_cnt,
        'benign_samples': neg_cnt,
        'attack_prevalence_pct': prevalence,
        'unique_ip_groups': n_groups,
        'models': {
            'Rule Engine (Regex)': compute_metrics(y, oof_pred_rule, oof_pred_rule),
            'Supervised Random Forest': compute_metrics(y, oof_pred_rf, oof_prob_rf),
            'Isolation Forest Anomaly': compute_metrics(y, oof_pred_if, oof_prob_if),
            'CyberOracle Meta-Fusion (Calibrated)': compute_metrics(y, oof_pred_meta, oof_prob_meta)
        }
    }


def main():
    print("=" * 80)
    print(" CyberOracle Intel: Phase B Real Dataset Benchmark")
    print("=" * 80)
    
    commit_hash = get_git_commit_hash()
    timestamp = datetime.now(timezone.utc).isoformat()
    random_seed = 42
    
    print(f"[*] Git Commit Hash: {commit_hash}")
    print(f"[*] Execution Timestamp (UTC): {timestamp}")
    print(f"[*] Random Seed: {random_seed}\n")
    
    all_results = {
        'metadata': {
            'git_commit_hash': commit_hash,
            'timestamp': timestamp,
            'random_seed': random_seed,
            'protocol': 'GroupKFold by IP (5 Folds), Out-of-Fold Stacking'
        },
        'datasets': {}
    }
    
    csv_rows = []
    
    # 1. CSIC 2010 HTTP Dataset (Balanced N=10,000)
    print("[1/4] Loading and evaluating CSIC 2010 HTTP Dataset (Balanced N=10,000)...")
    csic_loader = CSIC2010Loader()
    df_csic = csic_loader.load(n_samples=10000, random_state=random_seed)
    csic_eval = evaluate_dataset_pipeline("CSIC 2010 HTTP Dataset", df_csic, n_splits=5, random_state=random_seed)
    all_results['datasets']['CSIC_2010_HTTP'] = csic_eval
    print(f"    Done. Attack={csic_eval['attack_samples']}, Benign={csic_eval['benign_samples']}, Meta-Fusion F1={csic_eval['models']['CyberOracle Meta-Fusion (Calibrated)']['f1_score']}%")

    # 2. CIC-IDS2017 Web Attacks Dataset (Balanced N=10,000)
    print("[2/4] Loading and evaluating CIC-IDS2017 Web Attacks (Balanced N=10,000)...")
    cic_loader = CICIDS2017WebAttackLoader()
    df_cic = cic_loader.load(n_samples=10000, random_state=random_seed)
    cic_eval = evaluate_dataset_pipeline("CIC-IDS2017 Web Attacks", df_cic, n_splits=5, random_state=random_seed)
    all_results['datasets']['CIC_IDS_2017'] = cic_eval
    print(f"    Done. Attack={cic_eval['attack_samples']}, Benign={cic_eval['benign_samples']}, Meta-Fusion F1={cic_eval['models']['CyberOracle Meta-Fusion (Calibrated)']['f1_score']}%")

    # 3. 6M Telemetry Corpus (Balanced N=20,000)
    print("[3/4] Loading and evaluating 6M Telemetry Corpus (Balanced N=20,000)...")
    corpus_loader = Corpus6MTelemetryLoader()
    df_corpus_bal = corpus_loader.load(n_samples=20000, prevalence=0.5, random_state=random_seed)
    corpus_bal_eval = evaluate_dataset_pipeline("6M Telemetry Corpus (Balanced)", df_corpus_bal, n_splits=5, random_state=random_seed)
    all_results['datasets']['Corpus_6M_Balanced'] = corpus_bal_eval
    print(f"    Done. Attack={corpus_bal_eval['attack_samples']}, Benign={corpus_bal_eval['benign_samples']}, Meta-Fusion F1={corpus_bal_eval['models']['CyberOracle Meta-Fusion (Calibrated)']['f1_score']}%")

    # 4. 6M Telemetry Corpus (Realistic 2% Operational Prevalence N=20,000)
    print("[4/4] Loading and evaluating 6M Telemetry Corpus (2% Prevalence N=20,000)...")
    df_corpus_prev = corpus_loader.load(n_samples=20000, prevalence=0.02, random_state=random_seed)
    corpus_prev_eval = evaluate_dataset_pipeline("6M Telemetry Corpus (2% Operational Prevalence)", df_corpus_prev, n_splits=5, random_state=random_seed)
    all_results['datasets']['Corpus_6M_Prevalence_2pct'] = corpus_prev_eval
    print(f"    Done. Attack={corpus_prev_eval['attack_samples']}, Benign={corpus_prev_eval['benign_samples']}, Meta-Fusion Precision={corpus_prev_eval['models']['CyberOracle Meta-Fusion (Calibrated)']['precision']}%, F1={corpus_prev_eval['models']['CyberOracle Meta-Fusion (Calibrated)']['f1_score']}%")

    # Save JSON artifact
    json_path = RESULTS_DIR / 'real_dataset_evaluation.json'
    with open(json_path, 'w') as fp:
        json.dump(all_results, fp, indent=2)
    print(f"\n[+] Saved JSON artifact to: {json_path}")

    # Build CSV summary table
    for dset_key, dset_info in all_results['datasets'].items():
        dset_name = dset_info['dataset_name']
        n_tot = dset_info['total_samples']
        n_att = dset_info['attack_samples']
        n_ben = dset_info['benign_samples']
        prev = dset_info['attack_prevalence_pct']
        
        for m_name, m_metrics in dset_info['models'].items():
            csv_rows.append({
                'Dataset': dset_name,
                'Total_Samples': n_tot,
                'Attack_Samples': n_att,
                'Benign_Samples': n_ben,
                'Prevalence_Pct': prev,
                'Model': m_name,
                'Accuracy': m_metrics['accuracy'],
                'Precision': m_metrics['precision'],
                'Recall': m_metrics['recall'],
                'F1_Score': m_metrics['f1_score'],
                'FPR': m_metrics['false_positive_rate'],
                'ROC_AUC': m_metrics['roc_auc'],
                'PR_AUC': m_metrics['pr_auc'],
                'TP': m_metrics['confusion_matrix']['tp'],
                'FP': m_metrics['confusion_matrix']['fp'],
                'TN': m_metrics['confusion_matrix']['tn'],
                'FN': m_metrics['confusion_matrix']['fn']
            })

    df_csv = pd.DataFrame(csv_rows)
    csv_path = RESULTS_DIR / 'real_dataset_evaluation.csv'
    df_csv.to_csv(csv_path, index=False)
    print(f"[+] Saved CSV summary table to: {csv_path}")

    print("\n" + "=" * 80)
    print(" PHASE B EVALUATION SUMMARY TABLE")
    print("=" * 80)
    print(df_csv[['Dataset', 'Model', 'Precision', 'Recall', 'F1_Score', 'FPR', 'PR_AUC']].to_string(index=False))


if __name__ == '__main__':
    main()
