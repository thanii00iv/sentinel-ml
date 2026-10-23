"""
Production Latency & Throughput Benchmark Harness for CyberOracle Intel
Measures latency (p50, p95, p99, mean, std dev) and Requests Per Second (RPS) throughput
across 5 separate runs of 1,000 requests each for each analytical pipeline component.
Outputs results to /experiments/results/latency_benchmark.json and latency_benchmark.csv.
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

from monitor.models import RequestLog, IPRiskProfile
from monitor.detection import (
    detect_sqli, detect_xss, detect_path_traversal, calculate_entropy,
    GLOBAL_TELEMETRY_CACHE
)
from monitor.ml_model import predict, predict_anomaly
from monitor.prediction import predict_next_stage_and_asset
from monitor.llm_layer import get_mitre_retriever, HeuristicRAGBackend
from monitor.meta_fusion import predict_fused_risk
from monitor.adaptive_response import recommend_mitigation_action
from monitor.fusion_engine import evaluate_and_fuse_profile

RESULTS_DIR = BASE_DIR / 'experiments' / 'results'
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


class DummyHttpRequest:
    def __init__(self, path: str = '/search/', get_params: dict = None):
        self.path = path
        self.GET = get_params or {'q': "admin' OR '1'='1"}
        self.POST = {}
        self.headers = {'User-Agent': 'Mozilla/5.0'}
        self.META = {'HTTP_USER_AGENT': 'Mozilla/5.0', 'REMOTE_ADDR': '198.51.100.45'}
        self.method = 'GET'

    def get_full_path(self):
        return f"{self.path}?q=admin%27%20OR%20%271%27=%271"


def benchmark_component(name: str, fn, n_runs: int = 5, n_samples_per_run: int = 1000) -> dict:
    """
    Execute n_runs of n_samples_per_run iterations, measuring per-call latency in milliseconds.
    """
    all_latencies_ms = []
    run_means = []

    for run_idx in range(n_runs):
        latencies = []
        for _ in range(n_samples_per_run):
            t0 = time.perf_counter()
            fn()
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000.0)

        all_latencies_ms.extend(latencies)
        run_means.append(float(np.mean(latencies)))

    arr = np.array(all_latencies_ms)
    mean_ms = float(np.mean(arr))
    std_ms = float(np.std(run_means))
    p50_ms = float(np.percentile(arr, 50))
    p95_ms = float(np.percentile(arr, 95))
    p99_ms = float(np.percentile(arr, 99))
    rps = round(1000.0 / mean_ms, 1) if mean_ms > 0 else 0.0

    return {
        'component_name': name,
        'n_runs': n_runs,
        'total_calls': len(arr),
        'mean_latency_ms': round(mean_ms, 4),
        'std_dev_ms': round(std_ms, 4),
        'p50_latency_ms': round(p50_ms, 4),
        'p95_latency_ms': round(p95_ms, 4),
        'p99_latency_ms': round(p99_ms, 4),
        'throughput_rps': rps
    }


def run_latency_benchmarks():
    print("=" * 80)
    print(" CyberOracle Intel: Production Latency & Throughput Benchmark Harness")
    print("=" * 80)
    print("[*] Benchmark Configuration: 5 Runs x 1,000 Invocations per Component (5,000 iterations each)")

    req = DummyHttpRequest()
    dummy_log = RequestLog(
        ip_address="198.51.100.45",
        method="GET",
        path="/search/?q=admin",
        status_code=200,
        response_time_ms=25.0,
        entropy_score=3.8,
        request_rate=5.0,
        is_sqli_suspect=True
    )
    dummy_profile = IPRiskProfile(
        ip_address="198.51.100.45",
        risk_score=75,
        sqli_count=2,
        recon_count=1
    )
    retriever = get_mitre_retriever()
    heuristic_rag = HeuristicRAGBackend()

    benchmarks = [
        ("1. Deterministic Rule Matching (SQLi/XSS/LFI Regex)", lambda: (detect_sqli(req), detect_xss(req), detect_path_traversal(req))),
        ("2. Sliding-Window In-Memory Telemetry Cache", lambda: (GLOBAL_TELEMETRY_CACHE.record_event('198.51.100.45', '/search/', 200), GLOBAL_TELEMETRY_CACHE.get_request_rate('198.51.100.45'))),
        ("3. Supervised Random Forest Inference", lambda: predict(dummy_log)),
        ("4. Isolation Forest Anomaly Detection", lambda: predict_anomaly(dummy_log)),
        ("5. Kill-Chain Next-Stage Sequence Forecaster", lambda: predict_next_stage_and_asset(dummy_profile)),
        ("6. Local TF-IDF MITRE ATT&CK RAG Retriever", lambda: retriever.retrieve_relevant_techniques("union select sql injection", top_k=2)),
        ("7. Calibrated Meta-Fusion Stacking (5 Views)", lambda: predict_fused_risk(75.0, 80.0, 45.0, 70.0, 85.0)),
        ("8. Adaptive Incident Response (LinUCB Action)", lambda: recommend_mitigation_action(dummy_profile, request_rate=5.0)),
        ("9. Full End-to-End Inline Middleware Pipeline", lambda: (
            detect_sqli(req),
            GLOBAL_TELEMETRY_CACHE.record_event('198.51.100.45', '/search/', 200),
            predict(dummy_log),
            predict_anomaly(dummy_log),
            predict_fused_risk(75.0, 80.0, 45.0, 70.0, 85.0)
        ))
    ]

    results = {}
    rows = []

    for name, fn in benchmarks:
        metrics = benchmark_component(name, fn, n_runs=5, n_samples_per_run=1000)
        results[name] = metrics
        rows.append({
            'Pipeline Component': name,
            'Mean Latency (ms)': metrics['mean_latency_ms'],
            'Std Dev (ms)': metrics['std_dev_ms'],
            'p50 Latency (ms)': metrics['p50_latency_ms'],
            'p95 Latency (ms)': metrics['p95_latency_ms'],
            'p99 Latency (ms)': metrics['p99_latency_ms'],
            'Throughput (RPS)': metrics['throughput_rps']
        })

        print(f"\n[+] {name}:")
        print(f"    - Mean Latency: {metrics['mean_latency_ms']} ms ± {metrics['std_dev_ms']} ms | Throughput: {metrics['throughput_rps']} RPS")
        print(f"    - p50: {metrics['p50_latency_ms']} ms | p95: {metrics['p95_latency_ms']} ms | p99: {metrics['p99_latency_ms']} ms")

    # Save to JSON
    json_path = RESULTS_DIR / 'latency_benchmark.json'
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    print(f"\n[SAVED] JSON latency benchmark report to {json_path}")

    # Save to CSV
    df = pd.DataFrame(rows)
    csv_path = RESULTS_DIR / 'latency_benchmark.csv'
    df.to_csv(csv_path, index=False)
    print(f"[SAVED] CSV latency benchmark table to {csv_path}")

    return results


if __name__ == '__main__':
    run_latency_benchmarks()
