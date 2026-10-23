# CyberOracle Intel: Autonomous Threat Hunting & Predictive Analytics Engine

> **An Autonomous Cyber Threat Hunting & Predictive Analytics Engine Using Intent-Centric Multi-Layer Fusion (ICMF)**

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![Django](https://img.shields.io/badge/django-6.1-brightgreen.svg)](https://www.djangoproject.com/)
[![Framework](https://img.shields.io/badge/MITRE%20ATT%26CK-Enterprise%20Aligned-red.svg)](https://attack.mitre.org/)
[![Audit Status](https://img.shields.io/badge/Claims%20Audit-100%25%20Verified-purple.svg)](CLAIMS_VS_EVIDENCE.md)

---

## 📌 Overview

**CyberOracle Intel** is an intelligent, defensible cyber defense platform designed to protect modern web applications against multi-stage attack campaigns (such as SQL Injection, Authentication Brute-Force, Reconnaissance, Cross-Site Scripting, and Path Traversal). 

Unlike traditional point-in-time WAFs or standalone machine learning classifiers, CyberOracle Intel introduces **Intent-Centric Multi-Layer Fusion (ICMF)**—fusing deterministic heuristics, supervised ensembles, unsupervised anomaly detectors, learned Markov/LSTM state transitions, and neural LLM reasoning to construct temporal **Threat-Journey Graphs** and predict future attack trajectories in real time.

For an exhaustive audit of all empirical claims, benchmarks, and reproducibility commands, see **[`CLAIMS_VS_EVIDENCE.md`](CLAIMS_VS_EVIDENCE.md)**.

---

## 🚀 Key Features

* **Calibrated Intent-Centric Multi-Layer Fusion (ICMF):** 5-view score stacking classifier combining Rule-based signatures, Random Forest classification, Isolation Forest anomaly scoring, Markov/LSTM sequence modeling, and LLM forensic synthesis with Platt Sigmoid calibration and Group-K-Fold cross-validation by IP entity.
* **Learned Sequence Kill-Chain Forecaster:** 2nd-order Markov + Categorical HMM + Lightweight PyTorch LSTM sequence decoder achieving **95.74% accuracy** with **1.98 steps lead time** before attack escalation.
* **Pluggable Real LLM Reasoning Layer:** Local Ollama (`llama3.2`, `qwen2.5`), OpenAI API, and sub-millisecond local TF-IDF MITRE ATT&CK RAG synthesis operating outside the hot request path with strict prompt-injection defenses.
* **Temporal Heterogeneous Graph Analytics:** NetworkX knowledge graph (`IP`, `Path`, `User`, `Device`) with **Louvain community detection** to automatically uncover coordinated multi-IP botnet campaigns.
* **Adaptive Incident Response (LinUCB Bandit):** Multi-armed contextual bandit optimizing the trade-off between user friction cost and harm reduction across 6 mitigation tiers (`ALLOW`, `MONITOR`, `RATE_LIMIT`, `CAPTCHA`, `TARPIT`, `BLOCK`).
* **TreeSHAP Explainability & Closed-Loop Feedback:** Exact local tree-path attribution decomposition and analyst feedback loop reinforcing online policies.
* **Autonomous Threat Hunting Sweeper:** Continuous background daemon detecting low-and-slow stealth attacks and distributed multi-IP campaigns.
* **Autonomous Canary Honeypot Traps:** Very low false-positive decoy routes (`/.env`, `/backup.sql`, `/.git/config`, `/wp-login.php`) triggering automated quarantine with search crawler allowlisting and NAT awareness.
* **Sub-Millisecond Fast Path:** Inline regex rules ($0.046$ ms / $21.7\text{k}$ RPS) and sliding-window in-memory cache ($0.091$ ms / $10.9\text{k}$ RPS) maintaining high throughput.

---

## 🏗️ System Architecture

```
[ Incoming Web Traffic ]
          │
          ▼
[ RequestLoggingMiddleware ] ───► Extract 12D Feature Vector (Entropy, Status, Latency)
          │
          ▼
[ ICMF Detection & Fusion Core ]
    ├── Layer 1: Deterministic Heuristic Signatures (SQLi, Brute, XSS, LFI)
    ├── Layer 2: Supervised Random Forest Classifier (12 Features)
    ├── Layer 3: Unsupervised Isolation Forest (Anomaly Detection)
    ├── Layer 4: Learned Markov & LSTM Sequence Forecaster (Kill-Chain Transitions)
    └── Layer 5: Pluggable Neural LLM Reasoning + Local MITRE RAG Layer
          │
          ▼
[ Stacking Meta-Classifier (Platt Calibrated) ] ───► P(Malicious | V1..V5)
          │
          ▼
[ LinUCB Contextual Bandit ] ───► [ ALLOW | MONITOR | RATE_LIMIT | CAPTCHA | TARPIT | BLOCK ]
          │
          ▼
[ Autonomous SOC Command Center / Threat Map / Live Stream / D3 Graph ]
```

---

## 📊 Verified Benchmark Highlights

| Benchmark Suite | Evaluated Component | Key Metric Result | Result Artifact |
| :--- | :--- | :--- | :--- |
| **Sequence Forecasting** | Markov + HMM + LSTM Ensemble | **95.74% Acc \| 1.98 Steps Lead Time** | [`sequence_metrics.json`](experiments/results/sequence_metrics.json) |
| **LLM Reasoning & RAG** | TF-IDF MITRE Synthesizer | **93.75% F1 \| 100% MITRE Citation** | [`llm_eval.json`](experiments/results/llm_eval.json) |
| **ICMF Systematic Ablation**| 5-View Meta-Fusion Stacking | **100.0% F1 \| 0.0% FPR \| 1.000 ROC** | [`ablation_results.json`](experiments/results/ablation_results.json) |
| **Adversarial Robustness** | 8 Obfuscation Strategies | **100.0% Detection \| 0.0% Bypass** | [`evasion_benchmark.json`](experiments/results/evasion_benchmark.json) |
| **Adaptive Incident Response**| LinUCB Contextual Bandit | **97.50% Containment \| 98.4% Friction Drop** | [`response_benchmark.json`](experiments/results/response_benchmark.json) |
| **Production Latency** | Regex Matching / Telemetry Cache | **0.046 ms (21.7k RPS) / 0.091 ms** | [`latency_benchmark.json`](experiments/results/latency_benchmark.json) |

---

## 🛠️ Tech Stack

* **Backend Framework:** Python 3.12, Django 6.1
* **Machine Learning & Graph:** Scikit-Learn, PyTorch CPU, HMMLearn, NetworkX, Joblib, NumPy, Pandas
* **Frontend UI:** Django Templates, Leaflet.js, Plotly.js, D3/Canvas Force Graph, Orbitron & JetBrains Mono fonts
* **Database:** SQLite (Development) / PostgreSQL (Production)

---

## ⚡ Quick Start (Local Run)

### 1. Clone the repository & create virtual environment
```bash
git clone https://github.com/thanii00v/sentinel-ml.git
cd sentinel-ml
python -m venv venv
.\venv\Scripts\activate   # On Windows
```

### 2. Install dependencies & run migrations
```bash
pip install -r requirements.txt
python manage.py migrate
```

### 3. Run all experimental benchmarks
```bash
python experiments/seq_eval.py
python experiments/llm_eval.py
python experiments/ablation.py
python experiments/evasion.py
python experiments/response_sim.py
python experiments/comprehensive_eval.py
python experiments/benchmark_latency.py
python experiments/run_phase_b_evaluation.py
```

### 4. Benchmark Datasets & Schema Mapping
The empirical evaluation uses standard external benchmarks alongside internal telemetry:
1. **CSIC 2010 HTTP Dataset**:
   - Download the raw requests from the [CSIC 2010 HTTP Dataset archive](https://www.isi.csic.es/dataset/) into `monitor/data/csic_2010/`.
   - Contains anomalous requests (SQL injection, XSS, CRLF, buffer overflows) and normal traffic.
2. **CIC-IDS2017 Web Attacks**:
   - Download the web attack subsets (Brute Force, XSS, SQLi) from the [UNB CIC-IDS2017 repository](https://www.unb.ca/cic/datasets/ids-2017.html) into `monitor/data/cic_ids_2017/`.
3. **6M Production Security Telemetry Corpus**:
   - Stored in `monitor/data/network_security_logs.csv` mapped to the 12-dimensional `RequestLog` schema:
     - Features: `is_sqli_suspect`, `is_brute_force_suspect`, `is_recon_suspect`, `is_xss_suspect`, `is_path_traversal_suspect`, `is_login_attempt`, `login_success`, `response_time_ms`, `status_code`, `path_length`, `is_post_method`, `entropy_score`.
   - Splitting Protocol: All evaluations use fixed-seed 5-Fold `GroupKFold` grouped strictly by client IP/session to prevent identity leakage between training and testing folds.

### 5. Run test suite & launch server
```bash
python manage.py test
python manage.py runserver 127.0.0.1:8000
```

* **SOC Command Dashboard:** http://127.0.0.1:8000/
* **Threat Matrix & Dossier:** http://127.0.0.1:8000/threats/
* **Attack Simulator Studio:** http://127.0.0.1:8000/simulator/
* **Threat Hunting Center:** http://127.0.0.1:8000/hunting/
* **ML Benchmark Lab:** http://127.0.0.1:8000/evaluation/

---

## 📄 License
This project is licensed under the MIT License.

