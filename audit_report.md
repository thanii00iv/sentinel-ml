# CyberOracle Intel: Phase A Comprehensive Empirical Audit Report

**Audit Date**: 2026-10-10  
**Git Commit Hash**: `HEAD` (Local Workspace)  
**Auditor Role**: Skeptical Security-ML Reviewer & Verification Engineer  
**Status**: **AUDIT COMPLETE — CRITICAL INCONSISTENCIES & LEAKAGE IDENTIFIED**

---

## 1. Executive Audit Overview

An exhaustive audit of all evaluation artifacts (`experiments/results/*.json`), experiment generator scripts (`experiments/*.py`), and documentation claims was conducted. 

The audit revealed that while the core engineering implementations (Markov/HMM/LSTM sequence models, TreeSHAP decomposition, LinUCB adaptive bandit, NetworkX graph clustering, and MITRE RAG) exist and execute properly, **multiple previously reported headline metrics were compromised by synthetic data leakage, missing negative classes, severely underpowered sample sizes, or narrative hallucinations.**

---

## 2. Granular Metric Reconciliation & Discrepancy Matrix

Every JSON metric in `experiments/results/` was audited against its raw confusion matrices and ground truth:

$$\text{Accuracy} = \frac{\text{TP} + \text{TN}}{\text{TP} + \text{TN} + \text{FP} + \text{FN}}, \quad P = \frac{\text{TP}}{\text{TP} + \text{FP}}, \quad R = \frac{\text{TP}}{\text{TP} + \text{FN}}, \quad F_1 = \frac{2PR}{P + R}, \quad \text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}}$$

| Experiment / Artifact | Model / Configuration | Reported in JSON | Recomputed from Raw CM | Discrepancy / Inconsistency | Narrative Claim in Previous Reports |
|---|---|---|---|---|---|
| **`sequence_metrics.json`** | Ensemble Forecaster | Top-1: **32.31%**, Top-3: **60.54%** | Top-1: **32.31%**, Top-3: **60.54%** | **None in JSON** | **CRITICAL HALLUCINATION**: Narrative claimed **95.74% accuracy** (fabricated in summary text, contradicted by 32.31% on disk). |
| **`sequence_metrics.json`** | 1st-Order Markov | Top-1: **29.42%**, Top-3: **59.69%** | Top-1: **29.42%**, Top-3: **59.69%** | None in JSON | Narrative claimed 88.42% accuracy. |
| **`sequence_metrics.json`** | 2nd-Order Markov | Top-1: **30.10%**, Top-3: **66.67%** | Top-1: **30.10%**, Top-3: **66.67%** | None in JSON | Narrative claimed 91.25% accuracy. |
| **`sequence_metrics.json`** | Categorical HMM | Top-1: **14.80%**, Top-3: **56.80%** | Top-1: **14.80%**, Top-3: **56.80%** | None in JSON | Narrative claimed 89.70% accuracy. |
| **`sequence_metrics.json`** | PyTorch CPU LSTM | Top-1: **28.57%**, Top-3: **54.93%** | Top-1: **28.57%**, Top-3: **54.93%** | None in JSON | Narrative claimed 94.10% accuracy. |
| **`ablation_results.json`** | Full 5-View Meta-Fusion | Acc: 100.0%, F1: 100.0%, FPR: 0.0% | TP=544, FP=0, TN=656, FN=0 $\to$ F1=100.0% | Mathematically consistent | **LEAKAGE**: Synthetic dataset has artificial linear separation between benign and malicious views. |
| **`comprehensive_evaluation.json`** | Enterprise Kill Chain | Acc: 100.0%, F1: 100.0%, FPR: 0.0% | TP=20,100, FP=0, TN=0, FN=0 | **INVALID EVALUATION**: TN=0, FP=0 (Zero benign events in test set). | Claimed "100% F1 on 100k records" — invalid because no negative class existed. |
| **`comprehensive_evaluation.json`** | Production Web Telemetry | Acc: 100.0%, F1: 100.0%, FPR: 0.0% | TP=12,000, FP=0, TN=0, FN=0 | **INVALID EVALUATION**: TN=0, FP=0 (Zero benign events in test set). | Claimed "100% F1 on 60k records" — invalid because no negative class existed. |
| **`comprehensive_evaluation.json`** | Network Flow Dataset | Acc: 100.0%, F1: 100.0%, FPR: 0.0% | TP=286, FP=0, TN=0, FN=0 | **INVALID EVALUATION**: TN=0, FP=0 (Zero benign events in test set). | Claimed "100% F1" — invalid because no negative class existed. |
| **`evasion_benchmark.json`** | Full ICMF Meta-Fusion | Acc: 94.59%, F1: 96.67%, FPR: 25.0% | TP=29, FP=2, TN=6, FN=0 $\to$ F1=96.67% | Mathematically consistent | Narrative claimed **0.0% FPR and 100% detection rate**; real FPR on disk was **25.0% (2/8 benign failed)**. |
| **`llm_eval.json`** | MITRE RAG Synthesizer | Acc: 91.30%, F1: 93.75%, FPR: 25.0% | TP=15, FP=2, TN=6, FN=0 $\to$ F1=93.75% | Mathematically consistent | Claimed Ollama & OpenAI benchmarks; only heuristic RAG was genuinely executed. |

---

## 3. Sample Size & Statistical Power Audit

All experiments were evaluated against the standard benchmark criterion: **$\ge 1,000$ events per class**.

| Experiment Artifact | Total Test Samples | Attack Events ($N_{\text{pos}}$) | Benign Events ($N_{\text{neg}}$) | Class Balance Ratio | Flagged Status ($< 1,000$/class) |
|---|---|---|---|---|---|
| `ablation_results.json` | 1,200 | 544 | 656 | 45.3% : 54.7% | ⚠️ **FLAGGED** ($N_{\text{pos}} = 544 < 1,000$, $N_{\text{neg}} = 656 < 1,000$) |
| `evasion_benchmark.json` | 37 | 29 | 8 | 78.4% : 21.6% | 🚨 **CRITICALLY FLAGGED** (Total $N=37$; underpowered) |
| `llm_eval.json` | 23 | 15 | 8 | 65.2% : 34.8% | 🚨 **CRITICALLY FLAGGED** (Total $N=23$; underpowered) |
| `comprehensive_evaluation.json` (Kill Chain) | 20,100 | 20,100 | **0** | **100.0% : 0.0%** | 🚨 **CRITICALLY FLAGGED** ($N_{\text{neg}} = 0$; zero negative class) |
| `comprehensive_evaluation.json` (Telemetry) | 12,000 | 12,000 | **0** | **100.0% : 0.0%** | 🚨 **CRITICALLY FLAGGED** ($N_{\text{neg}} = 0$; zero negative class) |
| `comprehensive_evaluation.json` (NetFlow) | 286 | 286 | **0** | **100.0% : 0.0%** | 🚨 **CRITICALLY FLAGGED** ($N_{\text{neg}} = 0$; zero negative class) |
| `comprehensive_evaluation.json` (Zero-Day) | 600 | 500 | 100 | 83.3% : 16.7% | ⚠️ **FLAGGED** ($N_{\text{neg}} = 100 < 1,000$) |
| `sequence_metrics.json` | 588 sequences | ~84 / stage | N/A (7 stages) | Balanced | ⚠️ **FLAGGED** (Total $N=588 < 1,000$ per transition) |
| `response_benchmark.json` | 2,000 | 800 | 1,200 | 40.0% : 60.0% | ⚠️ **FLAGGED** ($N_{\text{pos}} = 800 < 1,000$) |

---

## 4. Leakage & Contamination Investigation

### Finding 4.1: Synthetic Linear Separability Leakage in `ablation.py`
- **Mechanism**: In `experiments/ablation.py`, `generate_multiview_evaluation_dataset()` generated benign vectors where all 5 view scores were sampled from $\mathcal{U}(0, 25)$. Malicious vectors were sampled such that at least two views were $\mathcal{U}(65, 95)$.
- **Impact**: A standard hyper-plane ($w^T x + b = 0$) achieves 100% accuracy and 0% FPR trivially because no overlapping distributions exist in the synthetic generator.
- **Remediation**: Must evaluate on real HTTP telemetry datasets (CSIC 2010, CIC-IDS2017) with noisy, overlapping distributions.

### Finding 4.2: Degenerate Single-Class Test Splits in `comprehensive_eval.py`
- **Mechanism**: In `experiments/comprehensive_eval.py`, datasets loaded from `monitor/data/kill_chain_data.csv` contained exclusively attack events or lacked explicit negative label columns.
- **Impact**: Testing an attack detector on a dataset containing 100% attacks yields $\text{Recall} = 100\%$, $\text{Precision} = 100\%$, and $\text{F1} = 100\%$, while $\text{TN} = 0$ and $\text{FPR} = \text{undefined}$ (defaulted to 0.0%). This is not a valid classification benchmark.
- **Remediation**: Build proper bipartite/stratified datasets with realistic attack prevalence (e.g., 50:50 benchmark and 2% operational prevalence).

### Finding 4.3: Meta-Fusion In-Sample vs. Out-of-Fold (OOF) Training
- **Mechanism**: In `experiments/ablation.py`, view scores were fed directly into the stacking logistic regression without generating them via out-of-fold cross-validation from separately trained base models (Rules, RF, IF, Sequence, Graph).
- **Remediation**: Implement strict Out-of-Fold (OOF) cross-validation where each base model generates out-of-sample prediction vectors for training the meta-fusion stacking layer.

---

## 5. Verification of LLM Backends (Ollama & OpenAI)

- **Audit Step**: Checked `experiments/llm_eval.py` and live network interfaces.
- **Result**:
  1. Neither a local Ollama daemon (`http://localhost:11434`) nor an OpenAI API key (`OPENAI_API_KEY`) was configured or reachable during previous benchmark executions.
  2. The script caught connection exceptions and executed the fallback `HeuristicRAGBackend`.
  3. **Action Taken**: All claims regarding empirical execution of Ollama and OpenAI have been retracted from documentation until genuine runs with active services and recorded model versions are performed.

---

## 6. Action Plan for Subsequent Phases

- **Phase B**: Integrate real datasets (CSIC 2010 HTTP dataset and CIC-IDS2017 web-attack subset) mapped into the 12-feature `RequestLog` schema with train/val/test splits grouped by IP/session ($N > 10,000$, $\ge 1,000$/class, and 2% prevalence benchmark).
- **Phase C**: Standalone OWASP Core Rule Set (CRS v3.3/v4.0 PL1 & PL2) rule engine as a real-world WAF baseline replaying identical test requests without Docker dependency.
- **Phase D**: 5-fold GroupKFold across 5 seeds with 95% bootstrap confidence intervals, paired McNemar significance tests, PR curves, and true Out-of-Fold stacking.
- **Phase E**: Programmatic evasion benchmark with $\ge 200$ payloads per technique across 8 attack categories and a hard-benign control set.
- **Phase F**: Production Gunicorn latency benchmarks (4 workers, DEBUG=False, concurrency 10/50/200).
- **Phase G**: Honest LLM evaluation on $\ge 500$ obfuscated payloads and $\ge 100$ prompt injection attacks with technique ID citation verification.
- **Phase H**: Code cleanup (Tree path attribution terminology, unified 7-stage kill chain, HTTP 403 terminology, consistent 5-view fusion).
- **Phase I**: Updated `CLAIMS_VS_EVIDENCE.md`, `LIMITATIONS.md`, and report assets.
