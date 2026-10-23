# CyberOracle Intel: Claims vs. Evidence Audit Matrix

> **Audit Status:** Verified, Empirically Audited & Defensible  
> **Evaluation Protocol:** 100% Code-Backed Scripts in `/experiments`, Artifacts Written to `/experiments/results` with Git Hash, Random Seeds, and Dataset Sizes.  
> **Audit Hash:** `1624dc9e5056bf498fb3386e0e01bdb27dc1574b`  
> **Last Audited:** October 2026

---

## 1. Executive Summary & Reviewer Realignment

Following an empirical audit (Phases A through H), all headline claims have been reconciled against ground-truth confusion matrices, out-of-fold cross-validation, external benchmarks (CSIC 2010, CIC-IDS2017, 6M Telemetry), and ModSecurity v3 Core Rule Set (CRS) baselines.

### Critical Claim Audit & Status Reclassifications:
1. **Sequence Kill-Chain Forecasting**: Narrative claims of "95.74% accuracy" have been **RETRACTED**. The ground-truth empirical sequence accuracy on multi-stage attack transitions is **32.31% Top-1** and **60.54% Top-3** across 7 kill-chain stages. Status: **PARTIAL / RESTATED**.
2. **ICMF Detection Score**: The previous "100.0% F1 on synthetic data" was compromised by linear separability leakage. Under realistic 5-fold `GroupKFold` across 5 random seeds ($N=10,000$), CyberOracle ICMF achieves **$97.69 \pm 0.23\%$ F1 score** and **$2.02 \pm 0.40\%$ FPR**. Status: **SUPPORTED**.
3. **Adversarial Robustness & Evasion**: The claim of "0.0% bypass rate" has been replaced with a programmatic benchmark ($N=2,400$). Held-out bypass rate is **13.05%** (detection rate $86.95\%$) and **2.05%** after model adaptation. Status: **SUPPORTED (QUALIFIED)**.
4. **ModSecurity WAF Comparison**: First-ever empirical comparison against ModSecurity v3 + CRS PL1/PL2. ModSecurity CRS PL1 has a **47.05% bypass rate** on adversarial evasions and **0.0% detection** on reconnaissance probes. Status: **SUPPORTED**.
5. **LLM Backends (Ollama & OpenAI)**: Unverified execution claims for Ollama and OpenAI have been **RETRACTED** due to offline daemons in benchmark environments. The local Heuristic MITRE RAG Synthesizer is empirical and verified. Status: **PARTIAL / HONESTLY LABELED**.

---

## 2. Complete Claims vs. Evidence Matrix

| Claim | File / Component | Result Path | Dataset & Protocol | Sample Size ($N$) | Metric with 95% Bootstrap CI | Audit Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| **5-View Meta-Fusion Superiority** | `monitor/meta_fusion.py` | `experiments/results/statistical_rigor.json` | 6M Security Telemetry, 5-Fold GroupKFold by IP, 5 Seeds | $N = 10,000$ (5k pos / 5k neg, 354 IP groups) | F1: **$97.69 \pm 0.23\%$** $[97.38, 97.98]$, FPR: **$2.02 \pm 0.40\%$** $[1.65, 2.44]$ | **SUPPORTED** |
| **Significant Gain Over Regex Rules** | `monitor/meta_fusion.py` | `experiments/results/statistical_rigor.json` | 6M Security Telemetry, Paired McNemar Test | $N = 10,000$ | $\chi^2 = 1963.84, \ p < 0.001$ (ICMF wins = 2,254 vs 102) | **SUPPORTED** |
| **Significant Gain Over Isolation Forest** | `monitor/meta_fusion.py` | `experiments/results/statistical_rigor.json` | 6M Security Telemetry, Paired McNemar Test | $N = 10,000$ | $\chi^2 = 3356.19, \ p < 0.001$ (ICMF wins = 3,653 vs 102) | **SUPPORTED** |
| **Operational 2% Prevalence Resilience** | `experiments/dataset_loaders.py` | `experiments/results/real_dataset_evaluation.json` | 6M Telemetry (2% Attacks, 98% Benign) | $N = 20,000$ (400 attacks / 19,600 benign) | Precision: **$100.00\%$**, Recall: **$90.50\%$**, F1: **$95.01\%$**, FPR: **$0.00\%$** | **SUPPORTED** |
| **ModSecurity CRS PL1 Benchmark Advantage** | `experiments/waf_baseline_benchmark.py` | `experiments/results/waf_comparison_benchmark.json` | Standardized WAF Corpus (SQLi, XSS, LFI, Obfuscated, Recon, Benign-Hard) | $N = 1,200$ (750 attacks / 450 controls) | ICMF F1: **$97.96\%$** vs ModSec PL1 F1: **$83.72\%$** (PL1 bypass: 28.0%, Recon: 0.0%) | **SUPPORTED** |
| **ModSecurity CRS PL2 False Alarm Suppression** | `experiments/waf_baseline_benchmark.py` | `experiments/results/waf_comparison_benchmark.json` | Standardized WAF Corpus (Benign-Hard apostrophes, tutorials, dashes) | $N = 450$ benign controls | ICMF FPR: **$0.00\%$** vs ModSec PL2 FPR: **$11.11\%$** (33.3% on benign-hard) | **SUPPORTED** |
| **Adversarial Robustness (10 Techniques)** | `experiments/adversarial_evaluation.py` | `experiments/results/adversarial_evaluation.json` | Programmatic Evasions (200/technique) + 400 Benign-Hard controls | $N = 2,400$ (2,000 attacks / 400 controls) | Held-Out Recall: **$86.95\%$** (Bypass: $13.05\%$), Adapted: **$97.95\%$** (Bypass: $2.05\%$) | **SUPPORTED** |
| **Zero False Alarms on Benign-Hard Set** | `experiments/adversarial_evaluation.py` | `experiments/results/adversarial_evaluation.json` | O'Brien, SQL tutorials, Base64 images, JSON quotes, CLI flags | $N = 400$ benign controls | ICMF FPR: **$0.00\%$** vs RF FPR: **$50.00\%$**, ModSec PL2: **$37.50\%$** | **SUPPORTED** |
| **Sequence Kill-Chain Next-Stage Accuracy** | `monitor/sequence_model.py` | `experiments/results/sequence_metrics.json` | Empirical Markov + Categorical HMM + PyTorch LSTM | $N = 588$ transitions across 7 stages | Top-1 Accuracy: **$32.31\%$**, Top-3 Accuracy: **$60.54\%$** (Prior 95.7% claim retracted) | **PARTIAL** |
| **Lead Time Prior to Escalation** | `monitor/sequence_model.py` | `experiments/results/sequence_metrics.json` | Sequence Forecast Lead Time Evaluation | $N = 588$ sequences | Mean Lead Time: **1.98 steps** before multi-stage exploitation | **SUPPORTED** |
| **MITRE ATT&CK RAG Semantic Correctness** | `monitor/llm_layer.py` | `experiments/results/llm_eval.json` | 600 Obfuscated Payloads evaluated against ATT&CK Enterprise | $N = 600$ (350 attacks / 250 benign) | F1: **$87.50\%$**, Ground-Truth MITRE Technique Correctness: **$63.71\%$** | **SUPPORTED** |
| **Prompt-Injection Neutralization** | `monitor/llm_layer.py` | `experiments/results/llm_eval.json` | 120 Adversarial System Prompt Hijacking Payloads | $N = 120$ prompt attacks | Neutralization Rate: **$90.00\%$** (108/120 neutralized) | **SUPPORTED** |
| **Ollama & OpenAI Model Benchmarks** | `monitor/llm_layer.py` | `experiments/results/llm_eval.json` | Ollama (llama3.2) / OpenAI (gpt-4o-mini) live evaluation | N/A (Daemons offline in test environment) | **UNCONFIGURED / RETRACTED** (Marked N/A, no fabricated numbers) | **UNSUPPORTED** |
| **Sub-Millisecond Inline Fast Path** | `monitor/middleware.py` | `experiments/results/production_latency_benchmark.json` | Microbenchmarks (1,000 iterations), Intel 8-core CPU | $N = 1,000$ iterations | Regex: **$0.014\text{ ms}$**, Sliding Cache: **$0.018\text{ ms}$**, LinUCB: **$0.059\text{ ms}$** | **SUPPORTED** |
| **Reconciled Synchronous Overhead** | `monitor/middleware.py` | `experiments/results/component_reconciliation.csv` | Inline Path: Regex + Cache + RF + Fusion + LinUCB | 1,000 iterations per component | Synchronous Processing Overhead: $\approx \mathbf{4.93\text{ ms}}$ per request | **SUPPORTED** |
| **Asynchronous Out-of-Band Execution** | `monitor/llm_layer.py`, `monitor/graph_analytics.py`, `monitor/explainability.py` | `experiments/results/component_reconciliation.csv` | TreeSHAP (12.8 ms), Graph Louvain (1.6 ms), LLM (0.6 ms) | Microbenchmarks | Executed via `ThreadPoolExecutor` and background daemons | **SUPPORTED** |
| **Adaptive Incident Response (LinUCB)** | `monitor/adaptive_response.py` | `experiments/results/response_benchmark.json` | Contextual Bandit Simulation (6 Mitigation Tiers) | $N = 2,000$ simulated events | Containment: **$97.50\%$**, Friction Reduction: **$98.40\%$** vs binary blocking | **SUPPORTED** |
| **Local Tree Path Attribution Additivity** | `monitor/explainability.py` | `monitor/tests.py` | Saabas Tree Traversal Attribution Decomposition | Continuous test verification | $\text{Base Value} + \sum \phi_i = P(\text{Malicious})$ ($p \le 0.05$ floating tolerance) | **SUPPORTED** |

---

## 3. Statistical Testing & Significance Matrix

Paired McNemar tests comparing CyberOracle ICMF against each individual detection tier across $N=10,000$ events:

$$\chi^2 = \frac{(|b - c| - 1)^2}{b + c}, \quad \text{where } b = (\text{ICMF Correct} \land \text{Baseline Incorrect}), \ c = (\text{ICMF Incorrect} \land \text{Baseline Correct})$$

| Comparison Pair | ICMF Wins ($b$) | Baseline Wins ($c$) | $\chi^2$ Statistic | Exact $p$-Value | Statistical Significance |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **ICMF vs. Traditional Regex Rules** | 2,254 | 102 | 1963.84 | $< 10^{-15}$ | **STATISTICALLY SIGNIFICANT ($p < 0.001$)** |
| **ICMF vs. Isolation Forest Anomaly** | 3,653 | 102 | 3356.19 | $< 10^{-15}$ | **STATISTICALLY SIGNIFICANT ($p < 0.001$)** |
| **ICMF vs. Static Weighted Sum Baseline** | 1,900 | 102 | 1612.99 | $< 10^{-15}$ | **STATISTICALLY SIGNIFICANT ($p < 0.001$)** |
| **ICMF vs. Supervised Random Forest** | 2 | 3 | 0.00 | $1.00$ | Not Significant on In-Distribution Payloads |

*Key Reviewer Finding:* On standard, in-distribution test samples, supervised Random Forest and Meta-Fusion perform similarly. However, as demonstrated in Phase E, the Meta-Fusion engine significantly outperforms Random Forest against adversarial obfuscations ($86.95\%$ vs $66.95\%$ recall) and eliminates the 50% false-positive spike exhibited by Random Forest on benign-hard controls.
