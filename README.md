# SentinelML: Autonomous Threat Hunting & Predictive Analytics Engine

> **An Autonomous Cyber Threat Hunting & Predictive Analytics Engine Using Intent-Centric Multi-Layer Fusion (ICMF)**

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![Django](https://img.shields.io/badge/django-4.2-brightgreen.svg)](https://www.djangoproject.com/)
[![Framework](https://img.shields.io/badge/MITRE%20ATT%26CK-Aligned-red.svg)](https://attack.mitre.org/)

---

## 📌 Overview

**SentinelML** is an intelligent, autonomous cyber defense platform designed to protect modern web applications against multi-stage attack campaigns (such as SQL Injection, Authentication Brute-Force, Reconnaissance, Cross-Site Scripting, and Path Traversal). 

Unlike traditional point-in-time WAFs or standalone machine learning classifiers, SentinelML introduces **Intent-Centric Multi-Layer Fusion (ICMF)**—fusing deterministic heuristics, supervised ensembles, unsupervised anomaly detectors, Markov state transitions, and neural LLM reasoning to construct temporal **Threat-Journey Graphs** and predict future attack trajectories in real time.

---

## 🚀 Key Features

* **Intent-Centric Multi-Layer Fusion (ICMF):** 5-view score fusion combining Rule-based signatures, Random Forest classification, Isolation Forest anomaly scoring, Markov sequence modeling, and LLM forensic synthesis.
* **Interactive Global Cyber Threat Map:** Real-time Leaflet.js adversary sensor grid plotting IP origins, ASNs, and live threat tiers with zero external API key requirements.
* **Real-Time Live Telemetry Stream (SSE):** Server-Sent Events dynamically streaming incoming attack telemetry and updating dashboard meters with zero page refreshes.
* **Markov Threat-Journey State Transition Visualizer:** Visual temporal kill-chain graph ($S_1 \rightarrow S_2 \rightarrow S_3 \rightarrow S_4$) with live stage indicators and forecasted target asset vectors.
* **MITRE ATT&CK® Enterprise Alignment:** Correlates detected vectors to standard techniques (`T1595.002`, `T1110.001`, `T1190`, `T1059.007`, `T1005`).
* **Autonomous Threat Hunting Sweeper:** Continuous background daemon detecting low-and-slow stealth attacks and distributed multi-IP campaigns.
* **Autonomous Canary Honeypot Traps:** Zero false-positive decoy routes (`/.env`, `/backup.sql`, `/.git/config`, `/wp-login.php`) triggering instant quarantine.
* **1-Click Forensic Dossier PDF Export:** Printable CISO executive forensic dossiers ready for security audits.

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
    ├── Layer 4: Markov Chain Sequence Model (Kill-Chain State Transitions)
    └── Layer 5: Neural LLM Reasoning Layer (Forensic Synthesis)
          │
          ▼
[ Threat-Journey Graph & Predictive Forensics ] ───► Target Asset Forecasting
          │
          ▼
[ Autonomous SOC Command Center / Leaflet Map / Live Stream ]
```

---

## 🛠️ Tech Stack

* **Backend:** Python 3.12, Django 4.2, Gunicorn, WhiteNoise
* **Machine Learning:** Scikit-Learn (Random Forest, Isolation Forest), NumPy, Joblib
* **Frontend:** Django Templates, Leaflet.js, Plotly.js, FontAwesome 6, Orbitron & JetBrains Mono fonts
* **Database:** SQLite (Development) / PostgreSQL (Production)

---

## ⚡ Quick Start (Local Run)

### 1. Clone the repository
```bash
git clone https://github.com/thanii00v/sentinel-ml.git
cd sentinel-ml
```

### 2. Create virtual environment & install dependencies
```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Run migrations & start server
```bash
python manage.py migrate
python manage.py runserver 127.0.0.1:8000
```

### 4. Access the SOC Command Center
* **SOC Dashboard:** http://127.0.0.1:8000/
* **Attack Studio:** http://127.0.0.1:8000/simulator/
* **Threat Hunting Center:** http://127.0.0.1:8000/hunting/
* **ML Evaluation Lab:** http://127.0.0.1:8000/evaluation/
* **Master Admin Portal:** http://127.0.0.1:8000/admin/

---

## ☁️ Deployment (Render / Railway)

1. Connect your repository to **[Render.com](https://render.com)**.
2. Set **Build Command:** `./build.sh`
3. Set **Start Command:** `gunicorn iml_core.wsgi:application`

---

## 📄 License
This project is licensed under the MIT License.
