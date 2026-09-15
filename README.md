# CyberNetra AI

> **AI-Powered Threat Intelligence & Predictive Network Attack Forecasting System**  
> *Smart India Hackathon (SIH26153) | Theme: Blockchain & Cybersecurity | Organization: NTRO*

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React%2018%2F19%20%2B%20Vite-61DAFB.svg?style=flat&logo=react&logoColor=black)](https://reactjs.org/)
[![TailwindCSS](https://img.shields.io/badge/Styling-Tailwind%20CSS-38B2AC.svg?style=flat&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=flat&logo=python&logoColor=white)](https://python.org)
[![Scikit-Learn](https://img.shields.io/badge/ML-Scikit--Learn%20%2B%20XGBoost-F7931E.svg?style=flat&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![Google Gemini](https://img.shields.io/badge/GenAI-Google%20Gemini%201.5-8E75B2.svg?style=flat&logo=google&logoColor=white)](https://deepmind.google/technologies/gemini/)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red.svg?style=flat)](https://attack.mitre.org/)
[![SIH 2026](https://img.shields.io/badge/Hackathon-SIH%202026%20%7C%20NTRO-orange.svg?style=flat)](https://sih.gov.in)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

---

## 📖 Master Documentation
For the complete, comprehensive project reference and presentation guide, see **[CYBERNETRA_PROJECT_MASTER_GUIDE.md](file:///d:/Dev/Projects/Cyber%20Netra/CyberNetra/CYBERNETRA_PROJECT_MASTER_GUIDE.md)** or **[project.md](file:///d:/Dev/Projects/Cyber%20Netra/CyberNetra/project.md)**.

---

## Overview

**CyberNetra AI** is an AI-powered predictive cybersecurity defense platform developed for the **National Technical Research Organisation (NTRO)** under **SIH26153**. Unlike conventional SIEMs and IDS tools that only flag attacks after damage has begun, CyberNetra ingests live network flow telemetry, classifies active threat vectors, and **forecasts the attacker's next attack phase 5 to 10 minutes before full compromise occurs**.

Combined with an **Explainable AI (XAI)** engine and **Google Gemini GenAI Copilot**, CyberNetra provides SOC analysts with:
1. **What Happened Until Now**: Retrospective evidence and baseline anomaly detection.
2. **What Is Going To Happen Next**: Prospective attack trajectory, targeted assets, and time-to-impact ETA.
3. **Automated Containment Playbook**: 1-click prescriptive remediation steps ready for execution.

---

## The Problem vs CyberNetra Solution

| Capability | Traditional SIEM / Rule-Based IDS | CyberNetra AI Predictive Defense |
| :--- | :--- | :--- |
| **Detection Timing** | Post-Exploitation (After compromise) | **Pre-Exploitation (During early reconnaissance/auth)** |
| **Temporal Prediction** | None (Static thresholds only) | **Predicts next attack phase & time-to-impact ETA (5-10 min)** |
| **Context & Explainability** | Raw log dumps & cryptic alert IDs | **Dual-Wing XAI ("What Happened" + "What's Next")** |
| **AI Copilot** | None (Manual forensic triage) | **Google Gemini GenAI root-cause & blast radius reasoning** |
| **Mitigation** | Manual SOC triage (slow response) | **Automated, copyable mitigation playbooks** |
| **Model Lifecycle** | Vendor-locked proprietary engines | **Drop-in model registry with zero-downtime hot-reload & 1-click rollback** |
| **Testing Sandbox** | Risky live production testing | **Isolated Controlled Vulnerable Web Lab (Port 9000)** |

---

## How It Works: End-to-End Pipeline

```text
[ Live Telemetry / NetFlow / IPFIX / Vulnerable Lab ] ──► (Packets/s, SYN Ratios, Auth Failures, Flow Volume)
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       CYBERNETRA AI CORE ENGINE                                         │
│                                                                                                         │
│  1. Traffic Feature Extractor  ──►  Statistical 3-Sigma Anomaly Baseline & 43 UNSW-NB15 Features        │
│  2. Dual-Stage ML Classifier   ──►  Binary (Normal/Attack) + Multi-Class Attack Taxonomy                │
│  3. Stage Forecast Engine      ──►  LSTM Sequence & Kill-Chain ETA Model (5-10 min warning)             │
│  4. Dual-Wing XAI & Gemini     ──►  Retrospective Evidence + Generative Threat Reasoning                │
│  5. Composite Risk Calculator  ──►  Real-Time 0-100 Threat Scoring Index                                │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       SOC COMMAND & CONTROL CENTER                                      │
│                                                                                                         │
│  • Dual-Axis Telemetry Graphs   • Radial Risk Threat Gauge   • Model Training & Hot-Reload Hub          │
│  • MITRE ATT&CK Roadmap         • Automated Containment Playbook • Live Threat Alerts Stream            │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Capabilities

- **Real-Time Telemetry Analysis**: Continuous stream processing of flow volumes, packet frequencies, connection attempt spikes, and authentication failures.
- **Predictive Attack Progression (Flagship Feature)**: Sequence state models forecasting subsequent adversary stages mapped to the **MITRE ATT&CK** kill chain.
- **Explainable AI (XAI) & Gemini Copilot**:
  - Transparent feature attribution identifying root causes behind threat alerts.
  - Anomaly scoring against 3-sigma baseline deviations.
  - Natural-language executive summaries and blast radius analysis via Google Gemini.
- **Extensible Model Registry (`backend/models/saved_models/`)**:
  - Train real Random Forest and XGBoost models on UNSW-NB15 datasets via UI / API (`POST /api/model/train`).
  - Direct upload of `.pkl` estimators (`POST /api/model/upload`).
  - Drop `.pkl` files into the registry and hot-reload them dynamically with zero server downtime (`POST /api/model/reload`).
  - Timestamped model versioning with 1-click rollback (`POST /api/model/rollback/{id}`).
- **Controlled Vulnerable Web Lab (`vulnerable_lab/`)**: Independent sandbox on port `9000` simulating 6 exploit surfaces (SQLi, XSS, Path Traversal, Command Injection, Brute Force, DoS) and streaming telemetry to CyberNetra.

---

## MITRE ATT&CK Kill-Chain Mapping

| Kill-Chain Stage | Technique ID | Observed Indicators | Predictive Next Stage | Recommended Action |
| :--- | :--- | :--- | :--- | :--- |
| **Reconnaissance** | `T1046` (Network Service Discovery) | High SYN rates, multi-port scans | Credential Access / Brute Force (`T1110`) | Apply rate-limiting & drop unsolicited SYN bursts |
| **Initial Access / Auth** | `T1110` (Brute Force) | SSH/RDP failure spikes, user enumeration | Privilege Escalation (`T1068`) | Enforce IP lockout, rotate admin tokens |
| **Privilege Escalation** | `T1068` (Exploitation for Privilege) | Unauthorized sudo attempts, token forging | Lateral Movement / Data Exfiltration (`T1041`) | Isolate endpoint & terminate unauthorized sessions |
| **Impact / Denial** | `T1498` (Network Denial of Service) | Volumetric UDP/ICMP flood, bandwidth saturation | Service Outage & Gateway Degradation | Enable upstream BGP blackholing / rate filtering |

---

## Project Structure

```text
CyberNetra/
├── CYBERNETRA_PROJECT_MASTER_GUIDE.md  # Comprehensive Project Master Guide & Presentation Cheat Sheet
├── project.md                          # Quick architecture and API reference
├── README.md                           # Main repository README
│
├── backend/
│   ├── main.py                         # FastAPI server, route handlers, CORS middleware
│   ├── requirements.txt                # Backend dependencies (FastAPI, Scikit-learn, XGBoost, etc.)
│   ├── models/
│   │   ├── schemas.py                  # Pydantic validation schemas
│   │   ├── model_loader.py             # Hot-reloadable ML model loader
│   │   └── saved_models/               # Model checkpoints (.pkl) & timestamped backups
│   ├── services/
│   │   ├── training_engine.py          # Real UNSW-NB15 dataset trainer & metrics generator
│   │   ├── gemini_service.py           # Google Gemini GenAI threat analysis
│   │   ├── log_parser.py               # Multi-format log parser
│   │   ├── traffic_analyzer.py         # Flow telemetry feature extractor
│   │   ├── threat_detector.py          # Active threat vector classifier
│   │   ├── forecast_engine.py          # Predictive kill-chain transition forecaster
│   │   ├── risk_calculator.py          # Composite threat scoring engine (0-100)
│   │   └── explainability_engine.py    # Dual-wing XAI engine & playbooks
│   └── data/
│       ├── simulated_traffic.json      # Multi-scenario network telemetry
│       ├── datasets/                   # Benchmark datasets
│       └── uploads/                    # User uploaded training datasets
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx                     # Dashboard state and layout
│   │   ├── index.css                   # Cybernetic dark-mode styling
│   │   ├── services/api.js             # Fail-safe REST client
│   │   └── components/
│   │       ├── Sidebar.jsx             # Collapsible cyber navigation sidebar
│   │       ├── StatCards.jsx           # Real-time threat posture metrics
│   │       ├── TrafficChart.jsx        # Dual-axis real-time telemetry chart
│   │       ├── RiskScore.jsx           # Radial SVG threat gauge
│   │       ├── AttackForecast.jsx      # MITRE ATT&CK progression forecast
│   │       ├── ExplainabilityPanel.jsx # XAI retrospective & prospective cards
│   │       ├── Alerts.jsx              # Live incident alerts stream
│   │       ├── SimulationControls.jsx  # 4-scenario simulation switcher
│   │       └── ModelRegistryView.jsx   # Model training, upload & hot-reload hub
│   ├── package.json
│   └── vite.config.js
│
└── vulnerable_lab/                     # Isolated Controlled Vulnerable Web Application (Port 9000)
    ├── app/                            # FastAPI sandbox application
    ├── logs/access.log                 # Structured JSON security telemetry
    ├── test_scenarios.py               # Automated exploit test runner
    └── send_logs.py                    # Telemetry forwarder to CyberNetra
```

---

## Quick Start Guide

### Prerequisites
- **Python**: 3.10 or higher
- **Node.js**: 18+ and `npm`

---

### 1. Backend Setup (Port 8000)

```bash
# In the repository root
pip install -r backend/requirements.txt

# Launch FastAPI backend server
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

- Backend API: `http://localhost:8000`
- Interactive Swagger Docs: `http://localhost:8000/docs`
- Health Check: `http://localhost:8000/api/health`

---

### 2. Frontend Setup (Port 5173)

```bash
# In a new terminal
cd frontend
npm install
npm run dev -- --host
```

- Web Dashboard: `http://localhost:5173`

---

### 3. Controlled Vulnerable Lab (Port 9000)

```bash
# In a new terminal
cd vulnerable_lab
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 9000 --reload
```

- Lab Web Portal: `http://localhost:9000`
- Trigger Automated Exploits: `python vulnerable_lab/test_scenarios.py`
- Stream Telemetry to CyberNetra: `python vulnerable_lab/send_logs.py`

---

## API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/dashboard` | Aggregated telemetry, threat classification, and risk index |
| `GET` | `/api/traffic` | Real-time traffic flow records |
| `GET` | `/api/forecast` | Predictive attack forecasting, next MITRE tactic, ETA |
| `GET` | `/api/explainability` | Dual-wing Explainable AI evidence trail and playbooks |
| `GET` | `/api/alerts` | Filtered SOC security alerts with MITRE technique IDs |
| `POST`| `/api/simulate` | Switch active scenario (`normal`, `suspicious`, `progression`, `ddos`) |
| `POST`| `/api/analyze-logs` | Ingest logs for hybrid ML + Gemini AI threat analysis |
| `GET` | `/api/model-status` | Inspect active ML models, loaded features, and registry status |
| `POST`| `/api/model/train` | Trigger real ML model training on an uploaded CSV dataset |
| `POST`| `/api/model/upload` | Upload custom pre-trained `.pkl` model files directly |
| `POST`| `/api/model/reload` | Hot-swap and reload model files from `saved_models/` without restarting |
| `GET` | `/api/model/backups` | List all timestamped model backups |
| `POST`| `/api/model/rollback/{id}` | Rollback to a specific historical model backup |

---

## License

This project is developed for the **Smart India Hackathon (SIH 2026)** under the MIT License.
