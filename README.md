# CyberNetra AI

> **AI-Powered Threat Intelligence & Predictive Network Attack Forecasting System**  
> *Smart India Hackathon (SIH26153) | Theme: Blockchain & Cybersecurity | Organization: NTRO*

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React%2018%20%2B%20Vite-61DAFB.svg?style=flat&logo=react&logoColor=black)](https://reactjs.org/)
[![TailwindCSS](https://img.shields.io/badge/Styling-Tailwind%20CSS-38B2AC.svg?style=flat&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=flat&logo=python&logoColor=white)](https://python.org)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red.svg?style=flat)](https://attack.mitre.org/)
[![SIH 2026](https://img.shields.io/badge/Hackathon-SIH%202026%20%7C%20NTRO-orange.svg?style=flat)](https://sih.gov.in)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

---

## Overview

**CyberNetra AI** is a next-generation predictive cybersecurity defense platform. Unlike conventional SIEMs and IDS tools that only flag attacks after damage has begun, CyberNetra ingests live network flow telemetry, classifies active threat vectors, and **forecasts the attacker's next attack phase** before full compromise occurs.

Combined with an **Explainable AI (XAI)** engine, CyberNetra gives SOC analysts actionable insights:
1. **What Happened Until Now**: Retrospective evidence and baseline anomaly detection.
2. **What Is Going To Happen Next**: Prospective attack trajectory, targeted assets, and time-to-impact ETA.
3. **Automated Containment Playbook**: Prescriptive remediation steps ready for execution.

---

## The Problem vs CyberNetra Solution

| Capability | Traditional SIEM / Rule-Based IDS | CyberNetra AI Predictive Defense |
| :--- | :--- | :--- |
| **Detection Timing** | Post-Exploitation (After compromise) | **Pre-Exploitation (During early reconnaissance/auth)** |
| **Temporal Prediction** | None (Static thresholds only) | **Predicts next attack phase & time-to-impact ETA** |
| **Context & Explainability** | Raw log dumps & cryptic alert IDs | **Dual-Wing XAI ("What Happened" + "What's Next")** |
| **Mitigation** | Manual SOC triage (slow response) | **Automated, step-by-step mitigation playbooks** |
| **Model Extensibility** | Vendor-locked proprietary engines | **Drop-in model registry for PyTorch, Scikit-Learn & ONNX** |

---

## How It Works: End-to-End Pipeline

```text
[ Live Network Telemetry ] ──► (Packets/s, SYN Ratios, Auth Failures, Flow Volume)
            │
            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          CYBERNETRA AI CORE ENGINE                          │
│                                                                             │
│  1. Traffic Feature Extractor  ──►  Statistical 3-Sigma Anomaly Baseline    │
│  2. Active Threat Classifier   ──►  Multi-Vector Anomaly Identification     │
│  3. Stage Forecast Engine      ──►  LSTM Sequence & Kill-Chain ETA Model    │
│  4. Dual-Wing XAI Engine       ──►  Retrospective Evidence + Next Steps     │
│  5. Composite Risk Calculator  ──►  Real-Time 0-100 Threat Scoring Index    │
└─────────────────────────────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          SOC COMMAND & CONTROL CENTER                       │
│                                                                             │
│  • Dual-Axis Telemetry Graphs   • Radial Risk Threat Gauge                  │
│  • MITRE ATT&CK Roadmap         • Automated Containment Playbook            │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Capabilities

- **Real-Time Telemetry Analysis**: Continuous stream processing of flow volumes, packet frequencies, connection attempt spikes, and authentication failures.
- **Predictive Attack Progression (Flagship Feature)**: Multi-stage LSTM and Bayesian transition models forecasting subsequent adversary stages mapped to the **MITRE ATT&CK** kill chain.
- **Explainable AI (XAI) Engine**:
  - Transparent feature attribution identifying root causes behind threat alerts.
  - Anomaly scoring against 3-sigma baseline deviations.
- **Extensible Model Registry (`backend/models/saved_models/`)**: Drop PyTorch (`.pt`), Scikit-Learn (`.pkl`), or ONNX models directly into the registry folder for automatic dynamic loading without restarts.
- **Interactive SOC Simulation**: Ingest realistic telemetry across 4 operational scenarios (*Normal Baseline*, *Suspicious Reconnaissance*, *Multi-Stage Attack Progression*, and *Volumetric DDoS*).

---

## MITRE ATT&CK Kill-Chain Mapping

| Kill-Chain Stage | Technique ID | Observed Indicators | Predictive Next Stage | Recommended Action |
| :--- | :--- | :--- | :--- | :--- |
| **Reconnaissance** | `T1046` (Network Service Discovery) | High SYN rates, multi-port scans | Credential Access / Brute Force (`T1110`) | Apply rate-limiting & drop unsolicited SYN bursts |
| **Initial Access / Auth** | `T1110` (Brute Force) | SSH/RDP failure spikes, user enumeration | Privilege Escalation (`T1068`) | Enforce IP lockout, rotate admin tokens |
| **Privilege Escalation** | `T1068` (Exploitation for Privilege) | Unauthorized sudo attempts, token forging | Lateral Movement / Data Exfiltration (`T1041`) | Isolate endpoint & terminate unauthorized sessions |
| **Impact / Denial** | `T1498` (Network Denial of Service) | Volumetric UDP/ICMP flood, bandwidth saturation | Service Outage & Gateway Degradation | Enable upstream BGP blackholing / rate filtering |

---

## Architecture & Tech Stack

### Frontend
- **Framework**: React 18 + Vite
- **Styling**: Tailwind CSS (Cyberpunk/Dark SOC theme)
- **Visualizations**: Recharts (Dual-axis telemetry timeline, risk radial gauge)
- **Icons**: Lucide React

### Backend
- **Framework**: FastAPI (Asynchronous Python 3.10+)
- **Data & ML**: NumPy, Pandas, Scikit-Learn, PyTorch / Joblib
- **Validation**: Pydantic v2
- **Server**: Uvicorn ASGI

---

## Project Structure

```text
CyberNetra/
├── backend/
│   ├── main.py                     # FastAPI application entrypoint and routes
│   ├── requirements.txt            # Python dependencies
│   ├── models/
│   │   ├── __init__.py
│   │   ├── schemas.py              # Pydantic request/response models
│   │   ├── model_loader.py         # Dynamic ML/DL model auto-detector
│   │   └── saved_models/           # Model weight storage (.pkl, .pt, .onnx)
│   ├── services/
│   │   ├── __init__.py
│   │   ├── traffic_analyzer.py     # Flow telemetry processor
│   │   ├── threat_detector.py      # Active threat vector classifier
│   │   ├── forecast_engine.py      # LSTM / Markov attack stage forecaster
│   │   ├── risk_calculator.py      # Composite risk scoring engine (0-100)
│   │   ├── explainability_engine.py# Retrospective & prospective XAI generator
│   │   └── training_engine.py      # Automated dataset training pipeline
│   └── data/
│       ├── simulated_traffic.json  # Multi-scenario network telemetry
│       └── datasets/               # Benchmark datasets (e.g. UNSW-NB15)
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx                 # Dashboard state and layout
│   │   ├── index.css               # Design system & dark cyber theme
│   │   ├── services/
│   │   │   └── api.js              # Backend REST client
│   │   └── components/
│   │       ├── Header.jsx          # SOC status header & system pulse
│   │       ├── Navbar.jsx          # Primary navigation tabs
│   │       ├── StatCards.jsx       # Threat posture and network metrics
│   │       ├── TrafficChart.jsx    # Dual-axis real-time telemetry chart
│   │       ├── RiskScore.jsx       # Radial SVG threat gauge
│   │       ├── AttackForecast.jsx  # MITRE ATT&CK progression forecast
│   │       ├── ExplainabilityPanel.jsx # XAI retrospective & prospective cards
│   │       ├── Alerts.jsx          # Live incident alerts stream
│   │       ├── SimulationControls.jsx # 4-scenario simulation switcher
│   │       └── ModelRegistryView.jsx  # ML model deployment & upload manager
│   ├── package.json
│   └── vite.config.js
│
├── .gitignore
└── README.md
```

---

## Quick Start Guide

### Prerequisites
- **Python**: 3.10 or higher
- **Node.js**: 18+ and `npm`

---

### 1. Backend Setup

```bash
# Clone the repository
git clone https://github.com/Krupal-ApexAI/CyberNetra.git
cd CyberNetra

# Install Python dependencies
pip install -r backend/requirements.txt

# Launch FastAPI backend server
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

- Backend API: `http://localhost:8000`
- Interactive Swagger Docs: `http://localhost:8000/docs`
- Health Check: `http://localhost:8000/api/health`

---

### 2. Frontend Setup

```bash
# In a new terminal, navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Start the Vite development server
npm run dev
```

- Web Dashboard: `http://localhost:5173`

---

## Simulation & Demo Flow for Judges

1. **Normal Baseline**:
   - Clean network posture with risk score (~10/100) and nominal traffic (~178 pkts/s).
2. **Suspicious Reconnaissance**:
   - Triggers network scanning detection (MITRE `T1046`). The forecast engine predicts an imminent credential attack.
3. **Attack Progression**:
   - Detects repeated authentication failures (54 failed logins). Risk elevates to 77/100, and the system forecasts **Privilege Escalation within 5-10 minutes**.
4. **Volumetric DDoS**:
   - Ingests high-frequency flood (>21,000 pkts/s). The system activates automatic rate-limiting and IP blacklisting recommendations.

---

## API Endpoints Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Service health status and uptime |
| `GET` | `/api/scenarios` | List available simulation scenarios |
| `POST` | `/api/analyze` | Analyze network telemetry and generate threat forecast |
| `GET` | `/api/models` | List loaded ML/DL models in the registry |
| `POST` | `/api/models/upload` | Upload new weights (`.pkl`, `.pt`, `.onnx`) |
| `POST` | `/api/models/train` | Trigger training pipeline on benchmark datasets |

---

## License

This project is developed for the **Smart India Hackathon (SIH 2026)** under the MIT License.
