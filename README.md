# CYBERNETRA AI — AI-Based Network Attack Forecasting System
### Smart India Hackathon (SIH26153) | Theme: Blockchain & Cybersecurity | Organization: NTRO

CYBERNETRA AI is a predictive cyber defense prototype that ingests network traffic telemetry, identifies active threat vectors, and **forecasts the impending next attack stage** before full compromise occurs.

---

## ?? Key Capabilities
1. **Real-Time Traffic Analysis**: Ingests flow telemetry (packet frequency, volume, connection attempts, authentication failures).
2. **Attack Stage Forecasting (The Star Feature ?)**: Predicts the attacker's next phase with confidence scoring and MITRE ATT&CK kill-chain mapping.
3. **Explainable AI (XAI) Engine**:
   - **What Happened Until Now**: Retrospective evidence trail of anomalous indicators against baseline standard deviations.
   - **What's Going to Happen Next**: Prospective attack trajectory, targeted assets, and time-to-impact ETA.
   - **Automated Mitigation Playbook**: Actionable containment steps for SOC operators.
4. **Drop-in Model Architecture (`backend/models/saved_models/`)**: Drop your PyTorch (`.pt`), Scikit-Learn (`.pkl`), or ONNX models into `saved_models/`; the system auto-detects and runs inference without code changes.
5. **Interactive Live Simulation**: 1-click scenario injection (Normal, Suspicious Recon, Attack Progression, Volumetric DDoS).

---

## ?? Quick Start Guide

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### 1. Start the FastAPI Backend
```bash
# In project root
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
- API Base URL: `http://localhost:8000`
- Interactive OpenAPI Docs: `http://localhost:8000/docs`

### 2. Start the React Frontend
```bash
cd frontend
npm run dev -- --host
```
- Web Dashboard: `http://localhost:5173`

---

## ?? Project Structure
```
d:\Projects\SIH_2026?
??? backend/
?   ??? main.py                         # FastAPI application and routes
?   ??? requirements.txt                # Python dependencies
?   ??? models/
?   ?   ??? schemas.py                  # Pydantic data schemas
?   ?   ??? model_loader.py             # Auto-detects custom ML models
?   ?   ??? saved_models/               # [DUMP YOUR ML/DL MODELS HERE]
?   ??? services/
?   ?   ??? traffic_analyzer.py         # Telemetry feature extractor
?   ?   ??? threat_detector.py          # Active threat vector classification
?   ?   ??? forecast_engine.py          # Attack stage progression forecaster
?   ?   ??? risk_calculator.py          # 0-100 composite risk scoring
?   ?   ??? explainability_engine.py    # Retrospective & prospective XAI
?   ??? data/
?       ??? simulated_traffic.json      # Realistic 15-minute telemetry datasets
?
??? frontend/
?   ??? src/
?   ?   ??? App.jsx                     # Centralized state & dashboard layout
?   ?   ??? index.css                   # Tailwind CSS v4 & cybernetic theme
?   ?   ??? services/api.js             # API connector to FastAPI backend
?   ?   ??? components/
?   ?       ??? Header.jsx              # Status, branding & live pulse
?   ?       ??? SimulationControls.jsx  # 4-scenario simulation switcher
?   ?       ??? StatCards.jsx           # Posture, endpoints, anomaly ratio
?   ?       ??? TrafficChart.jsx        # Dual-axis Recharts telemetry timeline
?   ?       ??? RiskScore.jsx           # Radial SVG risk gauge (0-100)
?   ?       ??? AttackForecast.jsx      # MITRE ATT&CK progression chain
?   ?       ??? ExplainabilityPanel.jsx # "What Happened" + "What's Next"
?   ?       ??? Alerts.jsx              # SOC alert feed with filters
?   ??? package.json
?
??? README.md
```

---

## ?? 2-Minute Demo Flow for Judges
1. **Normal Baseline**: Show healthy network (10/100 risk, stable ~178 pkts/s).
2. **Suspicious Recon**: Click *Suspicious Recon* ? system detects subnet port scanning (MITRE T1046) and warns of credential spraying.
3. **Attack Progression ?**: Click *Attack Progression* ? risk jumps to 77/100. System highlights 54 failed logins and **forecasts privilege escalation in 5-10 minutes**.
4. **DDoS Attack**: Click *DDoS Attack* ? volumetric flood (21,800 pkts/s) triggers imminent service outage warnings and mitigation playbooks.
