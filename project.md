# CYBERNETRA AI — Project Master Guide & Architecture Reference
> **Note:** This is the primary reference file for CYBERNETRA AI. For the full master presentation guide and judge cheat sheet, see [CYBERNETRA_PROJECT_MASTER_GUIDE.md](file:///d:/Dev/Projects/Cyber%20Netra/CyberNetra/CYBERNETRA_PROJECT_MASTER_GUIDE.md).

---

## Quick Reference Summary

- **Project Name:** CYBERNETRA AI (`CYBERNETRA.AI`)
- **Hackathon:** Smart India Hackathon (SIH 2026) | Problem Statement: **SIH26153**
- **Theme:** Blockchain & Cybersecurity | **Organization:** NTRO (National Technical Research Organisation)
- **Problem:** AI-Based Network Attack Forecasting from Network Traffic Data
- **Core Innovation:** Shifting cyber defense from **reactive cleanup** (post-compromise alerts) to **predictive preemption** (forecasting impending MITRE ATT&CK stages 5–10 minutes ahead).

---

## System Architecture

```
[ Raw Network Flow Telemetry / NetFlow / IPFIX / Web Logs / Vulnerable Lab ]
                                  │
                                  ▼
[ Log Parser & Ingestion ] ──► [ Feature Extraction (43 UNSW-NB15 Features) ]
                                  │
                                  ▼
[ Dual-Stage ML Classifiers ] (Binary: Normal/Attack + Multi-Class Attack Family)
                                  │
                                  ▼
[ Attack Stage Forecaster ] ──► (Markov Kill-Chain Transitions + ETA Calculation)
                                  │
                                  ▼
[ Hybrid Explainable AI ] ──► (Baseline Deviation Delta + Google Gemini Reasoning)
                                  │
                                  ▼
[ SOC Command Center ] (React 19 Dashboard + Recharts + Radial Risk Gauge + Playbooks)
```

---

## Key Modules & Endpoints

| Component | Port / Path | Description |
| :--- | :--- | :--- |
| **Backend API** | `http://localhost:8000` | FastAPI server with Swagger docs at `/docs` |
| **Frontend UI** | `http://localhost:5173` | React + Vite Cybernetic SOC Dashboard |
| **Vulnerable Lab** | `http://localhost:9000` | Isolated testing sandbox with 6 vulnerability surfaces |
| **Training Engine** | `POST /api/model/train` | Real UNSW-NB15 dataset trainer (RandomForest, XGBoost) |
| **Model Registry** | `POST /api/model/reload` | Zero-downtime hot-reload for `.pkl` models |
| **Model Rollback** | `POST /api/model/rollback/{id}` | 1-Click rollback to timestamped backups |
| **Log Analysis** | `POST /api/analyze-logs` | Hybrid ML + Google Gemini GenAI log analysis |

---

## 3 Ways to Update / Replace Models

1. **Automated Training via UI / API:** `POST /api/model/train` with custom CSV.
2. **Direct Upload via API:** `POST /api/model/upload` with multipart `.pkl` files.
3. **Manual Drop-in:** Place `.pkl` files in `backend/models/saved_models/` and call `POST /api/model/reload`.

---

## Execution Commands

```bash
# 1. Backend
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

# 2. Frontend
cd frontend && npm run dev -- --host

# 3. Vulnerable Lab (Optional)
cd vulnerable_lab && python -m uvicorn app.main:app --host 127.0.0.1 --port 9000 --reload
```
