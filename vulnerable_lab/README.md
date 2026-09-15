# CyberNetra — Controlled Vulnerable Web Lab

> **Isolated Security Testing Sandbox for CyberNetra AI Telemetry Ingestion**  
> *Smart India Hackathon (SIH26153) | Theme: Blockchain & Cybersecurity | Organization: NTRO*

---

## 🎯 Purpose

The **Controlled Vulnerable Web Lab** is a dedicated security testing environment built inside the CyberNetra repository. It allows security operators and evaluators to safely execute realistic web exploits and attacks without affecting production infrastructure.

The lab is equipped with **telemetry generation middleware** that captures every request, evaluates attack signatures and behavioral anomalies, and writes structured JSON Lines events to `logs/access.log`. These logs are then forwarded directly to **CyberNetra AI's Machine Learning and Gemini GenAI pipeline** for threat classification, kill-chain forecasting, and mitigation playbook generation.

---

## 🔒 Complete Environment Isolation

```
┌────────────────────────────────────────────────────────┐
│            CyberNetra Core Ecosystem                   │
│                                                        │
│  • React SOC Dashboard (Port 5173)                     │
│  • FastAPI Core Intelligence Backend (Port 8000)       │
│  • Production ML Models & Gemini Pipeline              │
└───────────────────────────▲────────────────────────────┘
                            │ Telemetry Stream
                            │ (POST /api/lab/ingest or /api/analyze-logs)
┌───────────────────────────┴────────────────────────────┐
│            Controlled Vulnerable Lab (Port 9000)       │
│                                                        │
│  • Separate FastAPI application (vulnerable_lab/)      │
│  • Dedicated logs/ directory                           │
│  • Isolated routes: general, auth, api                 │
│  • Zero dependencies on CyberNetra internal state      │
└────────────────────────────────────────────────────────┘
```

---

## ⚔️ Embedded Vulnerability Attack Surfaces

The lab includes 6 intentional, controlled security vulnerability surfaces:

| Attack Surface | Target Endpoints | Simulated Exploit Payload | Mapped MITRE ATT&CK |
| :--- | :--- | :--- | :--- |
| **SQL Injection (SQLi)** | `GET /search?q=...`<br>`POST /auth/login` | `' OR '1'='1`<br>`' UNION SELECT 1,2,3,4 --` | `T1190` (Exploit Public-Facing Application) |
| **Cross-Site Scripting (XSS)** | `GET /search?q=...`<br>`POST /feedback` | `<script>alert(1)</script>`<br>`<img src=x onerror=...>` | `T1059.007` (JavaScript) |
| **Path Traversal** | `GET /api/logs/view?file=...` | `../../etc/passwd`<br>`..\..\windows\win.ini` | `T1083` (File & Directory Discovery) |
| **Remote Command Execution** | `POST /api/tools/ping` | `127.0.0.1; whoami`<br>`127.0.0.1 && cat /etc/passwd` | `T1059` (Command & Scripting Interpreter) |
| **Credential Brute-Force** | `POST /auth/login` | High-frequency failed authentication attempts | `T1110` (Brute Force Spraying) |
| **Denial of Service (DoS)** | `GET /api/resource-intensive` | Volumetric CPU loop and concurrent request flood | `T1498` (Network Denial of Service) |

---

## 📊 Telemetry Schema (`logs/access.log`)

Every incoming HTTP request generates a structured JSON Lines event:

```json
{
  "timestamp": "2026-09-15T20:30:15.123456Z",
  "client_ip": "127.0.0.1",
  "method": "POST",
  "path": "/auth/login",
  "query_params": {},
  "status_code": 401,
  "response_time_ms": 14.2,
  "user_agent": "python-requests/2.31.0",
  "bytes_received": 42,
  "bytes_sent": 2104,
  "event_type": "auth_failure",
  "indicator": "Authentication failure (5 failed in last 60s)",
  "mitre_technique": "T1110",
  "rate_10s": 5
}
```

> **Security & Privacy Guarantee:** Sensitive credential fields (`password`, `token`, `secret`) are scrubbed before logging.

---

## 🚀 Quick Start Guide

### 1. Install Lab Dependencies
```bash
cd vulnerable_lab
pip install -r requirements.txt
```

### 2. Launch the Vulnerable Web Lab (Port 9000)
```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 9000 --reload
```
- Web Portal: `http://127.0.0.1:9000`
- Interactive API Docs: `http://127.0.0.1:9000/docs`

### 3. Generate Automated Test Attack Traffic
In a second terminal, execute the attack simulator:
```bash
# Run all 8 attack scenarios
python test_scenarios.py

# Or run specific scenarios:
python test_scenarios.py --scenario recon
python test_scenarios.py --scenario sqli
python test_scenarios.py --scenario brute
python test_scenarios.py --scenario dos
```

### 4. Ship Logs to CyberNetra for Real-Time Threat Analysis
In a third terminal, forward telemetry events directly to CyberNetra:
```bash
# Ship newly generated logs
python send_logs.py

# Or continuously stream logs in real time as attacks happen:
python send_logs.py --follow
```

---

## 🏆 Demonstration Flow for Hackathon Judges

1. **Start the Vulnerable Lab:** Open `http://127.0.0.1:9000` to show the authentic enterprise staging portal.
2. **Execute an Attack:** Run `python test_scenarios.py --scenario brute` to simulate a credential brute-force attack.
3. **Show the Telemetry Stream:** Show `vulnerable_lab/logs/access.log` recording the attack signatures and MITRE `T1110` tags.
4. **Forward to CyberNetra:** Run `python send_logs.py`.
5. **View Predictive Results:** Watch CyberNetra's Machine Learning models classify the threat with high confidence and Google Gemini produce an executive root-cause breakdown and mitigation playbook!
