import os
import sys
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(Path(__file__).resolve().parent.parent, ".env"))
except ImportError:
    pass  # python-dotenv not installed; rely on system env vars

import json
import logging
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from backend.models.schemas import (
    DashboardStats,
    TrafficResponse,
    ForecastResponse,
    ExplainabilityResponse,
    AlertsResponse,
    AlertItem,
    SimulationResponse,
    LogAnalysisRequest,
    LogAnalysisResponse,
)
from backend.models.model_loader import model_loader
from backend.services.traffic_analyzer import traffic_analyzer
from backend.services.threat_detector import threat_detector
from backend.services.forecast_engine import forecast_engine
from backend.services.risk_calculator import risk_calculator
from backend.services.explainability_engine import explainability_engine

logger = logging.getLogger(__name__)

app = FastAPI(
    title="CYBERNETRA AI - Network Attack Forecasting System",
    description="SIH26153 Prototype: AI-Based Network Attack Forecasting from Network Traffic Data (NTRO)",
    version="1.0.0"
)

# Enable CORS for React frontend (default Vite port 5173 and any local dev host)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory application state
CURRENT_SCENARIO = "normal"

def load_scenario_data(scenario: str) -> List[Dict[str, Any]]:
    data_path = os.path.join(os.path.dirname(__file__), "data", "simulated_traffic.json")
    if not os.path.exists(data_path):
        return []
    with open(data_path, "r", encoding="utf-8") as f:
        all_data = json.load(f)
    return all_data.get(scenario, all_data.get("normal", []))

@app.get("/")
def read_root():
    return {
        "system": "CYBERNETRA AI",
        "description": "AI-Based Network Attack Forecasting System (SIH26153)",
        "status": "Operational",
        "current_scenario": CURRENT_SCENARIO,
        "docs_url": "/docs"
    }

@app.get("/api/health")
def health_check():
    return {
        "status": "ok",
        "service": "cybersecurity-backend"
    }

@app.get("/api/dashboard", response_model=DashboardStats)
def get_dashboard():
    records = load_scenario_data(CURRENT_SCENARIO)
    summary = traffic_analyzer.analyze_records(records)
    threat = threat_detector.detect_threat(summary, CURRENT_SCENARIO)
    forecast = forecast_engine.forecast_next_stage(threat, summary)
    risk = risk_calculator.calculate_score(summary, threat, forecast)

    status_map = {
        "normal": "Healthy - All Clear",
        "suspicious": "Under Observation",
        "progression": "High Threat Alert",
        "ddos": "Critical Defense Active"
    }

    devices_map = {
        "normal": 38,
        "suspicious": 42,
        "progression": 36,
        "ddos": 54
    }

    return DashboardStats(
        network_status=status_map.get(CURRENT_SCENARIO, "Active"),
        active_devices=devices_map.get(CURRENT_SCENARIO, 40),
        suspicious_traffic_percent=summary["suspicious_percent"],
        risk_score=risk["score"],
        risk_level=risk["level"],
        scenario=CURRENT_SCENARIO,
        active_threat=threat["threat_name"]
    )

@app.get("/api/traffic", response_model=TrafficResponse)
def get_traffic():
    records = load_scenario_data(CURRENT_SCENARIO)
    analysis = traffic_analyzer.analyze_records(records)
    return TrafficResponse(
        scenario=CURRENT_SCENARIO,
        records=analysis["classified_records"]
    )

@app.get("/api/forecast", response_model=ForecastResponse)
def get_forecast():
    records = load_scenario_data(CURRENT_SCENARIO)
    summary = traffic_analyzer.analyze_records(records)
    threat = threat_detector.detect_threat(summary, CURRENT_SCENARIO)
    forecast = forecast_engine.forecast_next_stage(threat, summary)
    risk = risk_calculator.calculate_score(summary, threat, forecast)

    return ForecastResponse(
        current_state=forecast["current_state"],
        current_tactic=forecast["current_tactic"],
        predicted_next_attack=forecast["predicted_next_attack"],
        predicted_tactic=forecast["predicted_tactic"],
        potential_impact=forecast["potential_impact"],
        confidence=forecast["confidence"],
        risk_level=risk["level"],
        model_used=forecast["model_used"],
        summary=forecast["summary"]
    )

@app.get("/api/explainability", response_model=ExplainabilityResponse)
def get_explainability():
    records = load_scenario_data(CURRENT_SCENARIO)
    summary = traffic_analyzer.analyze_records(records)
    threat = threat_detector.detect_threat(summary, CURRENT_SCENARIO)
    forecast = forecast_engine.forecast_next_stage(threat, summary)
    risk = risk_calculator.calculate_score(summary, threat, forecast)

    res = explainability_engine.generate_explanation(
        CURRENT_SCENARIO, threat, forecast, summary, risk
    )
    return ExplainabilityResponse(**res)

@app.get("/api/alerts", response_model=AlertsResponse)
def get_alerts():
    records = load_scenario_data(CURRENT_SCENARIO)
    summary = traffic_analyzer.analyze_records(records)
    threat = threat_detector.detect_threat(summary, CURRENT_SCENARIO)

    alerts: List[AlertItem] = []

    if CURRENT_SCENARIO == "ddos":
        alerts.append(AlertItem(
            id="ALT-101",
            timestamp="10:14:02",
            severity="CRITICAL",
            title="Volumetric Attack Flooding Detected",
            message="Packet throughput exceeded 21,000 pkts/s on external gateway.",
            mitre_id="T1498"
        ))
        alerts.append(AlertItem(
            id="ALT-102",
            timestamp="10:12:45",
            severity="CRITICAL",
            title="SYN Buffer Exhaustion Imminent",
            message="Connection pool utilization at 98.4%. Packet drop rate rising.",
            mitre_id="T1499"
        ))
        alerts.append(AlertItem(
            id="ALT-103",
            timestamp="10:07:30",
            severity="HIGH",
            title="Ingress Traffic Threshold Exceeded",
            message="Traffic bandwidth surpassed 25 MB/s baseline limit.",
            mitre_id="T1498"
        ))
    elif CURRENT_SCENARIO == "progression":
        alerts.append(AlertItem(
            id="ALT-201",
            timestamp="10:14:15",
            severity="CRITICAL",
            title="Active Credential Brute Force in Progress",
            message="54 failed authentications logged from 185.220.101.5 on SSH port 22.",
            mitre_id="T1110"
        ))
        alerts.append(AlertItem(
            id="ALT-202",
            timestamp="10:11:20",
            severity="HIGH",
            title="Attacker Velocity Accelerating",
            message="Authentication failure rate jumped to 41 attempts / minute.",
            mitre_id="T1110.001"
        ))
        alerts.append(AlertItem(
            id="ALT-203",
            timestamp="10:04:10",
            severity="MEDIUM",
            title="Proactive Defense Warning",
            message="Forecast engine predicts host compromise within 5-10 minutes.",
            mitre_id="TA0004"
        ))
    elif CURRENT_SCENARIO == "suspicious":
        alerts.append(AlertItem(
            id="ALT-301",
            timestamp="10:14:10",
            severity="MEDIUM",
            title="Network Port Reconnaissance Flagged",
            message="Host 10.0.0.88 scanned 12 internal addresses across subnet VLAN 1.",
            mitre_id="T1046"
        ))
        alerts.append(AlertItem(
            id="ALT-302",
            timestamp="10:08:45",
            severity="LOW",
            title="Elevated TCP SYN Attempts",
            message="Connection attempt frequency reached 112 attempts / minute.",
            mitre_id="T1595"
        ))
    else: # normal
        alerts.append(AlertItem(
            id="ALT-001",
            timestamp="10:14:00",
            severity="LOW",
            title="Continuous Telemetry Monitoring Active",
            message="All traffic features and telemetry streams within safe normal bounds.",
            mitre_id=None
        ))

    return AlertsResponse(alerts=alerts)

@app.post("/api/simulate/{scenario}", response_model=SimulationResponse)
def simulate_scenario(scenario: str):
    global CURRENT_SCENARIO
    valid_scenarios = ["normal", "suspicious", "progression", "ddos"]
    sc = scenario.lower().strip()
    if sc not in valid_scenarios:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scenario '{scenario}'. Choose from: {valid_scenarios}"
        )
    CURRENT_SCENARIO = sc
    return SimulationResponse(
        status="success",
        scenario=CURRENT_SCENARIO,
        message=f"Simulation switched to '{CURRENT_SCENARIO}' scenario successfully."
    )

@app.get("/api/model-status")
def get_model_status():
    return model_loader.get_model_info()

from backend.services.training_engine import training_engine
from pydantic import BaseModel
from fastapi import UploadFile, File

class TrainingRequest(BaseModel):
    architecture: str
    dataset_name: str
    epochs: int = 5
    learning_rate: float = 0.001

@app.get("/api/dataset/list")
def list_datasets():
    return training_engine.get_available_datasets()

@app.get("/api/dataset/preview")
def preview_dataset(dataset_id: str = "ds-unsw"):
    return training_engine.get_dataset_preview(dataset_id)

@app.post("/api/dataset/upload")
async def upload_dataset_file(file: UploadFile = File(...)):
    filename = file.filename
    upload_dir = os.path.join(os.path.dirname(__file__), "data", "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    fpath = os.path.join(upload_dir, filename)
    content = await file.read()
    with open(fpath, "wb") as f:
        f.write(content)
    return {
        "status": "success",
        "filename": filename,
        "size_bytes": len(content),
        "message": f"Dataset '{filename}' successfully uploaded and indexed for model training."
    }

@app.post("/api/model/train")
def run_model_training(req: TrainingRequest):
    result = training_engine.train_model(req.dict())
    return result


# ──────────────────────────────────────────────
# Log Analysis Endpoint (ML + Gemini pipeline)
# ──────────────────────────────────────────────

@app.post("/api/analyze-logs")
async def analyze_logs(request: LogAnalysisRequest):
    """
    End-to-end log analysis pipeline:
    1. Parse network logs
    2. Map to UNSW-NB15 features
    3. Binary detection (Random Forest, threshold 0.30)
    4. Attack classification (XGBoost) if attack detected
    5. Feature evidence extraction
    6. Gemini AI explanation (if attack detected)
    7. Return structured security analysis
    """
    from backend.services.log_parser import parse_logs
    from backend.services.predictor import predict_batch, generate_analysis_id
    from backend.services.gemini_service import get_gemini_explanation

    # Step 1: Parse logs
    try:
        parsed = parse_logs(request.logs)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not parsed["events"]:
        raise HTTPException(
            status_code=400,
            detail="No valid network events found in the input. "
                   "Please check the log format."
        )

    # Step 2-4: ML prediction pipeline
    try:
        prediction_results = predict_batch(parsed["events"])
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logger.error("Prediction pipeline failed: %s", str(e), exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="ML prediction pipeline encountered an error."
        )

    analysis_id = generate_analysis_id(request.logs)

    # Step 5: Build incident summary
    events = prediction_results["events"]
    attack_events = [e for e in events if e["prediction"] == "Attack"]
    normal_events = [e for e in events if e["prediction"] == "Normal"]

    # Determine dominant attack and aggregate confidence
    dominant_attack = prediction_results.get("dominant_attack")
    avg_detection_conf = 0.0
    avg_attack_conf = 0.0

    if attack_events:
        avg_detection_conf = sum(
            e["detection_confidence"] for e in attack_events
        ) / len(attack_events)
        confs = [e["attack_confidence"] for e in attack_events
                 if e.get("attack_confidence")]
        avg_attack_conf = sum(confs) / len(confs) if confs else 0.0

    # Collect feature evidence from the most confident attack event
    feature_evidence = []
    if attack_events:
        best_attack = max(attack_events, key=lambda e: e["detection_confidence"])
        feature_evidence = best_attack.get("important_features", [])

    # Step 6: Gemini explanation (only for attacks)
    incident = {
        "classification": dominant_attack or "Normal",
        "confidence": round(avg_attack_conf if dominant_attack else avg_detection_conf, 4),
        "ai_explanation_available": False,
        "summary": None,
        "why_detected": None,
        "evidence": None,
        "risk_level": None,
        "confidence_note": None,
        "recommended_actions": None,
        "analyst_note": None,
    }

    if attack_events and dominant_attack:
        try:
            gemini_result = await get_gemini_explanation(
                prediction_data={
                    "prediction": "Attack",
                    "dominant_attack": dominant_attack,
                    "detection_confidence": avg_detection_conf,
                    "attack_confidence": avg_attack_conf,
                    "risk_level": best_attack.get("risk_level", "MEDIUM"),
                },
                events=attack_events,
                feature_evidence=feature_evidence,
                batch_summary={
                    "total_events": len(events),
                    "normal_events": len(normal_events),
                    "attack_events": len(attack_events),
                },
            )
            incident.update({
                "ai_explanation_available": gemini_result.get(
                    "ai_explanation_available", False
                ),
                "summary": gemini_result.get("summary"),
                "why_detected": gemini_result.get("why_detected"),
                "evidence": gemini_result.get("evidence"),
                "risk_level": gemini_result.get("risk_level"),
                "confidence_note": gemini_result.get("confidence_note"),
                "recommended_actions": gemini_result.get("recommended_actions"),
                "analyst_note": gemini_result.get("analyst_note"),
            })
        except Exception as e:
            logger.error("Gemini explanation failed: %s", str(e))
            incident["summary"] = (
                f"ML models detected {dominant_attack} attack. "
                f"AI explanation could not be generated."
            )

    # If no attacks, set normal incident
    if not attack_events:
        incident.update({
            "classification": "Normal",
            "confidence": round(
                sum(e["detection_confidence"] for e in normal_events)
                / max(len(normal_events), 1),
                4,
            ),
            "risk_level": "LOW",
            "summary": "All analyzed traffic appears to be normal network activity.",
        })

    # Step 7: Build response
    # Remove batch_features from event results (internal data)
    clean_events = []
    for e in events:
        clean_event = {k: v for k, v in e.items() if k != "batch_features"}
        clean_events.append(clean_event)

    return {
        "analysis_id": analysis_id,
        "total_events": len(events),
        "normal_events": len(normal_events),
        "attack_events": len(attack_events),
        "dominant_attack": dominant_attack,
        "events": clean_events,
        "incident": incident,
        "parsing_warnings": parsed.get("warnings", []),
    }


# ──────────────────────────────────────────────
# New SOC Feature Endpoints
# ──────────────────────────────────────────────

@app.get("/api/system-health")
def get_system_health():
    """Returns real-time service health, latency, and status metrics."""
    return {
        "status": "nominal",
        "cluster": "NTRO-SOC-CLUSTER-1",
        "services": [
            {"name": "Predictive Inference Engine", "status": "Active", "latency": "12ms", "health": "100%", "type": "ML Model"},
            {"name": "API Gateway & Ingress Router", "status": "Active", "latency": "3ms", "health": "99.9%", "type": "FastAPI"},
            {"name": "PCAP / NetFlow Log Pipeline", "status": "Active", "latency": "18ms", "health": "100%", "type": "Kafka Stream"},
            {"name": "MITRE Threat Knowledgebase", "status": "Active", "latency": "5ms", "health": "100%", "type": "STIX/TAXII"}
        ]
    }

@app.get("/api/network-graph")
def get_network_graph():
    """Returns topology nodes and links adapted to current scenario."""
    nodes = [
        {"id": "gw-1", "name": "Edge Gateway Router", "ip": "192.168.1.1", "type": "gateway", "status": "normal", "val": 18, "color": "#06b6d4"},
        {"id": "srv-web1", "name": "Web Server Primary", "ip": "192.168.1.10", "type": "server", "status": "target" if CURRENT_SCENARIO == "ddos" else "normal", "val": 15, "color": "#f43f5e" if CURRENT_SCENARIO == "ddos" else "#10b981"},
        {"id": "srv-web2", "name": "Web Server Replica", "ip": "192.168.1.11", "type": "server", "status": "target" if CURRENT_SCENARIO == "ddos" else "normal", "val": 13, "color": "#f59e0b" if CURRENT_SCENARIO == "ddos" else "#10b981"},
        {"id": "srv-db", "name": "Core SQL Database", "ip": "192.168.1.50", "type": "database", "status": "target" if CURRENT_SCENARIO == "progression" else "normal", "val": 16, "color": "#f43f5e" if CURRENT_SCENARIO == "progression" else "#38bdf8"},
        {"id": "srv-ad", "name": "Active Directory DC", "ip": "10.0.4.12", "type": "server", "status": "target" if CURRENT_SCENARIO == "progression" else "normal", "val": 16, "color": "#f43f5e" if CURRENT_SCENARIO == "progression" else "#38bdf8"},
        {"id": "host-1", "name": "Analyst Workstation A", "ip": "192.168.1.105", "type": "workstation", "status": "normal", "val": 9, "color": "#10b981"},
        {"id": "host-2", "name": "Finance Workstation B", "ip": "192.168.1.45", "type": "workstation", "status": "compromised" if CURRENT_SCENARIO == "progression" else "normal", "val": 12, "color": "#f43f5e" if CURRENT_SCENARIO == "progression" else "#10b981"},
        {"id": "host-3", "name": "Eng Workstation C", "ip": "192.168.1.150", "type": "workstation", "status": "normal", "val": 9, "color": "#10b981"},
        {"id": "ext-c2", "name": "External C2 Server", "ip": "193.142.146.88", "type": "external", "status": "attacker" if CURRENT_SCENARIO in ["progression", "ransomware"] else "normal", "val": 14, "color": "#e11d48"},
        {"id": "ext-bot1", "name": "Botnet Node Cluster #1", "ip": "198.51.100.44", "type": "attacker", "status": "attacker" if CURRENT_SCENARIO == "ddos" else "normal", "val": 12, "color": "#f43f5e"},
        {"id": "ext-bot2", "name": "Botnet Node Cluster #2", "ip": "203.0.113.88", "type": "attacker", "status": "attacker" if CURRENT_SCENARIO == "ddos" else "normal", "val": 12, "color": "#f43f5e"},
        {"id": "ext-scan", "name": "Nmap Scanner External", "ip": "185.190.140.2", "type": "attacker", "status": "attacker" if CURRENT_SCENARIO == "suspicious" else "normal", "val": 11, "color": "#f59e0b"}
    ]

    links = [
        {"source": "gw-1", "target": "srv-web1", "color": "#f43f5e" if CURRENT_SCENARIO == "ddos" else "#334155", "width": 3 if CURRENT_SCENARIO == "ddos" else 1},
        {"source": "gw-1", "target": "srv-web2", "color": "#f43f5e" if CURRENT_SCENARIO == "ddos" else "#334155", "width": 2 if CURRENT_SCENARIO == "ddos" else 1},
        {"source": "gw-1", "target": "host-1", "color": "#1e293b", "width": 1},
        {"source": "gw-1", "target": "host-2", "color": "#f43f5e" if CURRENT_SCENARIO == "progression" else "#1e293b", "width": 2.5 if CURRENT_SCENARIO == "progression" else 1},
        {"source": "gw-1", "target": "host-3", "color": "#1e293b", "width": 1},
        {"source": "srv-web1", "target": "srv-db", "color": "#334155", "width": 1.5},
        {"source": "host-2", "target": "srv-ad", "color": "#f43f5e" if CURRENT_SCENARIO == "progression" else "#1e293b", "width": 3 if CURRENT_SCENARIO == "progression" else 1},
        {"source": "host-2", "target": "srv-db", "color": "#f59e0b" if CURRENT_SCENARIO == "progression" else "#1e293b", "width": 2 if CURRENT_SCENARIO == "progression" else 1},
        {"source": "ext-c2", "target": "host-2", "color": "#f43f5e" if CURRENT_SCENARIO == "progression" else "#1e293b", "width": 2 if CURRENT_SCENARIO == "progression" else 0},
        {"source": "ext-bot1", "target": "gw-1", "color": "#f43f5e" if CURRENT_SCENARIO == "ddos" else "#1e293b", "width": 3 if CURRENT_SCENARIO == "ddos" else 0},
        {"source": "ext-bot2", "target": "gw-1", "color": "#f43f5e" if CURRENT_SCENARIO == "ddos" else "#1e293b", "width": 3 if CURRENT_SCENARIO == "ddos" else 0},
        {"source": "ext-scan", "target": "gw-1", "color": "#f59e0b" if CURRENT_SCENARIO == "suspicious" else "#1e293b", "width": 2.5 if CURRENT_SCENARIO == "suspicious" else 0}
    ]

    return {"scenario": CURRENT_SCENARIO, "nodes": nodes, "links": links}

@app.get("/api/search")
def search_network_entities(q: str = ""):
    """Universal search across IP nodes, threat classifications, MITRE TTPs, and reports."""
    query = q.strip().lower()
    if not query:
        return {"query": "", "count": 0, "results": []}

    entities = [
        # IP Nodes
        {"category": "IP Nodes & Hosts", "title": "192.168.1.10", "subtitle": "Source (Attacker) • DDoS SYN Flooder • Ingress Hub", "type": "ip", "tab": "graph", "meta": {"ip": "192.168.1.10"}},
        {"category": "IP Nodes & Hosts", "title": "8.8.8.8", "subtitle": "Destination (Victim Server) • Ports 80, 443, 53 Under Siege", "type": "ip", "tab": "graph", "meta": {"ip": "8.8.8.8"}},
        {"category": "IP Nodes & Hosts", "title": "192.168.1.45", "subtitle": "Compromised Botnet Worker • Port Scan Origin", "type": "ip", "tab": "graph", "meta": {"ip": "192.168.1.45"}},
        {"category": "IP Nodes & Hosts", "title": "10.0.0.88", "subtitle": "Internal Host • Subnet VLAN 1 Reconnaissance Scanner", "type": "ip", "tab": "threats", "meta": {"ip": "10.0.0.88"}},
        {"category": "IP Nodes & Hosts", "title": "185.220.101.5", "subtitle": "External Tor Exit Node • SSH Brute Force Ingress", "type": "ip", "tab": "threats", "meta": {"ip": "185.220.101.5"}},
        {"category": "IP Nodes & Hosts", "title": "172.16.0.3", "subtitle": "Internal Gateway Router • DMZ Segment", "type": "ip", "tab": "live", "meta": {"ip": "172.16.0.3"}},
        
        # Threats & Incidents
        {"category": "Threat Detections", "title": "DDoS Attack (Critical)", "subtitle": "Volumetric SYN flood saturating gateway at 21,000 pkts/s", "type": "threat", "tab": "threats", "meta": {"attack": "DDoS"}},
        {"category": "Threat Detections", "title": "Exploits & Shellcode Ingress", "subtitle": "Flagged by Random Forest + XGBoost with 98% confidence", "type": "threat", "tab": "threats", "meta": {"attack": "Exploits"}},
        {"category": "Threat Detections", "title": "SSH Credential Brute Force", "subtitle": "54 failed authentications observed on port 22", "type": "threat", "tab": "threats", "meta": {"attack": "BruteForce"}},
        {"category": "Threat Detections", "title": "Nmap Port Reconnaissance", "subtitle": "SYN probes sweeping ports 80, 443, 22, 3389, 8080", "type": "threat", "tab": "threats", "meta": {"attack": "PortScan"}},
        
        # MITRE ATT&CK TTPs
        {"category": "MITRE ATT&CK", "title": "T1498: Network Denial of Service", "subtitle": "Tactic: Impact (TA0040) • Upstream rate-limiting mitigation", "type": "mitre", "tab": "mitre", "meta": {"tactic": "TA0040", "technique": "T1498"}},
        {"category": "MITRE ATT&CK", "title": "T1110: Brute Force", "subtitle": "Tactic: Credential Access (TA0006) • Password Guessing & Spraying", "type": "mitre", "tab": "mitre", "meta": {"tactic": "TA0006", "technique": "T1110"}},
        {"category": "MITRE ATT&CK", "title": "T1046: Network Service Discovery", "subtitle": "Tactic: Discovery (TA0007) • Port scan and host sweeps", "type": "mitre", "tab": "mitre", "meta": {"tactic": "TA0007", "technique": "T1046"}},
        {"category": "MITRE ATT&CK", "title": "T1566: Phishing", "subtitle": "Tactic: Initial Access (TA0001) • Spearphishing Attachment", "type": "mitre", "tab": "mitre", "meta": {"tactic": "TA0001", "technique": "T1566"}},
        {"category": "MITRE ATT&CK", "title": "T1059: Command and Scripting Interpreter", "subtitle": "Tactic: Execution (TA0002) • PowerShell / Unix Shell execution", "type": "mitre", "tab": "mitre", "meta": {"tactic": "TA0002", "technique": "T1059"}},

        # Forensic Reports
        {"category": "SOC Reports", "title": "REP-2026-0914-01: Executive Incident Briefing", "subtitle": "Real-Time Incident Forensic Assessment & Threat Audit (1,420 Anomalies)", "type": "report", "tab": "reports", "meta": {"id": "REP-2026-0914-01"}},
        {"category": "SOC Reports", "title": "REP-2026-0914-02: AI Validation Audit", "subtitle": "NTRO SIH26153 Model Precision (98.6%) & Latency Compliance Report", "type": "report", "tab": "reports", "meta": {"id": "REP-2026-0914-02"}},

        # Datasets
        {"category": "Datasets & Models", "title": "UNSW_NB15_telemetry_sample.csv", "subtitle": "Primary benchmark dataset containing multi-stage intrusion telemetry flows", "type": "model", "tab": "models", "meta": {"dataset": "ds-unsw"}},
        {"category": "Datasets & Models", "title": "LSTM Sequence Forecaster", "subtitle": "Temporal state model forecasting multi-stage attack transitions", "type": "model", "tab": "models", "meta": {"arch": "LSTM"}}
    ]

    matched = []
    for item in entities:
        if (query in item["title"].lower() or 
            query in item["subtitle"].lower() or 
            query in item["category"].lower() or
            query in item.get("meta", {}).get("ip", "").lower() or
            query in item.get("meta", {}).get("technique", "").lower()):
            matched.append(item)

    return {"query": q, "count": len(matched), "results": matched[:10]}



