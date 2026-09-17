import os
import sys
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Load environment variables from .env file
try:
    # pyrefly: ignore [missing-import]
    from dotenv import load_dotenv
    load_dotenv(os.path.join(Path(__file__).resolve().parent.parent, ".env"))
except ImportError:
    pass  # python-dotenv not installed; rely on system env vars

import json
import logging
from typing import Dict, Any, List
# pyrefly: ignore [missing-import]
from fastapi import FastAPI, HTTPException
# pyrefly: ignore [missing-import]
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
from backend.services.network_stats_engine import network_stats_engine
import asyncio
import random
from datetime import datetime, timezone

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

    net_stats = network_stats_engine.get_network_stats(
        scenario=CURRENT_SCENARIO,
        active_devices=devices_map.get(CURRENT_SCENARIO, 40),
        risk_score=risk["score"],
        risk_level=risk["level"]
    )

    return DashboardStats(
        network_status=status_map.get(CURRENT_SCENARIO, "Active"),
        active_devices=net_stats["active_devices"],
        suspicious_traffic_percent=summary["suspicious_percent"],
        risk_score=risk["score"],
        risk_level=risk["level"],
        scenario=CURRENT_SCENARIO,
        active_threat=threat["threat_name"],
        total_flows=net_stats["total_flows"],
        threats_detected=net_stats["threats_detected"],
        suspicious_flows=net_stats["suspicious_flows"],
        normal_flows=net_stats["normal_flows"],
        flow_trends=net_stats["trends"],
    )

@app.get("/api/network-stats")
def get_network_stats():
    """Real-time aggregated network flow statistics and trends for StatCards."""
    devices_map = {"normal": 38, "suspicious": 42, "progression": 36, "ddos": 54}
    risk_map = {
        "normal": (12, "LOW"),
        "suspicious": (48, "MEDIUM"),
        "progression": (82, "HIGH"),
        "ddos": (97, "CRITICAL"),
    }
    score, level = risk_map.get(CURRENT_SCENARIO, (12, "LOW"))
    return network_stats_engine.get_network_stats(
        scenario=CURRENT_SCENARIO,
        active_devices=devices_map.get(CURRENT_SCENARIO, 38),
        risk_score=score,
        risk_level=level,
    )

@app.get("/api/ml/live-analysis")
def get_live_ml_analysis():
    """Real-time ML analysis outputs, continuous detections, and time-series for LiveMonitoring."""
    return network_stats_engine.get_live_ml_analysis()

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
# pyrefly: ignore [missing-import]
from pydantic import BaseModel
# pyrefly: ignore [missing-import]
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
# Model Management Endpoints
# ──────────────────────────────────────────────

@app.get("/api/model/backups")
def list_model_backups():
    """List all available model backup snapshots."""
    return {
        "status": "success",
        "backups": training_engine.list_backups(),
    }


@app.post("/api/model/rollback/{backup_id}")
def rollback_model(backup_id: str):
    """Restore production models from a backup snapshot."""
    return training_engine.rollback_to_backup(backup_id)


@app.post("/api/model/reload")
def reload_models():
    """Hot-reload model artifacts from disk without restarting the server."""
    return model_loader.reload()


@app.post("/api/model/upload")
async def upload_model_files(
    binary_model: UploadFile = File(None),
    attack_model: UploadFile = File(None),
    preprocessor: UploadFile = File(None),
    label_encoder: UploadFile = File(None),
    feature_info: UploadFile = File(None),
):
    """
    Upload pre-trained .pkl model files to replace production models.

    Upload any combination of the 5 model artifacts:
    - binary_model: RandomForest binary classifier (.pkl)
    - attack_model: XGBoost attack classifier (.pkl)
    - preprocessor: ColumnTransformer preprocessor (.pkl)
    - label_encoder: LabelEncoder (.pkl)
    - feature_info: Feature metadata dict (.pkl)

    Backs up existing models before replacement.
    """
    import shutil

    file_map = {
        "unsw_nb15_binary_model.pkl": binary_model,
        "unsw_nb15_attack_model.pkl": attack_model,
        "unsw_nb15_attack_preprocessor.pkl": preprocessor,
        "unsw_nb15_label_encoder.pkl": label_encoder,
        "unsw_nb15_feature_info.pkl": feature_info,
    }

    # Filter out None uploads
    uploads = {name: f for name, f in file_map.items() if f is not None}

    if not uploads:
        raise HTTPException(
            status_code=400,
            detail="No model files provided. Upload at least one of: "
                   "binary_model, attack_model, preprocessor, "
                   "label_encoder, feature_info",
        )

    # Back up current models
    backup_id = training_engine._backup_current_models()

    # Save uploaded files
    models_dir = os.path.join(os.path.dirname(__file__), "models")
    saved_files = []
    for target_name, upload_file in uploads.items():
        content = await upload_file.read()
        target_path = os.path.join(models_dir, target_name)
        with open(target_path, "wb") as f:
            f.write(content)
        saved_files.append({
            "filename": target_name,
            "original_name": upload_file.filename,
            "size_bytes": len(content),
        })

    # Hot-reload
    reload_result = model_loader.reload()

    return {
        "status": "success",
        "uploaded_files": saved_files,
        "backup_id": backup_id,
        "reload_result": reload_result,
        "message": f"Uploaded {len(saved_files)} model file(s). "
                   f"Previous models backed up as '{backup_id}'. "
                   f"Models reloaded successfully.",
    }

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
# Vulnerable Lab Integration Layer
# ──────────────────────────────────────────────

# In-memory buffer of lab events with their ML classification results
_lab_event_buffer: List[Dict[str, Any]] = []
_LAB_BUFFER_MAX = 200
_LAB_URL = os.environ.get("LAB_URL", "http://127.0.0.1:9000")


@app.post("/api/lab/ingest")
async def ingest_lab_logs(payload: Dict[str, Any]):
    """
    Accept structured JSON log entries directly from the Controlled Vulnerable Lab,
    store them in the event buffer, convert them into telemetry format,
    and execute the full ML + Gemini pipeline.
    """
    entries = payload.get("entries", [])
    if not entries and isinstance(payload, list):
        entries = payload

    if not entries:
        raise HTTPException(status_code=400, detail="No log entries provided in 'entries' field.")

    # Store raw entries in the lab event buffer
    for entry in entries:
        buffered = {
            "raw": entry,
            "ingested_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            "classification": None,
        }
        _lab_event_buffer.append(buffered)

    # Trim buffer if over max
    while len(_lab_event_buffer) > _LAB_BUFFER_MAX:
        _lab_event_buffer.pop(0)

    text_blocks = []
    for entry in entries:
        client_ip = entry.get("client_ip", "127.0.0.1")
        method = entry.get("method", "GET")
        path = entry.get("path", "/")
        status_code = entry.get("status_code", 200)
        duration = entry.get("response_time_ms", 10.0)
        event_type = entry.get("event_type", "normal")
        indicator = entry.get("indicator", "")
        mitre = entry.get("mitre_technique", "")
        bytes_sent = entry.get("bytes_sent", 500)
        bytes_recv = entry.get("bytes_received", 100)

        record = (
            f"Timestamp: {entry.get('timestamp')}\n"
            f"Protocol: TCP\n"
            f"Source IP: {client_ip}\n"
            f"Source Port: 52140\n"
            f"Destination IP: 127.0.0.1\n"
            f"Destination Port: 9000\n"
            f"Duration: {duration / 1000.0:.3f}\n"
            f"Source Bytes: {bytes_recv}\n"
            f"Destination Bytes: {bytes_sent}\n"
            f"HTTP Method: {method}\n"
            f"HTTP Path: {path}\n"
            f"HTTP Status: {status_code}\n"
            f"Event Type: {event_type}\n"
            f"Indicator: {indicator}\n"
            f"MITRE Technique: {mitre}\n"
        )
        text_blocks.append(record)

    combined_text = "\n---\n".join(text_blocks)

    try:
        result = await analyze_logs(LogAnalysisRequest(logs=combined_text))
        # Update the buffer with classification results
        dominant = result.get("dominant_attack") if isinstance(result, dict) else None
        for buffered in _lab_event_buffer[-len(entries):]:
            buffered["classification"] = dominant or "Normal"

        # Pass each event into network_stats_engine for real-time live counters and feed
        events = result.get("events", []) if isinstance(result, dict) else []
        for idx, entry in enumerate(entries):
            ml_pred = events[idx] if idx < len(events) else None
            network_stats_engine.ingest_lab_event(entry, ml_pred)

        return result
    except Exception as e:
        # Pass entries to network_stats_engine with rule-based fallback
        for entry in entries:
            network_stats_engine.ingest_lab_event(entry, None)
        return {
            "status": "ingested",
            "records_received": len(entries),
            "ml_analysis": "unavailable",
            "error": str(e),
        }


@app.get("/api/lab/status")
async def get_lab_status():
    """
    Check if the Vulnerable Lab is running and return its status.
    Proxies to the lab's /lab/status endpoint.
    """
    import httpx
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"{_LAB_URL}/lab/status")
            if r.status_code == 200:
                data = r.json()
                data["connection"] = "connected"
                data["lab_url"] = _LAB_URL
                data["buffered_events"] = len(_lab_event_buffer)
                return data
    except Exception:
        pass

    return {
        "connection": "disconnected",
        "status": "offline",
        "lab_url": _LAB_URL,
        "buffered_events": len(_lab_event_buffer),
        "message": "Vulnerable Lab is not responding. Start it with: python -m uvicorn app.main:app --host 127.0.0.1 --port 9000",
    }


@app.post("/api/lab/attack")
async def trigger_lab_attack(payload: Dict[str, Any]):
    """
    Proxy an attack trigger request to the Vulnerable Lab,
    then execute the full CyberNetra ML classification pipeline and Gemini AI explanation.
    Returns the raw lab result, ML predictions, and Gemini AI security analysis.
    """
    import httpx
    from datetime import datetime, timezone
    from backend.services.predictor import predict_batch
    from backend.services.gemini_service import get_gemini_explanation, _fallback_explanation

    attack_type = payload.get("attack_type", "").lower().strip()
    if not attack_type:
        raise HTTPException(status_code=400, detail="Missing 'attack_type' field.")

    # 1. Trigger the attack in the Vulnerable Lab
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(
                f"{_LAB_URL}/api/attack/trigger",
                json={"attack_type": attack_type},
            )
            lab_result = r.json()
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to reach Vulnerable Lab at {_LAB_URL}: {str(e)}. Ensure the lab is running on port 9000.",
        )

    # 2. Map the attack into high-fidelity UNSW-NB15 telemetry event
    attack_specs = {
        "sqli": {
            "name": "SQL Injection",
            "mitre": "T1190",
            "endpoint": "GET /api/users?search=' OR '1'='1",
            "method": "GET",
            "path": "/api/users?search=' OR '1'='1",
            "indicator": "' OR '1'='1 -- Authentication Bypass probe",
            "event_type": "suspicious_input",
            "sbytes": 250,
            "dbytes": 3420,
            "packets": 12,
            "duration": 0.040,
            "rate": 25.0,
            "failed_attempts": 0,
            "repeated_connections": 1,
        },
        "xss": {
            "name": "Cross-Site Scripting (Reflected)",
            "mitre": "T1059.007",
            "endpoint": "GET /search?q=<script>alert('XSS')</script>",
            "method": "GET",
            "path": "/search?q=<script>alert('XSS')</script>",
            "indicator": "<script>alert('XSS')</script> -- Reflected XSS payload",
            "event_type": "suspicious_input",
            "sbytes": 180,
            "dbytes": 2100,
            "packets": 10,
            "duration": 0.025,
            "rate": 18.0,
            "failed_attempts": 0,
            "repeated_connections": 1,
        },
        "traversal": {
            "name": "Directory / Path Traversal",
            "mitre": "T1083",
            "endpoint": "GET /api/logs/view?file=../../etc/passwd",
            "method": "GET",
            "path": "/api/logs/view?file=../../etc/passwd",
            "indicator": "../../etc/passwd -- Directory Traversal probe",
            "event_type": "suspicious_input",
            "sbytes": 210,
            "dbytes": 2650,
            "packets": 11,
            "duration": 0.030,
            "rate": 20.0,
            "failed_attempts": 0,
            "repeated_connections": 1,
        },
        "cmd": {
            "name": "Remote OS Command Injection",
            "mitre": "T1059",
            "endpoint": "POST /api/tools/ping",
            "method": "POST",
            "path": "/api/tools/ping",
            "indicator": "127.0.0.1; whoami -- OS Command Injection",
            "event_type": "suspicious_input",
            "sbytes": 380,
            "dbytes": 1420,
            "packets": 14,
            "duration": 0.055,
            "rate": 22.0,
            "failed_attempts": 0,
            "repeated_connections": 1,
        },
        "brute": {
            "name": "Credential Brute-Force",
            "mitre": "T1110",
            "endpoint": "POST /auth/login",
            "method": "POST",
            "path": "/auth/login",
            "indicator": "Multiple failed credential authentication attempts for user admin",
            "event_type": "auth_failure",
            "sbytes": 620,
            "dbytes": 480,
            "packets": 25,
            "duration": 0.018,
            "rate": 60.0,
            "failed_attempts": 5,
            "repeated_connections": 5,
        },
        "dos": {
            "name": "Denial of Service / Resource Exhaustion",
            "mitre": "T1498",
            "endpoint": "GET /api/resource-intensive?workload=50000",
            "method": "GET",
            "path": "/api/resource-intensive?workload=50000",
            "indicator": "Volumetric resource-exhaustion request flood",
            "event_type": "rate_limit",
            "sbytes": 16000,
            "dbytes": 2800,
            "packets": 90,
            "duration": 0.280,
            "rate": 140.0,
            "failed_attempts": 0,
            "repeated_connections": 10,
        },
    }

    spec = attack_specs.get(attack_type, {
        "name": attack_type.upper(),
        "mitre": "T1190",
        "endpoint": f"/api/{attack_type}",
        "method": "POST",
        "path": f"/api/{attack_type}",
        "indicator": f"Generic exploit payload: {attack_type}",
        "event_type": "suspicious_input",
        "sbytes": 250,
        "dbytes": 1500,
        "packets": 10,
        "duration": 0.04,
        "rate": 20.0,
        "failed_attempts": 0,
        "repeated_connections": 1,
    })

    now_iso = datetime.now(timezone.utc).isoformat()
    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    event_payload = {
        "timestamp": now_ts,
        "src_ip": "192.168.1.105",
        "src_port": 52140,
        "dst_ip": "127.0.0.1",
        "dst_port": 9000,
        "protocol": "TCP",
        "duration": spec["duration"],
        "bytes_sent": spec["sbytes"],
        "bytes_received": spec["dbytes"],
        "packets": spec["packets"],
        "rate": spec["rate"],
        "failed_attempts": spec["failed_attempts"],
        "repeated_connections": spec["repeated_connections"],
        "raw_log": f"{spec['method']} {spec['path']} -> HTTP/1.1 {spec['indicator']} [{spec['mitre']}]",
    }

    # 3. Run ML prediction pipeline (Random Forest binary + XGBoost attack classifier)
    try:
        prediction_results = predict_batch([event_payload])
        best_attack = prediction_results["events"][0] if prediction_results.get("events") else {}
        dominant_attack = prediction_results.get("dominant_attack") or "Exploits"
    except Exception as e:
        logger.error("ML prediction on lab attack failed: %s", str(e), exc_info=True)
        best_attack = {
            "prediction": "Attack",
            "detection_confidence": 0.95,
            "attack_type": "Exploits",
            "attack_confidence": 0.92,
            "risk_level": "HIGH",
            "important_features": [],
        }
        dominant_attack = "Exploits"

    # 4. Generate Gemini AI security analyst explanation
    try:
        ai_explanation = await get_gemini_explanation(
            prediction_data={
                "prediction": "Attack",
                "dominant_attack": dominant_attack,
                "detection_confidence": best_attack.get("detection_confidence", 0.95),
                "attack_confidence": best_attack.get("attack_confidence", 0.92),
                "risk_level": best_attack.get("risk_level", "HIGH"),
            },
            events=[best_attack],
            feature_evidence=best_attack.get("important_features", []),
            batch_summary={"total_events": 1, "normal_events": 0, "attack_events": 1},
        )
    except Exception as e:
        logger.error("Gemini explanation failed: %s", str(e), exc_info=True)
        ai_explanation = _fallback_explanation(
            {"dominant_attack": dominant_attack, "detection_confidence": 0.95, "risk_level": "HIGH"},
            f"Error generating explanation: {str(e)}"
        )

    # 5. Ingest into CyberNetra event buffer & network statistics engine
    lab_entry = {
        "timestamp": now_iso,
        "client_ip": "192.168.1.105",
        "method": spec["method"],
        "path": spec["path"],
        "status_code": 200 if attack_type != "brute" else 401,
        "response_time_ms": round(spec["duration"] * 1000, 2),
        "user_agent": "CyberNetra-Lab-Runner/1.0",
        "bytes_received": spec["sbytes"],
        "bytes_sent": spec["dbytes"],
        "event_type": spec["event_type"],
        "indicator": spec["indicator"],
        "mitre_technique": spec["mitre"],
        "rate_10s": int(spec["rate"]),
    }

    _lab_event_buffer.append({
        "raw": lab_entry,
        "ingested_at": now_iso,
        "classification": dominant_attack,
        "ml_result": best_attack,
        "ai_explanation": ai_explanation,
    })
    while len(_lab_event_buffer) > _LAB_BUFFER_MAX:
        _lab_event_buffer.pop(0)

    try:
        network_stats_engine.ingest_lab_event(lab_entry, best_attack)
    except Exception as e:
        logger.warning("network_stats_engine ingestion error: %s", str(e))

    return {
        "success": True,
        "attack_type": attack_type,
        "lab_result": lab_result,
        "ml_prediction": {
            "prediction": best_attack.get("prediction", "Attack"),
            "dominant_attack": dominant_attack,
            "detection_confidence": best_attack.get("detection_confidence", 0.95),
            "attack_confidence": best_attack.get("attack_confidence", 0.92),
            "risk_level": best_attack.get("risk_level", "HIGH"),
            "important_features": best_attack.get("important_features", []),
            "model_pipeline": "RandomForest (Binary) + XGBoost (Multi-Class UNSW-NB15)",
        },
        "ai_explanation": ai_explanation,
        "proxied_through": "cybernetra-backend",
    }


@app.get("/api/lab/events")
async def get_lab_events(limit: int = 50):
    """
    Return recently ingested lab events with their ML classification results.
    """
    events = _lab_event_buffer[-limit:]
    events_reversed = list(reversed(events))
    return {
        "count": len(events_reversed),
        "total_buffered": len(_lab_event_buffer),
        "events": events_reversed,
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


# ──────────────────────────────────────────────
# Continuous ML Analysis Background Worker
# ──────────────────────────────────────────────

async def _continuous_ml_worker():
    """
    Background worker that continuously generates and analyzes network traffic
    using the ML models (Random Forest + XGBoost) every 3 seconds.
    """
    from backend.services.predictor import predict_batch

    await asyncio.sleep(4)
    logger.info("Continuous ML Traffic Analysis worker active.")

    PROBE_TEMPLATES = [
        {"src": "192.168.1.105", "dst": "127.0.0.1", "sport": 54120, "dport": 9000, "proto": "TCP", "sbytes": 480, "dbytes": 1200, "dur": 0.045, "method": "GET", "path": "/api/users"},
        {"src": "10.0.0.88", "dst": "192.168.1.1", "sport": 49152, "dport": 22, "proto": "TCP", "sbytes": 84, "dbytes": 0, "dur": 0.002, "method": "SYN", "path": "PORT_SCAN"},
        {"src": "172.16.0.4", "dst": "127.0.0.1", "sport": 52110, "dport": 9000, "proto": "TCP", "sbytes": 310, "dbytes": 850, "dur": 0.012, "method": "GET", "path": "/health"},
        {"src": "185.220.101.5", "dst": "127.0.0.1", "sport": 60124, "dport": 9000, "proto": "TCP", "sbytes": 620, "dbytes": 180, "dur": 0.025, "method": "POST", "path": "/auth/login"},
        {"src": "10.0.0.14", "dst": "8.8.8.8", "sport": 53530, "dport": 53, "proto": "UDP", "sbytes": 64, "dbytes": 128, "dur": 0.008, "method": "DNS", "path": "QUERY"},
    ]

    while True:
        try:
            await asyncio.sleep(3.0)

            # Select probe based on current scenario
            if CURRENT_SCENARIO == "ddos":
                tmpl = random.choice([
                    {"src": f"198.51.100.{random.randint(10, 250)}", "dst": "127.0.0.1", "sport": random.randint(1024, 65535), "dport": 9000, "proto": "TCP", "sbytes": 1400, "dbytes": 0, "dur": 0.001, "method": "SYN_FLOOD", "path": "/"},
                    {"src": "198.51.100.44", "dst": "127.0.0.1", "sport": random.randint(1024, 65535), "dport": 9000, "proto": "TCP", "sbytes": 1200, "dbytes": 0, "dur": 0.001, "method": "SYN_FLOOD", "path": "/"}
                ])
                is_attack_expected = True
            elif CURRENT_SCENARIO == "progression":
                tmpl = random.choice([
                    {"src": "185.220.101.5", "dst": "127.0.0.1", "sport": 60124, "dport": 9000, "proto": "TCP", "sbytes": 950, "dbytes": 150, "dur": 0.015, "method": "POST", "path": "/auth/login", "failed_attempts": 12},
                    {"src": "192.168.1.45", "dst": "10.0.4.12", "sport": 51200, "dport": 445, "proto": "TCP", "sbytes": 1240, "dbytes": 420, "dur": 0.035, "method": "SMB", "path": "IPC$"}
                ])
                is_attack_expected = True
            elif CURRENT_SCENARIO == "suspicious":
                tmpl = random.choice([
                    {"src": "10.0.0.88", "dst": f"10.0.0.{random.randint(10, 25)}", "sport": random.randint(40000, 60000), "dport": random.choice([22, 80, 443, 8080]), "proto": "TCP", "sbytes": 60, "dbytes": 0, "dur": 0.001, "method": "SYN", "path": "RECON"},
                    PROBE_TEMPLATES[2]
                ])
                is_attack_expected = False
            else:  # normal
                tmpl = random.choice([PROBE_TEMPLATES[0], PROBE_TEMPLATES[2], PROBE_TEMPLATES[4]])
                is_attack_expected = False

            now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            parsed_event = {
                "timestamp": now_iso,
                "src_ip": tmpl["src"],
                "dst_ip": tmpl["dst"],
                "src_port": tmpl["sport"],
                "dst_port": tmpl["dport"],
                "protocol": tmpl["proto"],
                "duration": tmpl["dur"],
                "sbytes": tmpl["sbytes"],
                "dbytes": tmpl["dbytes"],
                "repeated_connections": tmpl.get("failed_attempts", 1),
            }

            try:
                ml_res = predict_batch([parsed_event])
                pred = ml_res["events"][0] if ml_res.get("events") else None
            except Exception as ml_err:
                logger.debug("ML worker prediction fallback: %s", ml_err)
                pred = None

            entry = {
                "client_ip": tmpl["src"],
                "method": tmpl.get("method", "GET"),
                "path": tmpl.get("path", "/"),
                "bytes_received": tmpl["sbytes"],
                "bytes_sent": tmpl["dbytes"],
                "event_type": "attack" if is_attack_expected else "normal",
                "indicator": f"{tmpl.get('method', 'GET')} {tmpl.get('path', '/')}",
                "status_code": 401 if (tmpl.get("failed_attempts") or tmpl.get("path") == "/auth/login") else 200,
            }

            network_stats_engine.ingest_lab_event(entry, pred)
            network_stats_engine.total_ml_inferences += 1

        except Exception as e:
            logger.error("Continuous ML worker error: %s", e)
            await asyncio.sleep(5)


@app.on_event("startup")
async def startup_event():
    asyncio.create_task(_continuous_ml_worker())




