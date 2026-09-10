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

