import sys
from pathlib import Path
# pyrefly: ignore [missing-import]
import pytest


# Resolve project root (d:\Projects\CyberNetra)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

# pyrefly: ignore [missing-import]
from fastapi.testclient import TestClient
from backend.main import app
from backend.models.schemas import (
    DashboardStats,
    TrafficResponse,
    ForecastResponse,
    ExplainabilityResponse,
    AlertsResponse,
    SimulationResponse
)

client = TestClient(app)

def test_root():
    res = client.get("/")
    assert res.status_code == 200, f"Root failed: {res.status_code}"
    data = res.json()
    assert data.get("system") == "CYBERNETRA AI"

@pytest.mark.parametrize("scenario", ["normal", "suspicious", "progression", "ddos"])
def test_endpoints_for_scenario(scenario: str):
    # Switch scenario
    sim_res = client.post(f"/api/simulate/{scenario}")
    assert sim_res.status_code == 200, f"Simulate {scenario} failed: {sim_res.status_code}"
    sim_data = SimulationResponse(**sim_res.json())
    assert sim_data.status == "success"
    assert sim_data.scenario == scenario

    # Dashboard
    dash_res = client.get("/api/dashboard")
    assert dash_res.status_code == 200, f"Dashboard failed: {dash_res.status_code}"
    dash_obj = DashboardStats(**dash_res.json())
    assert dash_obj.scenario == scenario

    # Traffic
    traf_res = client.get("/api/traffic")
    assert traf_res.status_code == 200, f"Traffic failed: {traf_res.status_code}"
    traf_obj = TrafficResponse(**traf_res.json())
    assert traf_obj.scenario == scenario
    assert len(traf_obj.records) > 0

    # Forecast
    fc_res = client.get("/api/forecast")
    assert fc_res.status_code == 200, f"Forecast failed: {fc_res.status_code}"
    fc_obj = ForecastResponse(**fc_res.json())
    assert 0 <= fc_obj.confidence <= 100

    # Explainability
    exp_res = client.get("/api/explainability")
    assert exp_res.status_code == 200, f"Explainability failed: {exp_res.status_code}"
    exp_obj = ExplainabilityResponse(**exp_res.json())
    assert len(exp_obj.evidence_trail) > 0
    assert len(exp_obj.mitigation_playbook) > 0

    # Alerts
    alt_res = client.get("/api/alerts")
    assert alt_res.status_code == 200, f"Alerts failed: {alt_res.status_code}"
    alt_obj = AlertsResponse(**alt_res.json())
    assert len(alt_obj.alerts) > 0

def test_model_status():
    res = client.get("/api/model-status")
    assert res.status_code == 200, f"Model status failed: {res.status_code}"
    data = res.json()
    assert "pipeline_ready" in data or "attack_categories" in data or "binary_model_type" in data

def test_invalid_simulation():
    res = client.post("/api/simulate/nonexistent_scenario")
    assert res.status_code == 400

def test_cors_headers():
    res = client.options("/api/dashboard", headers={
        "Origin": "http://localhost:5173",
        "Access-Control-Request-Method": "GET"
    })
    assert res.status_code == 200
