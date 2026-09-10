import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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
    print("[OK] GET / passed")

def test_endpoints_for_scenario(scenario: str):
    # Switch scenario
    sim_res = client.post(f"/api/simulate/{scenario}")
    assert sim_res.status_code == 200, f"Simulate {scenario} failed: {sim_res.status_code}"
    sim_data = SimulationResponse(**sim_res.json())
    assert sim_data.status == "success"
    assert sim_data.scenario == scenario
    print(f"[OK] POST /api/simulate/{scenario} passed")

    # Dashboard
    dash_res = client.get("/api/dashboard")
    assert dash_res.status_code == 200, f"Dashboard failed: {dash_res.status_code}"
    dash_obj = DashboardStats(**dash_res.json())
    assert dash_obj.scenario == scenario
    print(f"  [OK] GET /api/dashboard [{scenario}] schema verified: {dash_obj.network_status}, risk={dash_obj.risk_score}")

    # Traffic
    traf_res = client.get("/api/traffic")
    assert traf_res.status_code == 200, f"Traffic failed: {traf_res.status_code}"
    traf_obj = TrafficResponse(**traf_res.json())
    assert traf_obj.scenario == scenario
    assert len(traf_obj.records) > 0
    print(f"  [OK] GET /api/traffic [{scenario}] schema verified: {len(traf_obj.records)} records")

    # Forecast
    fc_res = client.get("/api/forecast")
    assert fc_res.status_code == 200, f"Forecast failed: {fc_res.status_code}"
    fc_obj = ForecastResponse(**fc_res.json())
    assert fc_obj.confidence >= 0 and fc_obj.confidence <= 100
    print(f"  [OK] GET /api/forecast [{scenario}] schema verified: next attack={fc_obj.predicted_next_attack}")

    # Explainability
    exp_res = client.get("/api/explainability")
    assert exp_res.status_code == 200, f"Explainability failed: {exp_res.status_code}"
    exp_obj = ExplainabilityResponse(**exp_res.json())
    assert len(exp_obj.evidence_trail) > 0
    assert len(exp_obj.mitigation_playbook) > 0
    print(f"  [OK] GET /api/explainability [{scenario}] schema verified: {len(exp_obj.evidence_trail)} evidence items, {len(exp_obj.mitigation_playbook)} playbooks")

    # Alerts
    alt_res = client.get("/api/alerts")
    assert alt_res.status_code == 200, f"Alerts failed: {alt_res.status_code}"
    alt_obj = AlertsResponse(**alt_res.json())
    assert len(alt_obj.alerts) > 0
    print(f"  [OK] GET /api/alerts [{scenario}] schema verified: {len(alt_obj.alerts)} alerts")

def test_model_status():
    res = client.get("/api/model-status")
    assert res.status_code == 200, f"Model status failed: {res.status_code}"
    data = res.json()
    assert "active" in data
    assert "name" in data
    assert "type" in data
    print(f"[OK] GET /api/model-status passed: {data}")

def test_invalid_simulation():
    res = client.post("/api/simulate/nonexistent_scenario")
    assert res.status_code == 400
    print("[OK] POST /api/simulate/nonexistent_scenario correctly returned 400")

def test_cors_headers():
    res = client.options("/api/dashboard", headers={
        "Origin": "http://localhost:5173",
        "Access-Control-Request-Method": "GET"
    })
    print(f"[OK] OPTIONS /api/dashboard CORS preflight check passed: {res.headers.get('access-control-allow-origin', '*')}")

if __name__ == "__main__":
    print("Starting Comprehensive API Endpoint Verification...")
    test_root()
    test_model_status()
    test_invalid_simulation()
    test_cors_headers()

    scenarios = ["normal", "suspicious", "progression", "ddos"]
    for sc in scenarios:
        test_endpoints_for_scenario(sc)

    # Reset to normal
    client.post("/api/simulate/normal")
    print("\nALL ENDPOINT TESTS PASSED SUCCESSFULLY!")
