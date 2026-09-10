from typing import List, Optional
from pydantic import BaseModel, Field

class TrafficRecord(BaseModel):
    timestamp: str
    source_ip: str
    destination_ip: str
    packet_count: int
    traffic_volume: float
    connection_attempts: int
    failed_login_attempts: int
    classification: Optional[str] = "Normal"

class DashboardStats(BaseModel):
    network_status: str
    active_devices: int
    suspicious_traffic_percent: float
    risk_score: int
    risk_level: str
    scenario: str
    active_threat: str

class TrafficResponse(BaseModel):
    scenario: str
    records: List[TrafficRecord]

class ForecastResponse(BaseModel):
    current_state: str
    current_tactic: str
    predicted_next_attack: str
    predicted_tactic: str
    potential_impact: str
    confidence: int
    risk_level: str
    model_used: str
    summary: str

class EvidenceItem(BaseModel):
    timestamp: str
    indicator: str
    observed_value: str
    baseline_value: str
    severity: str
    description: str

class ExplainabilityResponse(BaseModel):
    current_threat: str
    what_happened_summary: str
    evidence_trail: List[EvidenceItem]
    whats_next_prediction: str
    whats_next_details: str
    attack_trajectory: List[str]
    target_assets: List[str]
    estimated_time_to_impact: str
    mitigation_playbook: List[str]

class AlertItem(BaseModel):
    id: str
    timestamp: str
    severity: str
    title: str
    message: str
    mitre_id: Optional[str] = None

class AlertsResponse(BaseModel):
    alerts: List[AlertItem]

class SimulationResponse(BaseModel):
    status: str
    scenario: str
    message: str
