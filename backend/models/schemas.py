"""
Pydantic schemas for the Log Analysis feature.
Extends the existing schemas.py with new request/response models.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


# ──────────────────────────────────────────────
# Existing schemas (preserved as-is)
# ──────────────────────────────────────────────

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


# ──────────────────────────────────────────────
# Log Analysis schemas (new)
# ──────────────────────────────────────────────

class LogAnalysisRequest(BaseModel):
    """Request body for POST /api/analyze-logs."""
    logs: str = Field(
        ...,
        min_length=1,
        max_length=512_000,  # 500KB max
        description="Multiline network log text to analyze"
    )

class FeatureEvidence(BaseModel):
    """A single feature that contributed to the model's prediction."""
    feature: str
    value: float
    importance: float

class LogEventResult(BaseModel):
    """Per-event ML prediction result."""
    event_index: int
    timestamp: Optional[str] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    prediction: str  # "Normal" or "Attack"
    detection_confidence: float
    threshold: float
    attack_type: Optional[str] = None
    attack_confidence: Optional[float] = None
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    raw_log: Optional[str] = None
    important_features: Optional[List[FeatureEvidence]] = None
    parsing_warnings: Optional[List[str]] = None

class IncidentSummary(BaseModel):
    """Overall incident summary with optional AI explanation."""
    classification: str  # "Normal" or dominant attack type
    confidence: float
    ai_explanation_available: bool = False
    summary: Optional[str] = None
    why_detected: Optional[List[str]] = None
    evidence: Optional[List[str]] = None
    risk_level: Optional[str] = None
    confidence_note: Optional[str] = None
    recommended_actions: Optional[List[str]] = None
    analyst_note: Optional[str] = None

class LogAnalysisResponse(BaseModel):
    """Full response for POST /api/analyze-logs."""
    analysis_id: str
    total_events: int
    normal_events: int
    attack_events: int
    dominant_attack: Optional[str] = None
    events: List[LogEventResult]
    incident: IncidentSummary
    parsing_warnings: Optional[List[str]] = None
