from typing import Dict, Any

class RiskCalculator:
    def calculate_score(self, summary: Dict[str, Any], threat_info: Dict[str, Any], forecast_info: Dict[str, Any]) -> Dict[str, Any]:
        peak_packets = summary.get("peak_packets", 0)
        total_failed_logins = summary.get("total_failed_logins", 0)
        max_connections = summary.get("max_connections", 0)
        suspicious_pct = summary.get("suspicious_percent", 0.0)

        # Baseline risk
        risk = 10.0

        # Packet anomaly contribution (max 25 pts)
        if peak_packets > 10000:
            risk += 25
        elif peak_packets > 2000:
            risk += 20
        elif peak_packets > 600:
            risk += 12
        elif peak_packets > 300:
            risk += 5

        # Connection intensity contribution (max 20 pts)
        if max_connections > 500:
            risk += 20
        elif max_connections > 100:
            risk += 15
        elif max_connections > 40:
            risk += 8

        # Failed logins contribution (max 25 pts)
        if total_failed_logins > 30:
            risk += 25
        elif total_failed_logins > 10:
            risk += 18
        elif total_failed_logins > 3:
            risk += 10

        # Threat severity contribution (max 20 pts)
        severity = threat_info.get("severity", "LOW")
        if severity == "CRITICAL":
            risk += 20
        elif severity == "HIGH":
            risk += 15
        elif severity == "MEDIUM":
            risk += 10

        final_score = int(min(max(risk, 5), 100))

        if final_score >= 81:
            level = "CRITICAL"
        elif final_score >= 61:
            level = "HIGH"
        elif final_score >= 31:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "score": final_score,
            "level": level
        }

risk_calculator = RiskCalculator()
