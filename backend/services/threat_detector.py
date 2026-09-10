from typing import Dict, Any

class ThreatDetector:
    def detect_threat(self, summary: Dict[str, Any], scenario: str = "normal") -> Dict[str, Any]:
        peak_packets = summary.get("peak_packets", 0)
        total_failed_logins = summary.get("total_failed_logins", 0)
        max_connections = summary.get("max_connections", 0)
        suspicious_percent = summary.get("suspicious_percent", 0.0)

        # Volumetric attack (DDoS)
        if peak_packets > 3000 or scenario == "ddos":
            return {
                "threat_name": "Volumetric DDoS Flooding Attack",
                "severity": "CRITICAL",
                "mitre_id": "T1498 (Network Denial of Service)",
                "tactic": "TA0040 - Impact",
                "short_description": "Massive incoming packet flood causing buffer saturation and interface congestion."
            }

        # Credential Brute Force
        if total_failed_logins >= 15 or scenario == "progression":
            return {
                "threat_name": "Credential Access - Brute Force Attack",
                "severity": "HIGH",
                "mitre_id": "T1110 (Brute Force)",
                "tactic": "TA0006 - Credential Access",
                "short_description": "Rapid consecutive authentication failures targeting SSH and administration ports."
            }

        # Reconnaissance / Scanning
        if (max_connections > 50 and suspicious_percent > 30) or scenario == "suspicious":
            return {
                "threat_name": "Suspicious Port Scanning & Network Reconnaissance",
                "severity": "MEDIUM",
                "mitre_id": "T1046 (Network Service Discovery)",
                "tactic": "TA0043 - Reconnaissance",
                "short_description": "Horizontal/vertical port probing scanning multiple target IP addresses."
            }

        # Normal
        return {
            "threat_name": "Normal Network Activity",
            "severity": "LOW",
            "mitre_id": "None",
            "tactic": "Baseline Enterprise Traffic",
            "short_description": "Telemetry parameters within standard deviation limits; no active intrusion indicators."
        }

threat_detector = ThreatDetector()
