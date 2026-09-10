from typing import List, Dict, Any

class TrafficAnalyzer:
    def __init__(self):
        # Baseline threshold metrics
        self.PACKET_SUSPICIOUS = 400
        self.PACKET_HIGH_RISK = 1000
        self.CONN_SUSPICIOUS = 40
        self.CONN_HIGH_RISK = 90
        self.FAILED_LOGIN_SUSPICIOUS = 2
        self.FAILED_LOGIN_HIGH_RISK = 8

    def analyze_records(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not records:
            return {
                "classified_records": [],
                "suspicious_percent": 0.0,
                "avg_packets": 0,
                "peak_packets": 0,
                "total_failed_logins": 0,
                "max_connections": 0,
                "avg_connections": 0
            }

        classified = []
        suspicious_count = 0
        total_packets = 0
        peak_packets = 0
        total_failed_logins = 0
        total_connections = 0
        max_connections = 0

        for r in records:
            p_count = r.get("packet_count", 0)
            c_attempts = r.get("connection_attempts", 0)
            f_logins = r.get("failed_login_attempts", 0)

            total_packets += p_count
            peak_packets = max(peak_packets, p_count)
            total_failed_logins += f_logins
            total_connections += c_attempts
            max_connections = max(max_connections, c_attempts)

            # Rule-based classification for each packet record
            is_high_risk = (
                p_count >= self.PACKET_HIGH_RISK or
                c_attempts >= self.CONN_HIGH_RISK or
                f_logins >= self.FAILED_LOGIN_HIGH_RISK
            )
            is_suspicious = (
                p_count >= self.PACKET_SUSPICIOUS or
                c_attempts >= self.CONN_SUSPICIOUS or
                f_logins >= self.FAILED_LOGIN_SUSPICIOUS
            )

            if is_high_risk:
                label = "High Risk"
                suspicious_count += 1
            elif is_suspicious:
                label = "Suspicious"
                suspicious_count += 1
            else:
                label = "Normal"

            rec_copy = dict(r)
            rec_copy["classification"] = label
            classified.append(rec_copy)

        n = len(records)
        suspicious_percent = round((suspicious_count / n) * 100, 1) if n > 0 else 0.0

        return {
            "classified_records": classified,
            "suspicious_percent": suspicious_percent,
            "avg_packets": int(total_packets / n),
            "peak_packets": peak_packets,
            "total_failed_logins": total_failed_logins,
            "max_connections": max_connections,
            "avg_connections": int(total_connections / n)
        }

traffic_analyzer = TrafficAnalyzer()
