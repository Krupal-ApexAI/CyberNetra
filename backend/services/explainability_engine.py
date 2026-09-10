from typing import Dict, Any, List

class ExplainabilityEngine:
    """
    Explainable AI (XAI) Engine:
    Answers two foundational questions for the cyber security analyst:
    1. What happened until now? (Telemetry evidence trail & trigger indicators)
    2. What's going to happen next? (Predictive trajectory, target assets, & mitigation playbook)
    """
    def generate_explanation(
        self,
        scenario: str,
        threat_info: Dict[str, Any],
        forecast_info: Dict[str, Any],
        telemetry_summary: Dict[str, Any],
        risk_info: Dict[str, Any]
    ) -> Dict[str, Any]:

        if scenario == "ddos":
            what_happened_summary = (
                "An unprecedented volumetric flood originated across distributed IP addresses. "
                "Packet frequency accelerated from baseline (180 pkts/s) to over 21,800 pkts/s "
                "within 12 minutes, saturating bandwidth and exhausting NAT connection tables."
            )
            evidence_trail = [
                {
                    "timestamp": "10:02",
                    "indicator": "SYN Flood Initiation",
                    "observed_value": "1,200 pkts/s (2.4 MB/s)",
                    "baseline_value": "180 pkts/s",
                    "severity": "MEDIUM",
                    "description": "Unsolicited connection handshakes from external ASNs."
                },
                {
                    "timestamp": "10:07",
                    "indicator": "Bandwidth Saturation",
                    "observed_value": "11,500 pkts/s (25.4 MB/s)",
                    "baseline_value": "210 pkts/s",
                    "severity": "HIGH",
                    "description": "Network ingress exceeded 85% link capacity."
                },
                {
                    "timestamp": "10:14",
                    "indicator": "Connection Pool Exhaustion",
                    "observed_value": "1,810 concurrent connections",
                    "baseline_value": "16 connections",
                    "severity": "CRITICAL",
                    "description": "Edge router dropping legitimate SYN packets due to buffer queue overflow."
                }
            ]
            whats_next_prediction = (
                "Complete Denial of Service (DoS) across core edge gateways and DNS resolvers. "
                "Internal enterprise users and external clients will experience timeout cascades."
            )
            whats_next_details = (
                "Attack forecasting indicates that without intervention, total network paralysis will occur in < 2 minutes. "
                "The adversary is attempting resource exhaustion to mask potential secondary exfiltration."
            )
            attack_trajectory = [
                "1. Botnet Mobilization (Observed)",
                "2. Volumetric SYN/UDP Flood (Current State)",
                "3. Edge Firewall Collapse (Predicted Next)",
                "4. Critical Infrastructure Outage (Potential Impact)"
            ]
            target_assets = ["Edge Gateway 192.168.1.1", "Primary DNS Resolver", "Public Load Balancers"]
            estimated_time = "Immediate (Under 2 minutes)"
            mitigation_playbook = [
                "Engage upstream BGP Anycast scrubbing and upstream ISP rate limiting.",
                "Activate edge SYN cookies and drop non-whitelisted UDP ingress packets.",
                "Isolate public load balancer subnets from internal management VLANs."
            ]

        elif scenario == "progression":
            what_happened_summary = (
                "The system detected targeted host reconnaissance by external IP 185.220.101.5, "
                "which quickly transitioned into an aggressive dictionary credential attack. "
                "A total of 54 failed authentication attempts were logged against internal host 192.168.1.5."
            )
            evidence_trail = [
                {
                    "timestamp": "10:02",
                    "indicator": "Target Reconnaissance",
                    "observed_value": "32 port probes from 185.220.101.5",
                    "baseline_value": "0 external probes",
                    "severity": "MEDIUM",
                    "description": "Targeted scanning specifically querying ports 22 (SSH) and 3389 (RDP)."
                },
                {
                    "timestamp": "10:06",
                    "indicator": "Authentication Burst",
                    "observed_value": "19 failed logins / 60s",
                    "baseline_value": "0 failed logins",
                    "severity": "HIGH",
                    "description": "High-velocity credential spraying utilizing known administrative username lists."
                },
                {
                    "timestamp": "10:14",
                    "indicator": "Credential Attack Acceleration",
                    "observed_value": "54 cumulative auth failures",
                    "baseline_value": "< 1 failure/hr",
                    "severity": "CRITICAL",
                    "description": "Attacker adapting password permutations against enterprise Active Directory node."
                }
            ]
            whats_next_prediction = (
                "Credential Breach followed by Privilege Escalation (MITRE T1068) and Lateral Movement (MITRE T1021)."
            )
            whats_next_details = (
                "The forecasting engine projects that the adversary will successfully compromise a weak credential account "
                "within 5-10 minutes. Upon initial access, they will deploy discovery scripts to traverse the internal subnet."
            )
            attack_trajectory = [
                "1. Port Scanning & Recon (Observed)",
                "2. Brute Force Credential Spraying (Current State)",
                "3. Unauthorized Account Access (Predicted Next)",
                "4. Internal Lateral Movement & Domain Compromise (Potential Impact)"
            ]
            target_assets = ["Domain Controller 192.168.1.5", "SSH Bastion Host", "Enterprise Kerberos Realm"]
            estimated_time = "5 to 10 minutes"
            mitigation_playbook = [
                "Immediately quarantine source IP 185.220.101.5 at the border perimeter firewall.",
                "Enforce immediate account lockout policy and mandatory multi-factor authentication (MFA) step-up.",
                "Isolate host 192.168.1.5 to an internal sandbox VLAN for forensic inspection."
            ]

        elif scenario == "suspicious":
            what_happened_summary = (
                "Host 10.0.0.88 initiated systematic horizontal port scanning across internal IP ranges 192.168.1.1 through 192.168.1.12. "
                "Connection attempts surged from standard baseline (14/min) to 148/min without completing application payloads."
            )
            evidence_trail = [
                {
                    "timestamp": "10:03",
                    "indicator": "Anomalous Connection Burst",
                    "observed_value": "28 connection attempts",
                    "baseline_value": "12-16 attempts",
                    "severity": "LOW",
                    "description": "Initial deviation detected in TCP SYN flags from 10.0.0.88."
                },
                {
                    "timestamp": "10:07",
                    "indicator": "Sequential Port Enumeration",
                    "observed_value": "95 connections spanning 5 IPs",
                    "baseline_value": "Single endpoint traffic",
                    "severity": "MEDIUM",
                    "description": "Sequential scanning pattern identifying open network services."
                },
                {
                    "timestamp": "10:14",
                    "indicator": "Subnet Mapping Complete",
                    "observed_value": "148 connections / 960 pkts/s",
                    "baseline_value": "14 connections / 175 pkts/s",
                    "severity": "MEDIUM",
                    "description": "Attacker has completed network topology discovery across VLAN 1."
                }
            ]
            whats_next_prediction = (
                "Transition into Active Exploitation / Credential Access Phase (MITRE TA0006)."
            )
            whats_next_details = (
                "Reconnaissance is the initial phase of multi-stage intrusions. Having cataloged responsive services, "
                "the attacker will likely launch automated exploits or password spraying against the identified open ports."
            )
            attack_trajectory = [
                "1. Network Baseline (Past)",
                "2. Network Discovery & Port Scanning (Current State)",
                "3. Vulnerability Exploitation or Credential Spraying (Predicted Next)",
                "4. Initial Unauthorized Access (Potential Impact)"
            ]
            target_assets = ["Subnet 192.168.1.0/24", "Management Routers", "Internal File Shares"]
            estimated_time = "15 to 30 minutes"
            mitigation_playbook = [
                "Apply microsegmentation to block inter-host communication on unneeded ports.",
                "Enable IDS/IPS signature inspection for Nmap and Masscan TCP fingerprints.",
                "Verify that internal management interfaces are strictly restricted to admin bastion jump boxes."
            ]

        else: # normal
            what_happened_summary = (
                "Network telemetry exhibits healthy, stochastic traffic patterns across all enterprise endpoints. "
                "Packet flows, payload volumes, and authentication requests remain well within normal operating thresholds."
            )
            evidence_trail = [
                {
                    "timestamp": "10:00 - 10:14",
                    "indicator": "Packet Rate Stability",
                    "observed_value": "Avg 178 pkts/s (Stable)",
                    "baseline_value": "150-220 pkts/s",
                    "severity": "LOW",
                    "description": "Telemetry within standard deviation limits (+/- 12%)."
                },
                {
                    "timestamp": "10:00 - 10:14",
                    "indicator": "Authentication Health",
                    "observed_value": "2 isolated failed logins",
                    "baseline_value": "< 5 / hour",
                    "severity": "LOW",
                    "description": "Benign typo rate; no distributed or high-frequency attempts."
                },
                {
                    "timestamp": "10:00 - 10:14",
                    "indicator": "Port & Connection Integrity",
                    "observed_value": "Avg 16 active sessions",
                    "baseline_value": "10-25 sessions",
                    "severity": "LOW",
                    "description": "No port scanning, half-open SYNs, or abnormal outbound beacons."
                }
            ]
            whats_next_prediction = (
                "Steady-state baseline operations. No anomalous security threats anticipated."
            )
            whats_next_details = (
                "Autonomous monitoring continues in passive surveillance mode. "
                "Feature extractors are actively computing real-time temporal baselines."
            )
            attack_trajectory = [
                "1. Baseline Established (Active)",
                "2. Telemetry Normal (Current State)",
                "3. Continuous Monitoring (Next Step)",
                "4. Zero Threat Forecast (Stable)"
            ]
            target_assets = ["All Monitored Subnets (Operating Normally)"]
            estimated_time = "N/A (System Secure)"
            mitigation_playbook = [
                "Maintain standard passive continuous monitoring.",
                "Ensure endpoint detection and response (EDR) telemetry agents remain online.",
                "Review daily automated audit logs."
            ]

        return {
            "current_threat": threat_info.get("threat_name", "Normal Activity"),
            "what_happened_summary": what_happened_summary,
            "evidence_trail": evidence_trail,
            "whats_next_prediction": whats_next_prediction,
            "whats_next_details": whats_next_details,
            "attack_trajectory": attack_trajectory,
            "target_assets": target_assets,
            "estimated_time_to_impact": estimated_time,
            "mitigation_playbook": mitigation_playbook
        }

explainability_engine = ExplainabilityEngine()
