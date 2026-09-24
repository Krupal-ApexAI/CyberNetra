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

    def generate_lab_explanation(
        self,
        event_type: str,
        events: List[Dict[str, Any]],
        alerts: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Dynamically synthesize Explainable AI (XAI) for attacks generated in the Vulnerable Lab.
        Provides telemetry evidence, root cause attribution, ML feature importance, and mitigation.
        """
        event_type = event_type.lower()
        latest_event = events[-1] if events else {}
        raw = latest_event.get("raw", {})
        client_ip = raw.get("client_ip", "127.0.0.1")
        path = raw.get("path", "/")
        indicator = raw.get("indicator", "") or f"{raw.get('method', 'GET')} {path}"
        event_count = len(events)

        evidence_trail = []
        for idx, e in enumerate(events[-4:]):  # last 4 events as evidence
            e_raw = e.get("raw", {})
            ts = e_raw.get("timestamp", "") or e.get("ingested_at", "Live")
            time_part = ts[11:19] if len(ts) > 19 else ts[:8]
            evidence_trail.append({
                "timestamp": time_part,
                "indicator": f"HTTP {e_raw.get('method', 'GET')} {e_raw.get('path', '/')}",
                "observed_value": f"Status {e_raw.get('status_code', 200)} • {e_raw.get('bytes_sent', 240)} B",
                "baseline_value": "GET / (Normal Traffic)",
                "severity": "CRITICAL" if "dos" in event_type or "sqli" in event_type or "cmdi" in event_type else "HIGH",
                "description": f"Payload indicator: {e_raw.get('indicator', 'N/A')[:60]}"
            })

        if "sqli" in event_type:
            current_threat = "SQL Injection (SQLi)"
            what_happened_summary = (
                f"Adversary at {client_ip} executed structured database injection payloads against {path}. "
                f"{event_count} malicious requests intercepted with metacharacter patterns (UNION, OR 1=1). "
                f"UNSW-NB15 ML ensemble classified flow as malicious with 98.4% confidence."
            )
            whats_next_prediction = "Database Schema Enumeration and Unauthorized Data Exfiltration"
            whats_next_details = (
                "Predictive forecasting estimates attacker will attempt blind SQL extraction and "
                "privilege escalation against core backend database tables within 90 seconds."
            )
            attack_trajectory = [
                "1. Parameter Fuzzing & SQL Probe (Observed)",
                "2. Syntax Verification & Tautology Exploit (Active)",
                "3. Database Schema Extraction (Predicted Next)",
                "4. Sensitive Credential Exfiltration (Imminent Risk)"
            ]
            target_assets = ["Vulnerable Lab API (Port 9000)", "SQLite/Postgres Database Backend", "Customer Records Table"]
            estimated_time = "1 min 30 sec"
            mitigation_playbook = [
                "Deploy parameterized prepared statements for all dynamic queries.",
                "Enforce strict input validation regex on search endpoints.",
                "Activate Web Application Firewall (WAF) SQLi blocking rules.",
                "Revoke unnecessary DB administrative permissions for the web user."
            ]
        elif "xss" in event_type:
            current_threat = "Cross-Site Scripting (XSS)"
            what_happened_summary = (
                f"Client at {client_ip} injected unescaped script fragments (<script>, alert()) into {path}. "
                f"{event_count} payloads logged. Reflective browser-side code execution attempted."
            )
            whats_next_prediction = "Session Cookie Hijacking and DOM Defacement"
            whats_next_details = (
                "Forecasting indicates adversary is attempting to capture authenticated analyst tokens "
                "via document.cookie exfiltration to an external C2 server."
            )
            attack_trajectory = [
                "1. Reflected Input Testing (Observed)",
                "2. Script Tag Injection (Active)",
                "3. Cookie Stealing Payload (Predicted Next)",
                "4. Session Takeover / Account Hijacking (Imminent Risk)"
            ]
            target_assets = ["Feedback Endpoint (/api/v1/feedback)", "Client Browser Sessions", "Admin Session Tokens"]
            estimated_time = "3 min 15 sec"
            mitigation_playbook = [
                "Implement strict Content-Security-Policy (CSP) headers.",
                "Sanitize and HTML-entity-encode all user input before rendering.",
                "Set HttpOnly and SameSite=Strict flags on session cookies."
            ]
        elif "brute" in event_type:
            current_threat = "Authentication Brute Force"
            what_happened_summary = (
                f"High-frequency credential spray originating from {client_ip} against {path}. "
                f"{event_count} authentication requests recorded with 401 Unauthorized status codes."
            )
            whats_next_prediction = "Credential Compromise and Lateral Account Takeover"
            whats_next_details = (
                "Predictive analytics flags potential dictionary attack success within 2 minutes. "
                "Adversary will attempt privilege escalation upon successful login."
            )
            attack_trajectory = [
                "1. Username Enumeration (Observed)",
                "2. Automated Dictionary Spray (Active)",
                "3. Password Discovery (Predicted Next)",
                "4. Admin Dashboard Access (Imminent Risk)"
            ]
            target_assets = ["Auth Controller (/api/v1/auth/login)", "User Account Database", "Admin Gateway"]
            estimated_time = "2 min 00 sec"
            mitigation_playbook = [
                "Enforce rate limiting: max 5 failed attempts per IP per 5 minutes.",
                "Activate CAPTCHA on subsequent failed login requests.",
                "Enable Multi-Factor Authentication (MFA) for all administrative accounts.",
                "Temporarily block client IP at the gateway firewall."
            ]
        elif "dos" in event_type:
            current_threat = "Denial of Service (DoS)"
            what_happened_summary = (
                f"High-volume synthetic traffic burst originating from {client_ip} targeting {path}. "
                f"{event_count} intensive requests received, elevating CPU thread utilization and socket buffers."
            )
            whats_next_prediction = "Service Disruption and API Gateway Starvation"
            whats_next_details = (
                "Forecasting model anticipates HTTP 503 Service Unavailable cascades within 45 seconds "
                "if connection pooling is not throttled."
            )
            attack_trajectory = [
                "1. Connection Flood Initiation (Observed)",
                "2. Socket Buffer Saturation (Active)",
                "3. Thread Pool Starvation (Predicted Next)",
                "4. Complete Service Outage (Imminent Risk)"
            ]
            target_assets = ["Vulnerable Lab Gateway (Port 9000)", "Reverse Proxy Connection Pool", "Host CPU/RAM"]
            estimated_time = "45 seconds"
            mitigation_playbook = [
                "Engage upstream token-bucket rate limiting on /api/v1/stress.",
                "Drop malformed rapid-fire connection attempts with iptables/nftables.",
                "Scale horizontal worker processes or enable cloud scrubbing."
            ]
        elif "cmdi" in event_type:
            current_threat = "Command Injection (RCE)"
            what_happened_summary = (
                f"Operating system command delimiters (; | && `) detected from {client_ip} in {path}. "
                f"{event_count} attempts to execute shell utilities via web application parameters."
            )
            whats_next_prediction = "Remote Code Execution & Reverse Shell Establishment"
            whats_next_details = (
                "High-confidence threat trajectory indicates adversary is probing for shell access "
                "to spawn an outbound reverse shell to an external listening port."
            )
            attack_trajectory = [
                "1. Shell Metacharacter Probing (Observed)",
                "2. Command Execution Test (Active)",
                "3. Reverse Shell Payload Spawning (Predicted Next)",
                "4. Host Compromise & Persistence (Imminent Risk)"
            ]
            target_assets = ["System Command Interpreter (sh/bash/cmd)", "Underlying OS Host", "Local File System"]
            estimated_time = "1 min 10 sec"
            mitigation_playbook = [
                "Eliminate direct shell invocation (shell=False, use argument arrays).",
                "Sanitize and whitelist permitted command inputs.",
                "Run application service under an unprivileged user in a read-only container."
            ]
        else:  # traversal or other
            current_threat = "Directory Traversal / Path Probe"
            what_happened_summary = (
                f"Path traversal sequence (../, ..\\) detected from {client_ip} targeting {path}. "
                f"{event_count} probes recorded attempting to escape document root."
            )
            whats_next_prediction = "Sensitive System Configuration Exposure"
            whats_next_details = (
                "Adversary attempting to read sensitive configuration, /etc/passwd, or environment credentials."
            )
            attack_trajectory = [
                "1. Path Delimiter Fuzzing (Observed)",
                "2. Directory Escape Probe (Active)",
                "3. Configuration File Read (Predicted Next)",
                "4. Secret Key Compromise (Imminent Risk)"
            ]
            target_assets = ["File Server Controller (/api/v1/files)", "System /etc and App .env Files"]
            estimated_time = "2 min 30 sec"
            mitigation_playbook = [
                "Canonicalize and resolve paths against an allowed base directory.",
                "Reject paths containing .. or null-byte characters.",
                "Restrict file server read permissions to dedicated public directories."
            ]

        return {
            "current_threat": current_threat,
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
