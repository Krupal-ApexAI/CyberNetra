"""
CyberNetra Controlled Vulnerable Lab — Log Telemetry Forwarder
Reads security logs from access.log and ships them to CyberNetra's
detection engine (POST /api/analyze-logs or /api/lab/ingest) for ML classification and XAI reasoning.
"""

import os
import sys
import time
import json
import argparse
import requests

LOG_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "logs", "access.log"))
OFFSET_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "logs", ".offset"))
DEFAULT_CYBERNETRA_URL = "http://127.0.0.1:8000"


def read_offset() -> int:
    if os.path.exists(OFFSET_FILE):
        try:
            with open(OFFSET_FILE, "r") as f:
                return int(f.read().strip())
        except Exception:
            return 0
    return 0


def write_offset(offset: int):
    try:
        with open(OFFSET_FILE, "w") as f:
            f.write(str(offset))
    except Exception:
        pass


def format_log_as_network_record(entry: dict) -> str:
    """
    Converts a structured JSON lab log entry into the multi-format
    key-value network record that CyberNetra's log_parser.py understands.
    """
    client_ip = entry.get("client_ip", "127.0.0.1")
    method = entry.get("method", "GET")
    path = entry.get("path", "/")
    status = entry.get("status_code", 200)
    duration = entry.get("response_time_ms", 10.0)
    event_type = entry.get("event_type", "normal")
    indicator = entry.get("indicator", "")
    mitre = entry.get("mitre_technique", "")
    bytes_sent = entry.get("bytes_sent", 500)
    rate = entry.get("rate_10s", 1)

    # Key-value block format
    record = (
        f"Timestamp: {entry.get('timestamp')}\n"
        f"Protocol: TCP\n"
        f"Source IP: {client_ip}\n"
        f"Source Port: 52140\n"
        f"Destination IP: 127.0.0.1\n"
        f"Destination Port: 9000\n"
        f"Duration: {duration / 1000.0:.3f}\n"
        f"Source Bytes: {entry.get('bytes_received', 120)}\n"
        f"Destination Bytes: {bytes_sent}\n"
        f"HTTP Method: {method}\n"
        f"HTTP Path: {path}\n"
        f"HTTP Status: {status}\n"
        f"Event Type: {event_type}\n"
        f"Indicator: {indicator}\n"
        f"MITRE Technique: {mitre}\n"
        f"Rate 10s: {rate}\n"
    )
    return record


def ship_logs(cybernetra_url: str, reset_offset: bool = False, max_records: int = 50):
    if not os.path.exists(LOG_FILE):
        print(f"[-] No log file found at {LOG_FILE}.")
        print("    Run test_scenarios.py first to generate attack telemetry.")
        return

    offset = 0 if reset_offset else read_offset()

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        f.seek(offset)
        lines = f.readlines()
        new_offset = f.tell()

    if not lines:
        print("[*] No new telemetry records to ship. (All current logs already sent).")
        return

    print(f"[*] Found {len(lines)} new telemetry record(s) in access.log.")

    # Parse JSON entries
    parsed_entries = []
    text_blocks = []

    for line in lines[-max_records:]:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            parsed_entries.append(entry)
            text_blocks.append(format_log_as_network_record(entry))
        except Exception:
            continue

    if not text_blocks:
        print("[-] No valid records parsed.")
        return

    combined_text = "\n---\n".join(text_blocks)

    # First attempt direct structured ingest (/api/lab/ingest)
    lab_ingest_url = f"{cybernetra_url}/api/lab/ingest"
    analyze_url = f"{cybernetra_url}/api/analyze-logs"

    try:
        # Try /api/lab/ingest first
        r = requests.post(lab_ingest_url, json={"entries": parsed_entries}, timeout=10)
        if r.status_code == 200:
            res_data = r.json()
            print("[+] Successfully shipped via /api/lab/ingest!")
            _print_detection_results(res_data)
            write_offset(new_offset)
            return
    except Exception:
        pass

    # Fallback to standard /api/analyze-logs
    try:
        r = requests.post(analyze_url, json={"logs": combined_text}, timeout=15)
        if r.status_code == 200:
            res_data = r.json()
            print("[+] Successfully analyzed via CyberNetra /api/analyze-logs!")
            _print_detection_results(res_data)
            write_offset(new_offset)
        else:
            print(f"[-] CyberNetra returned error status {r.status_code}: {r.text[:200]}")
    except Exception as e:
        print(f"[-] Failed to connect to CyberNetra at {cybernetra_url}: {e}")
        print("    Ensure CyberNetra backend is running: python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000")


def _print_detection_results(res_data: dict):
    print("\n" + "=" * 65)
    print("  CYBERNETRA AI THREAT ANALYSIS REPORT")
    print("=" * 65)
    threat = res_data.get("threat_classification") or res_data.get("classification") or "Analyzed"
    prob = res_data.get("confidence") or res_data.get("threat_probability") or "High"
    records_count = res_data.get("records_analyzed", res_data.get("total_logs", 0))

    print(f"  * Records Processed:      {records_count}")
    print(f"  * Threat Classification:  {threat}")
    print(f"  * Model Probability:      {prob}")

    ai_exp = res_data.get("ai_explanation") or res_data.get("explanation")
    if ai_exp:
        print("\n  * AI Forensic Intelligence Brief:")
        # If string
        if isinstance(ai_exp, str):
            for line in ai_exp.split("\n")[:8]:
                print(f"    {line}")
        elif isinstance(ai_exp, dict):
            summary = ai_exp.get("summary") or ai_exp.get("incident_overview", "")
            print(f"    {summary}")

    playbook = res_data.get("mitigation_playbook") or res_data.get("playbook", [])
    if playbook:
        print("\n  * Recommended Containment Playbook:")
        if isinstance(playbook, list):
            for step in playbook[:3]:
                print(f"    - {step}")
    print("=" * 65 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Ship Vulnerable Lab Logs to CyberNetra AI")
    parser.add_argument("--url", default=DEFAULT_CYBERNETRA_URL, help="CyberNetra Backend URL (default: http://127.0.0.1:8000)")
    parser.add_argument("--all", action="store_true", help="Resend all logs from beginning of file")
    parser.add_argument("--follow", "-f", action="store_true", help="Continuously tail logs and ship in real-time")
    parser.add_argument("--interval", type=int, default=3, help="Poll interval in seconds for follow mode")
    args = parser.parse_args()

    print(f"[*] CyberNetra Log Forwarder active. Target: {args.url}")

    if args.all:
        ship_logs(args.url, reset_offset=True)
    else:
        ship_logs(args.url, reset_offset=False)

    if args.follow:
        print(f"[*] Tailing {LOG_FILE} every {args.interval}s (Press Ctrl+C to stop)...")
        try:
            while True:
                time.sleep(args.interval)
                ship_logs(args.url, reset_offset=False)
        except KeyboardInterrupt:
            print("\n[*] Stopped log forwarder.")


if __name__ == "__main__":
    main()
