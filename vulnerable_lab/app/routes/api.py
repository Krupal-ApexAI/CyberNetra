"""
API routes for Vulnerable Lab:
Exposes simulated endpoints for SQLi, Path Traversal, Command Injection,
and Resource Exhaustion (DoS).
"""

import os
import time
import subprocess
from typing import Optional
from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api", tags=["API"])

# Simulated user database
USER_DATABASE = [
    {"id": 1, "username": "admin", "role": "root", "email": "admin@apex-corp.internal", "department": "Executive"},
    {"id": 2, "username": "operator", "role": "soc_analyst", "email": "operator@apex-corp.internal", "department": "Security"},
    {"id": 3, "username": "dev_john", "role": "developer", "email": "john@apex-corp.internal", "department": "Engineering"},
    {"id": 4, "username": "sarah_hr", "role": "hr_manager", "email": "sarah@apex-corp.internal", "department": "HR"},
    {"id": 5, "username": "finance_bob", "role": "accountant", "email": "bob@apex-corp.internal", "department": "Finance"},
]

PRODUCT_CATALOG = [
    {"id": 101, "sku": "FW-ENTERPRISE-500", "name": "Next-Gen Edge Firewall Gateway", "price": 4999.00, "stock": 14},
    {"id": 102, "sku": "SIEM-COLLECTOR-VM", "name": "Log Forwarder Appliance Appliance", "price": 1299.00, "stock": 42},
    {"id": 103, "sku": "EDR-AGENT-50PK", "name": "Endpoint Sensor License 50-Pack", "price": 2450.00, "stock": 98},
    {"id": 104, "sku": "VPN-CONCENTRATOR", "name": "SSL-VPN Hardware Concentrator", "price": 3150.00, "stock": 8},
]

class AttackTriggerRequest(BaseModel):
    attack_type: str  # sqli, xss, traversal, cmd, brute, dos

class PingRequest(BaseModel):
    host: str

class DemoModeToggleRequest(BaseModel):
    enabled: bool

LOG_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "logs", "access.log"))


# ─────────────────────────────────────────────────────────────
# CyberNetra Demo Mode Endpoints
# ─────────────────────────────────────────────────────────────

@router.get("/demo-mode")
async def get_demo_mode_status():
    """
    Get current Demo Mode state, CyberNetra connection health,
    and telemetry transmission counters.
    """
    from app.services.demo_mode import demo_mode_manager
    return await demo_mode_manager.get_status()


@router.post("/demo-mode")
async def toggle_demo_mode(req: DemoModeToggleRequest):
    """
    Toggle Demo Mode ON or OFF.
    When ON: telemetry is forwarded to CyberNetra backend.
    When OFF: lab runs locally with isolated logging.
    """
    from app.services.demo_mode import demo_mode_manager
    return await demo_mode_manager.set_enabled(req.enabled)


@router.post("/demo-mode/reset")
async def reset_demo_mode():
    """
    Reset lab demo session counters (events sent, queued buffer).
    """
    from app.services.demo_mode import demo_mode_manager
    return await demo_mode_manager.reset_session()



@router.get("/users")
async def list_users(search: Optional[str] = None):
    """
    Search users endpoint:
    Vulnerable to simulated SQL Injection token detection.
    """
    if not search:
        return {"count": len(USER_DATABASE), "users": USER_DATABASE}

    search_lower = search.lower()
    # SQLi check
    if "' or '1'='1" in search_lower or "' or 1=1" in search_lower or "union" in search_lower:
        return {
            "injection_status": "SQL Injection query evaluated to TRUE",
            "count": len(USER_DATABASE),
            "users": USER_DATABASE,
            "raw_query": f"SELECT * FROM users WHERE username LIKE '%{search}%' OR email LIKE '%{search}%'"
        }

    filtered = [u for u in USER_DATABASE if search_lower in u["username"].lower() or search_lower in u["email"].lower()]
    return {"count": len(filtered), "users": filtered}


@router.get("/products")
async def list_products(category: Optional[str] = None):
    """List enterprise hardware catalog."""
    return {"count": len(PRODUCT_CATALOG), "products": PRODUCT_CATALOG}


@router.get("/logs/view")
async def view_log_file(file: str = Query("system.log", description="File name to read")):
    """
    Simulated Directory / Path Traversal endpoint:
    Intentionally vulnerable to ../../etc/passwd or path sequences.
    """
    file_lower = file.lower()
    
    # Path traversal simulation
    if ".." in file or "%2e%2e" in file_lower:
        if "passwd" in file_lower:
            simulated_passwd = (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                "soc_admin:x:1001:1001:SOC Admin:/home/soc_admin:/bin/bash\n"
                "netra_service:x:1002:1002:CyberNetra Agent:/opt/cybernetra:/bin/sh\n"
            )
            return {
                "file": file,
                "traversal_status": "SUCCESSFUL_TRAVERSAL",
                "content": simulated_passwd
            }
        elif "win.ini" in file_lower or "boot.ini" in file_lower:
            return {
                "file": file,
                "traversal_status": "SUCCESSFUL_TRAVERSAL",
                "content": "[fonts]\n[extensions]\n[mci extensions]\n[files]\n"
            }
        else:
            return {
                "file": file,
                "traversal_status": "TRAVERSAL_DETECTED",
                "content": f"[Simulated Content for file path: {file}]\nConfig: DB_HOST=10.0.4.15\nDB_PASS=SuperSecretCorpKey2026!"
            }

    return {
        "file": file,
        "content": f"2026-09-15 12:00:00 [INFO] System heartbeat verified.\n2026-09-15 12:05:00 [INFO] Backup routine finished."
    }


@router.post("/tools/ping")
async def network_ping_tool(req: PingRequest):
    """
    Simulated Command Injection endpoint:
    Accepts host parameter, evaluates shell commands if metacharacters are present.
    """
    host = req.host.strip()

    # Check for command injection sequences
    if any(sep in host for sep in [";", "&&", "|", "`", "$("]):
        # Simulated command execution response
        command_executed = host.split(";")[-1].strip() if ";" in host else host
        return {
            "target": host,
            "status": "VULNERABILITY_TRIGGERED",
            "type": "Command Injection (RCE)",
            "output": f"uid=33(www-data) gid=33(www-data) groups=33(www-data)\nLinux apex-server 5.15.0-generic #82-Ubuntu\nExecuted: {command_executed}"
        }

    return {
        "target": host,
        "status": "SUCCESS",
        "output": f"PING {host} (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.038 ms\n64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.041 ms\n--- {host} ping statistics ---\n2 packets transmitted, 2 received, 0% packet loss"
    }


@router.get("/resource-intensive")
async def resource_intensive(workload: int = Query(50000, ge=1000, le=5000000)):
    """
    Simulated resource-intensive endpoint for volumetric DoS testing.
    Consumes CPU cycles and adds artificial latency.
    """
    start = time.time()
    total = 0
    for i in range(min(workload, 200000)):
        total += (i * i) % 997
    duration_ms = round((time.time() - start) * 1000, 2)
    return {
        "status": "COMPLETED",
        "workload_cycles": workload,
        "duration_ms": duration_ms,
        "checksum": total
    }


@router.get("/telemetry/recent")
async def get_recent_telemetry(limit: int = Query(50, ge=1, le=200)):
    """
    Inspect the most recent security telemetry events recorded by the lab.
    """
    if not os.path.exists(LOG_FILE):
        return {"count": 0, "logs": []}

    logs = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
            for line in lines[-limit:]:
                line = line.strip()
                if line:
                    import json
                    logs.append(json.loads(line))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {"count": len(logs), "logs": logs}


@router.post("/attack/trigger")
async def trigger_attack(req: AttackTriggerRequest):
    """
    Interactive Attack Console endpoint:
    Programmatically triggers one of the 6 vulnerability surfaces and returns
    the result. Each call hits the lab's own vulnerable endpoints, generating
    real security telemetry via the middleware.
    """
    import httpx
    base = "http://127.0.0.1:" + str(os.environ.get("LAB_PORT", 9000))
    attack_type = req.attack_type.lower().strip()

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            if attack_type == "sqli":
                # SQL Injection — auth bypass
                r = await client.get(f"{base}/api/users", params={"search": "' OR '1'='1"})
                return {
                    "attack": "SQL Injection",
                    "mitre": "T1190",
                    "endpoint": "GET /api/users?search=' OR '1'='1",
                    "status": r.status_code,
                    "result": r.json(),
                    "telemetry": "Captured by SecurityLoggingMiddleware"
                }

            elif attack_type == "xss":
                # Reflected XSS via search
                r = await client.get(f"{base}/search", params={"q": "<script>alert('XSS')</script>"})
                return {
                    "attack": "Cross-Site Scripting (Reflected)",
                    "mitre": "T1059.007",
                    "endpoint": "GET /search?q=<script>alert('XSS')</script>",
                    "status": r.status_code,
                    "result": "XSS payload reflected in search results page",
                    "telemetry": "Captured by SecurityLoggingMiddleware"
                }

            elif attack_type == "traversal":
                # Path Traversal — read /etc/passwd
                r = await client.get(f"{base}/api/logs/view", params={"file": "../../etc/passwd"})
                return {
                    "attack": "Directory / Path Traversal",
                    "mitre": "T1083",
                    "endpoint": "GET /api/logs/view?file=../../etc/passwd",
                    "status": r.status_code,
                    "result": r.json(),
                    "telemetry": "Captured by SecurityLoggingMiddleware"
                }

            elif attack_type == "cmd":
                # OS Command Injection
                r = await client.post(f"{base}/api/tools/ping", json={"host": "127.0.0.1; whoami"})
                return {
                    "attack": "Remote OS Command Injection",
                    "mitre": "T1059",
                    "endpoint": "POST /api/tools/ping",
                    "payload": {"host": "127.0.0.1; whoami"},
                    "status": r.status_code,
                    "result": r.json(),
                    "telemetry": "Captured by SecurityLoggingMiddleware"
                }

            elif attack_type == "brute":
                # Brute force — 5 rapid failed logins
                results = []
                passwords = ["123456", "password", "admin", "qwerty", "letmein"]
                for pwd in passwords:
                    r = await client.post(f"{base}/auth/login", data={"username": "admin", "password": pwd})
                    results.append({"password": pwd, "status": r.status_code})
                return {
                    "attack": "Credential Brute-Force",
                    "mitre": "T1110",
                    "endpoint": "POST /auth/login",
                    "attempts": len(results),
                    "results": results,
                    "telemetry": "Each failed attempt (401) generates T1110 telemetry"
                }

            elif attack_type == "dos":
                # DoS — rapid resource-intensive requests
                results = []
                for i in range(10):
                    r = await client.get(f"{base}/api/resource-intensive", params={"workload": 50000})
                    results.append({"request": i + 1, "status": r.status_code})
                return {
                    "attack": "Denial of Service / Resource Exhaustion",
                    "mitre": "T1498",
                    "endpoint": "GET /api/resource-intensive?workload=50000",
                    "flood_requests": len(results),
                    "results": results,
                    "telemetry": "High request rate triggers T1498 rate_limit detection"
                }

            else:
                raise HTTPException(
                    status_code=400,
                    detail=f"Unknown attack type: '{attack_type}'. Use: sqli, xss, traversal, cmd, brute, dos"
                )

        except httpx.RequestError as e:
            return {
                "error": f"Failed to reach lab endpoint: {str(e)}",
                "hint": "Ensure the Vulnerable Lab is running on port 9000"
            }
