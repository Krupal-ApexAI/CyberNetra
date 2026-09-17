"""
CyberNetra Controlled Vulnerable Lab - Security Telemetry Middleware
Captures all HTTP requests/responses, performs signature and behavioral analysis,
and logs structured security events (JSON Lines) to access.log for CyberNetra ingestion.
Automatically forwards telemetry to CyberNetra backend in real-time.
"""

import os
import re
import json
import time
import asyncio
from datetime import datetime, timezone
from collections import defaultdict
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.services.demo_mode import demo_mode_manager

# Path to log file
LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "logs"))
LOG_FILE = os.path.join(LOG_DIR, "access.log")
os.makedirs(LOG_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────
# Signature & Pattern Definitions
# ─────────────────────────────────────────────────────────────

SQLI_PATTERNS = [
    re.compile(r"('|\%27)\s*(OR|AND)\s*('|\%27)?(\d+|\w+)\s*=\s*('|\%27)?\4", re.IGNORECASE),
    re.compile(r"UNION\s+(ALL\s+)?SELECT", re.IGNORECASE),
    re.compile(r"(--|#|/\*|xp_cmdshell|WAITFOR\s+DELAY)", re.IGNORECASE),
    re.compile(r"(DROP\s+TABLE|INSERT\s+INTO|SELECT\s+.*\s+FROM)", re.IGNORECASE),
    re.compile(r"('|\%27)\s*OR\s*1\s*=\s*1", re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r"<script[^>]*>", re.IGNORECASE),
    re.compile(r"javascript:\s*", re.IGNORECASE),
    re.compile(r"on(error|load|click|mouseover|submit)\s*=", re.IGNORECASE),
    re.compile(r"<img[^>]+src=[^>]+onerror=", re.IGNORECASE),
    re.compile(r"<iframe[^>]*>", re.IGNORECASE),
    re.compile(r"document\.(cookie|location|write)", re.IGNORECASE),
]

TRAVERSAL_PATTERNS = [
    re.compile(r"(\.\./|\.\.\\|\%2e\%2e\%2f|\%2e\%2e/)", re.IGNORECASE),
    re.compile(r"(etc/passwd|windows/system32|boot\.ini|win\.ini)", re.IGNORECASE),
]

CMD_INJECTION_PATTERNS = [
    re.compile(r"(;|&&|\||\`|\$\([^)]+\))\s*(whoami|cat|id|dir|ls|uname|ping|curl|wget)", re.IGNORECASE),
]

SCAN_PATHS = [
    "/.env", "/.git", "/wp-admin", "/wp-login.php", "/phpmyadmin",
    "/administrator", "/admin/backup", "/config.php", "/actuator",
    "/server-status", "/web.config", "/.aws/credentials"
]

# Sensitive keys to redact from logs
SENSITIVE_KEYS = {"password", "passwd", "pwd", "secret", "token", "auth", "credit_card"}

# ─────────────────────────────────────────────────────────────
# State Trackers (Rate Tracking & Failed Logins)
# ─────────────────────────────────────────────────────────────

# { ip: [timestamps] }
_ip_request_times = defaultdict(list)
# { ip: [failed_timestamps] }
_ip_failed_logins = defaultdict(list)

def _sanitize_data(data: dict) -> dict:
    """Scrub sensitive fields (passwords, tokens) before logging."""
    sanitized = {}
    for k, v in data.items():
        if any(s in k.lower() for s in SENSITIVE_KEYS):
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, dict):
            sanitized[k] = _sanitize_data(v)
        else:
            sanitized[k] = v
    return sanitized


class SecurityLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        client_ip = request.client.host if request.client else "127.0.0.1"
        method = request.method
        path = request.url.path
        query_str = str(request.url.query)
        user_agent = request.headers.get("user-agent", "Unknown")

        # Sliding window rate tracking (10-second window)
        now = time.time()
        _ip_request_times[client_ip] = [t for t in _ip_request_times[client_ip] if now - t < 10.0]
        _ip_request_times[client_ip].append(now)
        req_count_10s = len(_ip_request_times[client_ip])

        # Inspect query params
        query_params = dict(request.query_params)
        sanitized_query = _sanitize_data(query_params)

        # Inspect body safely without consuming it permanently
        body_str = ""
        try:
            body_bytes = await request.body()
            body_len = len(body_bytes)
            if body_bytes and len(body_bytes) < 10000:
                body_str = body_bytes.decode("utf-8", errors="ignore")
        except Exception:
            body_len = 0

        # Run attack detection heuristics
        event_type = "normal"
        indicator = ""
        mitre_technique = ""

        # 1. Path scanning / Reconnaissance (T1046 / T1595)
        for scan_path in SCAN_PATHS:
            if scan_path in path.lower():
                event_type = "path_scan"
                indicator = f"Perimeter probing / scan targeting sensitive path: '{path}'"
                mitre_technique = "T1046"
                break

        # 2. SQL Injection detection (T1190)
        target_check = f"{path} {query_str} {body_str}"
        if event_type == "normal":
            for pat in SQLI_PATTERNS:
                if pat.search(target_check):
                    event_type = "suspicious_input"
                    indicator = f"SQL Injection signature detected: {pat.pattern}"
                    mitre_technique = "T1190"
                    break

        # 3. Cross-Site Scripting (XSS) detection (T1059.007)
        if event_type == "normal":
            for pat in XSS_PATTERNS:
                if pat.search(target_check):
                    event_type = "suspicious_input"
                    indicator = f"Cross-Site Scripting (XSS) payload detected: {pat.pattern}"
                    mitre_technique = "T1059.007"
                    break

        # 4. Path Traversal detection (T1083 / T1005)
        if event_type == "normal":
            for pat in TRAVERSAL_PATTERNS:
                if pat.search(target_check):
                    event_type = "suspicious_input"
                    indicator = f"Directory Traversal pattern detected: {pat.pattern}"
                    mitre_technique = "T1083"
                    break

        # 5. OS Command Injection detection (T1059)
        if event_type == "normal":
            for pat in CMD_INJECTION_PATTERNS:
                if pat.search(target_check):
                    event_type = "suspicious_input"
                    indicator = f"Command Injection payload detected: {pat.pattern}"
                    mitre_technique = "T1059"
                    break

        # 6. Rate Limit / Request Flood (T1498)
        if req_count_10s > 25:
            event_type = "rate_limit"
            indicator = f"High request rate detected ({req_count_10s} reqs/10s from {client_ip})"
            mitre_technique = "T1498"

        # Execute downstream request
        response: Response = await call_next(request)
        duration_ms = round((time.time() - start_time) * 1000, 2)
        status_code = response.status_code

        # 7. Check for Auth Failures / Brute Force (T1110)
        if path.startswith("/auth/login") and method == "POST" and status_code in (401, 403):
            _ip_failed_logins[client_ip] = [t for t in _ip_failed_logins[client_ip] if now - t < 60.0]
            _ip_failed_logins[client_ip].append(now)
            failed_count = len(_ip_failed_logins[client_ip])
            event_type = "auth_failure"
            indicator = f"Authentication failure ({failed_count} failed in last 60s)"
            mitre_technique = "T1110"

        # Calculate bytes sent
        bytes_sent = int(response.headers.get("content-length", 0))

        # Build telemetry log entry
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "query_params": sanitized_query,
            "status_code": status_code,
            "response_time_ms": duration_ms,
            "user_agent": user_agent,
            "bytes_received": body_len,
            "bytes_sent": bytes_sent,
            "event_type": event_type,
            "indicator": indicator,
            "mitre_technique": mitre_technique,
            "rate_10s": req_count_10s
        }

        # Write to JSON Lines log
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception:
            pass

        # Forward to CyberNetra backend ONLY when Demo Mode is ON
        if demo_mode_manager.is_enabled():
            try:
                await demo_mode_manager.enqueue_event(log_entry)
            except Exception:
                pass

        return response
