"""
Network Log Parser for CyberNetra.

Parses common network-log formats into structured event dictionaries.
Supports multiple formats with robust fallback handling.
"""

import re
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime


# Maximum limits to prevent abuse
MAX_INPUT_BYTES = 512_000   # 500KB
MAX_LOG_LINES = 1000


# ──────────────────────────────────────────────
# Regex patterns for common log formats
# ──────────────────────────────────────────────

# Format: 2026-09-11 00:42:16 TCP 192.168.1.45:49231 -> 10.0.0.20:80
PATTERN_ARROW = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<proto>\w+)\s+"
    r"(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<src_port>\d+)\s+"
    r"(?:->|→|-->)\s+"
    r"(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<dst_port>\d+)"
    r"(?:\s+(?P<extra>.+))?"
)

# Format: TCP 192.168.1.45:49231 -> 10.0.0.20:80 (no timestamp)
PATTERN_ARROW_NO_TS = re.compile(
    r"(?P<proto>\w+)\s+"
    r"(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<src_port>\d+)\s+"
    r"(?:->|→|-->)\s+"
    r"(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<dst_port>\d+)"
    r"(?:\s+(?P<extra>.+))?"
)

# Format: Syslog-style with IP extraction
PATTERN_SYSLOG = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?:\S+)\s+"  # hostname
    r"(?:\S+):\s+"  # process
    r".*?(?P<proto>TCP|UDP|ICMP|tcp|udp|icmp)"
    r".*?(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<src_port>\d+))?"
    r".*?(?:->|→|-->|to)\s*"
    r"(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<dst_port>\d+))?"
)

# Format: Generic IP:port extraction (fallback)
PATTERN_GENERIC_IP = re.compile(
    r"(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<src_port>\d+))?"
    r".*?"
    r"(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<dst_port>\d+))?"
)

# Timestamp extraction (standalone)
PATTERN_TIMESTAMP = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
    r"|(?P<ts_syslog>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)

# Protocol extraction (standalone)
PATTERN_PROTO = re.compile(r"\b(TCP|UDP|ICMP|HTTP|HTTPS|SSH|FTP|DNS|SMTP|TLS)\b", re.IGNORECASE)

# Extra fields: bytes, packets, duration
PATTERN_BYTES = re.compile(r"(?:bytes?|len|size)\s*[=:]\s*(\d+)", re.IGNORECASE)
PATTERN_PACKETS = re.compile(r"(?:pkts?|packets?)\s*[=:]\s*(\d+)", re.IGNORECASE)
PATTERN_DURATION = re.compile(r"(?:dur(?:ation)?|time)\s*[=:]\s*([\d.]+)", re.IGNORECASE)


def validate_input(raw_text: str) -> Tuple[str, List[str]]:
    """Validate and sanitize input text. Returns (cleaned_text, warnings)."""
    warnings = []

    if not raw_text or not raw_text.strip():
        raise ValueError("Empty log input")

    if len(raw_text.encode("utf-8", errors="replace")) > MAX_INPUT_BYTES:
        raise ValueError(
            f"Log input exceeds maximum size of {MAX_INPUT_BYTES // 1024}KB"
        )

    lines = raw_text.strip().splitlines()
    if len(lines) > MAX_LOG_LINES:
        warnings.append(
            f"Input truncated from {len(lines)} to {MAX_LOG_LINES} lines"
        )
        lines = lines[:MAX_LOG_LINES]

    return "\n".join(lines), warnings


def parse_single_line(line: str, line_index: int) -> Optional[Dict[str, Any]]:
    """
    Parse a single log line into a structured event dict.
    Returns None for unparseable lines (comments, blanks, headers).
    """
    stripped = line.strip()

    # Skip empty lines, comments, headers, separators
    if not stripped:
        return None
    if stripped.startswith(("#", "//", "--", "=", "Paste", "timestamp")):
        return None
    if len(stripped) < 10:
        return None

    event: Dict[str, Any] = {
        "line_index": line_index,
        "raw_log": stripped,
        "timestamp": None,
        "src_ip": None,
        "src_port": None,
        "dst_ip": None,
        "dst_port": None,
        "protocol": None,
        "duration": None,
        "bytes_sent": None,
        "bytes_received": None,
        "packets": None,
        "parsing_warnings": [],
    }

    parsed = False

    # Try structured patterns in order of specificity
    m = PATTERN_ARROW.search(stripped)
    if m:
        event["timestamp"] = m.group("timestamp")
        event["protocol"] = m.group("proto").upper()
        event["src_ip"] = m.group("src_ip")
        event["src_port"] = int(m.group("src_port"))
        event["dst_ip"] = m.group("dst_ip")
        event["dst_port"] = int(m.group("dst_port"))
        parsed = True
        # Parse extra fields if present
        extra = m.group("extra")
        if extra:
            _extract_extra_fields(extra, event)
    else:
        m = PATTERN_ARROW_NO_TS.search(stripped)
        if m:
            event["protocol"] = m.group("proto").upper()
            event["src_ip"] = m.group("src_ip")
            event["src_port"] = int(m.group("src_port"))
            event["dst_ip"] = m.group("dst_ip")
            event["dst_port"] = int(m.group("dst_port"))
            parsed = True
            event["parsing_warnings"].append("No timestamp found in log line")

    if not parsed:
        m = PATTERN_SYSLOG.search(stripped)
        if m:
            event["timestamp"] = m.group("timestamp")
            event["protocol"] = m.group("proto").upper()
            event["src_ip"] = m.group("src_ip")
            event["src_port"] = int(m.group("src_port")) if m.group("src_port") else None
            event["dst_ip"] = m.group("dst_ip")
            event["dst_port"] = int(m.group("dst_port")) if m.group("dst_port") else None
            parsed = True

    if not parsed:
        # Fallback: extract any two IPs
        m = PATTERN_GENERIC_IP.search(stripped)
        if m:
            event["src_ip"] = m.group("src_ip")
            event["dst_ip"] = m.group("dst_ip")
            event["src_port"] = int(m.group("src_port")) if m.group("src_port") else None
            event["dst_port"] = int(m.group("dst_port")) if m.group("dst_port") else None
            parsed = True
            event["parsing_warnings"].append("Used fallback IP extraction pattern")

    if not parsed:
        return None  # Truly unparseable

    # Extract missing fields from line content
    if not event["timestamp"]:
        ts_m = PATTERN_TIMESTAMP.search(stripped)
        if ts_m:
            event["timestamp"] = ts_m.group("ts") or ts_m.group("ts_syslog")

    if not event["protocol"]:
        proto_m = PATTERN_PROTO.search(stripped)
        if proto_m:
            event["protocol"] = proto_m.group(1).upper()
        else:
            event["protocol"] = "TCP"  # Default assumption
            event["parsing_warnings"].append("Protocol defaulted to TCP")

    # Document missing fields
    if not event["src_port"]:
        event["parsing_warnings"].append("Source port not found")
    if not event["dst_port"]:
        event["parsing_warnings"].append("Destination port not found")

    return event


def _extract_extra_fields(extra: str, event: Dict[str, Any]):
    """Extract bytes, packets, duration from extra text after the main pattern."""
    bm = PATTERN_BYTES.search(extra)
    if bm:
        event["bytes_sent"] = int(bm.group(1))

    pm = PATTERN_PACKETS.search(extra)
    if pm:
        event["packets"] = int(pm.group(1))

    dm = PATTERN_DURATION.search(extra)
    if dm:
        event["duration"] = float(dm.group(1))


def _parse_kv_blocks(cleaned_text: str) -> List[Dict[str, Any]]:
    """Parse block/key-value formatted network logs into structured events."""
    raw_blocks = re.split(r'(?:\r?\n\s*\r?\n)|(?:(?=\b(?:DOS|Brute Force|Normal|Suspicious|\d+\.\s+Normal|\d+\.\s+DOS|\d+\.\s+Brute)\b))', cleaned_text.strip(), flags=re.IGNORECASE)
    events = []
    
    for idx, block in enumerate(raw_blocks):
        if not block.strip():
            continue
        lines = [l.strip() for l in block.splitlines() if l.strip()]
        kv = {}
        for line in lines:
            if ":" in line:
                k, v = line.split(":", 1)
                kv[k.strip().lower()] = v.strip()
        
        # Check if block has network telemetry indicators
        src_ip = kv.get("source ip") or kv.get("src ip") or kv.get("src_ip")
        dst_ip = kv.get("destination ip") or kv.get("dst ip") or kv.get("dst_ip")
        if src_ip or dst_ip or "protocol" in kv or "source port" in kv:
            src_port = int(re.sub(r"[^\d]", "", kv.get("source port", kv.get("src_port", "0"))) or "0")
            dst_port = int(re.sub(r"[^\d]", "", kv.get("destination port", kv.get("dst_port", "0"))) or "0")
            
            dur_str = kv.get("duration", "0.001")
            try:
                duration = float(re.findall(r"[\d.]+", dur_str)[0])
            except Exception:
                duration = 0.001

            pkts_str = kv.get("packets", kv.get("packet count", "1"))
            try:
                packets = int(re.findall(r"\d+", pkts_str)[0])
            except Exception:
                packets = 1

            bytes_str = kv.get("source bytes", kv.get("bytes sent", kv.get("bytes", kv.get("traffic volume", "100"))))
            try:
                bytes_sent = int(re.findall(r"\d+", bytes_str)[0])
            except Exception:
                bytes_sent = 100

            dbytes_str = kv.get("destination bytes", kv.get("bytes received", kv.get("bytes_received", kv.get("dbytes", "0"))))
            try:
                bytes_received = int(re.findall(r"\d+", dbytes_str)[0])
            except Exception:
                bytes_received = 0

            # If it's a web/HTTP event or indicator
            method = (kv.get("http method") or kv.get("method") or "").upper()
            path = kv.get("http path") or kv.get("path") or ""
            status_code_str = kv.get("http status") or kv.get("status code") or kv.get("status") or "200"
            try:
                status_code = int(re.findall(r"\d+", status_code_str)[0])
            except Exception:
                status_code = 200

            event_type = kv.get("event type") or kv.get("event_type") or "normal"
            indicator = kv.get("indicator") or ""
            mitre_technique = kv.get("mitre technique") or kv.get("mitre_technique") or ""

            rate_str = kv.get("connection rate", kv.get("rate", ""))
            try:
                rate_val = float(re.findall(r"[\d.]+", rate_str)[0]) if re.findall(r"[\d.]+", rate_str) else None
            except Exception:
                rate_val = None

            rep_str = kv.get("repeated connections", kv.get("connection attempts", "0"))
            try:
                rep_val = int(re.findall(r"\d+", rep_str)[0]) if re.findall(r"\d+", rep_str) else 0
            except Exception:
                rep_val = 0

            fail_str = kv.get("failed attempts", kv.get("failed login attempts", "0"))
            try:
                fail_val = int(re.findall(r"\d+", fail_str)[0]) if re.findall(r"\d+", fail_str) else 0
            except Exception:
                fail_val = 0

            state_raw = kv.get("connection state", kv.get("state", "CON")).upper()

            event = {
                "line_index": idx,
                "raw_log": block.strip(),
                "timestamp": kv.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                "src_ip": src_ip or "192.168.1.100",
                "src_port": src_port or 49152,
                "dst_ip": dst_ip or "10.0.0.1",
                "dst_port": dst_port or 80,
                "protocol": (kv.get("protocol") or "TCP").upper(),
                "duration": duration,
                "bytes_sent": bytes_sent,
                "bytes_received": bytes_received,
                "packets": packets,
                "connection_state": state_raw,
                "rate": rate_val,
                "repeated_connections": rep_val,
                "failed_attempts": fail_val,
                "method": method,
                "path": path,
                "status_code": status_code,
                "event_type": event_type,
                "indicator": indicator,
                "mitre_technique": mitre_technique,
                "parsing_warnings": []
            }
            events.append(event)
    return events


def parse_logs(raw_text: str) -> Dict[str, Any]:
    """
    Parse multiline log input into structured events.
    Supports both single-line streams and multi-line key-value blocks.
    """
    cleaned_text, global_warnings = validate_input(raw_text)
    lines = cleaned_text.splitlines()

    events = []
    skipped = 0

    # First try line-by-line parsing
    for idx, line in enumerate(lines):
        event = parse_single_line(line, idx)
        if event is not None:
            events.append(event)
        else:
            if line.strip() and not line.strip().startswith(("#", "//", "--", "=")):
                skipped += 1

    # If line-by-line parsing found nothing, try key-value block parsing
    if not events:
        block_events = _parse_kv_blocks(cleaned_text)
        if block_events:
            events = block_events
            skipped = 0

    if not events:
        global_warnings.append(
            "No valid network events could be parsed from the input"
        )

    return {
        "events": events,
        "total_lines": len(lines),
        "parsed_count": len(events),
        "skipped_count": skipped,
        "warnings": global_warnings,
    }
