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


def parse_logs(raw_text: str) -> Dict[str, Any]:
    """
    Parse multiline log input into structured events.

    Returns:
        {
            "events": [parsed event dicts],
            "total_lines": int,
            "parsed_count": int,
            "skipped_count": int,
            "warnings": [global warnings]
        }
    """
    cleaned_text, global_warnings = validate_input(raw_text)
    lines = cleaned_text.splitlines()

    events = []
    skipped = 0

    for idx, line in enumerate(lines):
        event = parse_single_line(line, idx)
        if event is not None:
            events.append(event)
        else:
            if line.strip() and not line.strip().startswith(("#", "//", "--", "=")):
                skipped += 1

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
