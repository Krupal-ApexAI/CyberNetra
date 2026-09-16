"""
Lab Status & Events API:
Exposes lab health, event statistics, recent event feed, and SSE streaming
for CyberNetra integration.
"""

import os
import json
import time
from datetime import datetime, timezone
from typing import Optional
from collections import defaultdict
from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse
import asyncio

router = APIRouter(prefix="/lab", tags=["Lab Status"])

LOG_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "logs", "access.log"))
_start_time = time.time()


def _read_all_events(limit: int = 500) -> list:
    """Read and parse the last N events from the access log."""
    if not os.path.exists(LOG_FILE):
        return []

    events = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
            for line in lines[-limit:]:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except Exception:
        pass
    return events


def _compute_stats(events: list) -> dict:
    """Compute aggregate statistics from event list."""
    type_counts = defaultdict(int)
    mitre_counts = defaultdict(int)
    attack_surface_counts = {
        "sqli": 0,
        "xss": 0,
        "traversal": 0,
        "cmd_injection": 0,
        "brute_force": 0,
        "dos": 0,
        "recon": 0,
    }

    for event in events:
        evt_type = event.get("event_type", "normal")
        type_counts[evt_type] += 1

        mitre = event.get("mitre_technique", "")
        if mitre:
            mitre_counts[mitre] += 1

        # Map MITRE techniques and indicators to attack surfaces
        indicator = (event.get("indicator", "") or "").lower()
        if mitre == "T1190" or "sql" in indicator:
            attack_surface_counts["sqli"] += 1
        elif mitre == "T1059.007" or "xss" in indicator or "script" in indicator:
            attack_surface_counts["xss"] += 1
        elif mitre == "T1083" or "traversal" in indicator:
            attack_surface_counts["traversal"] += 1
        elif mitre == "T1059" and "command" in indicator:
            attack_surface_counts["cmd_injection"] += 1
        elif mitre == "T1110" or "auth" in indicator or "brute" in indicator:
            attack_surface_counts["brute_force"] += 1
        elif mitre == "T1498" or "rate" in indicator or "flood" in indicator:
            attack_surface_counts["dos"] += 1
        elif mitre == "T1046" or "scan" in indicator or "probe" in indicator:
            attack_surface_counts["recon"] += 1

    return {
        "event_type_breakdown": dict(type_counts),
        "mitre_technique_counts": dict(mitre_counts),
        "attack_surface_counts": attack_surface_counts,
    }


@router.get("/status")
async def lab_status():
    """
    Returns lab health, uptime, total events, event breakdown, and last event timestamp.
    Used by CyberNetra backend to verify lab connectivity.
    """
    events = _read_all_events(limit=5000)
    stats = _compute_stats(events)
    uptime_seconds = round(time.time() - _start_time, 1)

    last_timestamp = None
    if events:
        last_timestamp = events[-1].get("timestamp")

    # Count attack events (non-normal)
    attack_events = [e for e in events if e.get("event_type", "normal") != "normal"]

    return {
        "status": "online",
        "app": "cybernetra-vulnerable-lab",
        "version": "1.0.0",
        "uptime_seconds": uptime_seconds,
        "total_events": len(events),
        "attack_events": len(attack_events),
        "normal_events": len(events) - len(attack_events),
        "last_event_timestamp": last_timestamp,
        "event_type_breakdown": stats["event_type_breakdown"],
        "mitre_technique_counts": stats["mitre_technique_counts"],
        "attack_surface_counts": stats["attack_surface_counts"],
        "telemetry_file": "logs/access.log",
        "port": int(os.environ.get("LAB_PORT", 9000)),
    }


@router.get("/events/recent")
async def recent_events(
    limit: int = Query(50, ge=1, le=500),
    event_type: Optional[str] = Query(None, description="Filter by event type: normal, suspicious_input, auth_failure, rate_limit, path_scan"),
):
    """
    Returns the most recent lab security events with optional filtering.
    """
    events = _read_all_events(limit=limit * 3)  # Read extra for filtering

    if event_type:
        events = [e for e in events if e.get("event_type") == event_type]

    # Return the last `limit` events, newest first
    recent = events[-limit:]
    recent.reverse()

    return {
        "count": len(recent),
        "events": recent,
    }


@router.get("/events/stream")
async def event_stream():
    """
    Server-Sent Events (SSE) endpoint for real-time telemetry streaming.
    The frontend or CyberNetra backend can subscribe to this for live events.
    """
    async def generate():
        last_size = 0
        if os.path.exists(LOG_FILE):
            last_size = os.path.getsize(LOG_FILE)

        # Send initial keepalive
        yield f"data: {json.dumps({'type': 'connected', 'message': 'Lab telemetry stream active'})}\n\n"

        while True:
            await asyncio.sleep(1.0)

            if not os.path.exists(LOG_FILE):
                continue

            current_size = os.path.getsize(LOG_FILE)
            if current_size > last_size:
                try:
                    with open(LOG_FILE, "r", encoding="utf-8") as f:
                        f.seek(last_size)
                        new_data = f.read()
                        last_size = f.tell()

                    for line in new_data.strip().split("\n"):
                        line = line.strip()
                        if line:
                            try:
                                event = json.loads(line)
                                yield f"data: {json.dumps({'type': 'event', 'event': event})}\n\n"
                            except json.JSONDecodeError:
                                continue
                except Exception:
                    continue

            # Keepalive every cycle
            yield ": keepalive\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/stats/summary")
async def stats_summary():
    """
    Returns a compact statistics summary for dashboard display.
    """
    events = _read_all_events(limit=5000)
    stats = _compute_stats(events)

    # Calculate events per minute (last 5 minutes)
    now = time.time()
    recent_window = []
    for event in reversed(events):
        ts = event.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if (now - dt.timestamp()) < 300:  # 5 minutes
                recent_window.append(event)
            else:
                break
        except (ValueError, AttributeError):
            continue

    events_per_minute = round(len(recent_window) / 5.0, 1) if recent_window else 0

    return {
        "total_events": len(events),
        "events_per_minute": events_per_minute,
        "attack_surfaces_triggered": sum(1 for v in stats["attack_surface_counts"].values() if v > 0),
        "total_attack_surfaces": 7,
        "uptime_seconds": round(time.time() - _start_time, 1),
        **stats,
    }
