"""
CyberNetra Controlled Vulnerable Lab — Demo Mode Manager.

Maintains persistent Demo Mode state on the Vulnerable Lab:
- Normal Lab Mode (enabled=False): Local logging only. Zero telemetry forwarded to CyberNetra.
- CyberNetra Demo Mode (enabled=True): Real-time incremental telemetry streamed to CyberNetra
  backend (POST /api/lab/ingest).

Includes resilient bounded queueing: if CyberNetra is unreachable, events buffer locally up to maxlen,
and automatically flush when connection is restored without stalling or crashing the lab.
"""

import os
import time
import asyncio
import logging
from typing import Dict, Any, List
from collections import deque

logger = logging.getLogger(__name__)

CYBERNETRA_API = os.environ.get("CYBERNETRA_API", "http://127.0.0.1:8000")
_BATCH_SIZE = 5
_FLUSH_INTERVAL = 1.5  # seconds
_MAX_QUEUE_LEN = 200


class DemoModeManager:
    def __init__(self):
        self.enabled: bool = False
        self.events_sent: int = 0
        self.cybernetra_connected: bool = False
        self.last_health_check: float = 0.0
        self.queue: deque = deque(maxlen=_MAX_QUEUE_LEN)
        self._lock = asyncio.Lock()
        self._worker_task: asyncio.Task = None

    def is_enabled(self) -> bool:
        return self.enabled

    async def check_connection(self) -> bool:
        """Probe CyberNetra backend health endpoint to verify connectivity."""
        now = time.time()
        # Cache health result for 2 seconds to avoid excessive pinging
        if now - self.last_health_check < 2.0:
            return self.cybernetra_connected

        self.last_health_check = now
        try:
            import httpx
            async with httpx.AsyncClient(timeout=2.0) as client:
                r = await client.get(f"{CYBERNETRA_API}/api/system-health")
                self.cybernetra_connected = (r.status_code == 200)
        except Exception:
            # Fallback check to /api/network-stats or /api/lab/status
            try:
                import httpx
                async with httpx.AsyncClient(timeout=2.0) as client:
                    r = await client.get(f"{CYBERNETRA_API}/api/network-stats")
                    self.cybernetra_connected = (r.status_code == 200)
            except Exception:
                self.cybernetra_connected = False

        return self.cybernetra_connected

    async def get_status(self) -> Dict[str, Any]:
        """Return comprehensive status for UI polling and API endpoints."""
        connected = await self.check_connection()

        if not self.enabled:
            telemetry_status = "INACTIVE"
        elif connected:
            telemetry_status = "ACTIVE"
        else:
            telemetry_status = "QUEUED LOCALLY"

        return {
            "enabled": self.enabled,
            "cybernetra_connected": connected,
            "cybernetra_api": CYBERNETRA_API,
            "telemetry_status": telemetry_status,
            "events_sent": self.events_sent,
            "events_queued": len(self.queue),
        }

    async def set_enabled(self, enabled: bool) -> Dict[str, Any]:
        """Toggle Demo Mode ON or OFF."""
        self.enabled = bool(enabled)
        if not self.enabled:
            # When turning off Demo Mode, drop any pending queue so telemetry stops immediately
            async with self._lock:
                self.queue.clear()
        else:
            self._ensure_worker_running()

        return await self.get_status()

    async def reset_session(self) -> Dict[str, Any]:
        """Reset local demo session counters and clear buffer."""
        async with self._lock:
            self.events_sent = 0
            self.queue.clear()
        return await self.get_status()

    async def enqueue_event(self, event: Dict[str, Any]):
        """Enqueue an event for forwarding if Demo Mode is enabled."""
        if not self.enabled:
            return

        self._ensure_worker_running()
        async with self._lock:
            self.queue.append(event)

    def _ensure_worker_running(self):
        """Start background flush worker if not already running."""
        if self._worker_task is None or self._worker_task.done():
            try:
                loop = asyncio.get_running_loop()
                self._worker_task = loop.create_task(self._background_flush_loop())
            except RuntimeError:
                pass

    async def _background_flush_loop(self):
        """Background worker that flushes queued events to CyberNetra backend."""
        import httpx
        while True:
            await asyncio.sleep(_FLUSH_INTERVAL)

            if not self.enabled or not self.queue:
                continue

            connected = await self.check_connection()
            if not connected:
                continue

            # Pop batch of events
            async with self._lock:
                batch = []
                while self.queue and len(batch) < _BATCH_SIZE:
                    batch.append(self.queue.popleft())

            if not batch:
                continue

            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    res = await client.post(
                        f"{CYBERNETRA_API}/api/lab/ingest",
                        json={"entries": batch},
                    )
                    if res.status_code in (200, 201):
                        self.events_sent += len(batch)
                        self.cybernetra_connected = True
                    else:
                        # Re-enqueue batch if server returned error
                        async with self._lock:
                            for item in reversed(batch):
                                if len(self.queue) < _MAX_QUEUE_LEN:
                                    self.queue.appendleft(item)
                        self.cybernetra_connected = False
            except Exception as e:
                logger.warning("Failed to forward telemetry batch to CyberNetra: %s", repr(e))
                self.cybernetra_connected = False
                # Re-enqueue batch on failure
                async with self._lock:
                    for item in reversed(batch):
                        if len(self.queue) < _MAX_QUEUE_LEN:
                            self.queue.appendleft(item)


# Singleton instance
demo_mode_manager = DemoModeManager()
