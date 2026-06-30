"""In-process background scan manager.

Each running scan is a :class:`ScanJob` that owns an asyncio task and a set of
subscriber queues. The scan runner calls :meth:`ScanJob.emit` to broadcast events;
the SSE endpoint subscribes to receive them live. A rolling ``snapshot`` lets a
late subscriber catch up to the current state immediately.

This state is intentionally in-memory: ReachCheck is a single-user tool, and scans
are short-lived. Completed results are persisted in the database; only live
progress lives here.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Optional


@dataclass(slots=True)
class ScanEvent:
    type: str  # "status" | "progress" | "subnet_complete" | "scan_complete" | "error"
    scan_id: int
    data: dict[str, Any]


class ScanJob:
    def __init__(self, scan_id: int):
        self.scan_id = scan_id
        self.task: Optional[asyncio.Task] = None
        self.finished = asyncio.Event()
        self._subscribers: set[asyncio.Queue[ScanEvent]] = set()
        self.snapshot: dict[str, Any] = {
            "scan_id": scan_id,
            "status": "pending",
            "subnets": {},  # cidr -> {checked, total, status}
        }

    def subscribe(self) -> asyncio.Queue[ScanEvent]:
        queue: asyncio.Queue[ScanEvent] = asyncio.Queue()
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[ScanEvent]) -> None:
        self._subscribers.discard(queue)

    def emit(self, event: ScanEvent) -> None:
        self._apply_to_snapshot(event)
        for queue in list(self._subscribers):
            queue.put_nowait(event)

    def _apply_to_snapshot(self, event: ScanEvent) -> None:
        subnets = self.snapshot["subnets"]
        if event.type == "status":
            self.snapshot["status"] = event.data.get("status", self.snapshot["status"])
        elif event.type == "progress":
            entry = subnets.setdefault(event.data["cidr"], {})
            entry["checked"] = event.data.get("checked")
            entry["total"] = event.data.get("total")
            entry.setdefault("status", "running")
        elif event.type == "subnet_complete":
            subnets[event.data["cidr"]] = {**event.data, "status": event.data["status"]}
        elif event.type in ("scan_complete", "error"):
            self.snapshot["status"] = event.data.get("status", event.type)


class ScanManager:
    def __init__(self) -> None:
        self._jobs: dict[int, ScanJob] = {}

    def create(self, scan_id: int) -> ScanJob:
        job = ScanJob(scan_id)
        self._jobs[scan_id] = job
        return job

    def get(self, scan_id: int) -> Optional[ScanJob]:
        return self._jobs.get(scan_id)

    def start(self, job: ScanJob, coro) -> None:
        job.task = asyncio.create_task(coro)
        job.task.add_done_callback(lambda _t: job.finished.set())

    async def cancel(self, scan_id: int) -> bool:
        job = self._jobs.get(scan_id)
        if job and job.task and not job.task.done():
            job.task.cancel()
            return True
        return False

    def cleanup(self, scan_id: int) -> None:
        self._jobs.pop(scan_id, None)


# Process-wide singleton.
manager = ScanManager()
