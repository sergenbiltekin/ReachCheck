"""REST + SSE endpoints for scans.

POST   /api/scans              start a scan
GET    /api/scans              list recent scans
GET    /api/scans/{id}         scan detail with per-subnet results
POST   /api/scans/{id}/cancel  cancel a running scan
GET    /api/scans/{id}/stream  live progress via Server-Sent Events
"""

from __future__ import annotations

import asyncio
import csv
import io
import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.models.schemas import ScanCreate, ScanDetailOut, ScanSummaryOut
from app.services import history_service, scan_service
from app.services.scan_service import ScanRequestError
from app.tasks.manager import ScanEvent, manager

router = APIRouter(prefix="/api/scans", tags=["scans"])

# How long to wait for an event before sending an SSE keep-alive comment.
_KEEPALIVE_SECONDS = 15.0


@router.post("", response_model=ScanSummaryOut, status_code=201)
async def create_scan(payload: ScanCreate, session: AsyncSession = Depends(get_session)):
    try:
        scan = await scan_service.start_scan(session, payload)
    except ScanRequestError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ScanSummaryOut.model_validate(scan)


@router.get("", response_model=list[ScanSummaryOut])
async def list_scans(session: AsyncSession = Depends(get_session)):
    scans = await history_service.list_scans(session)
    return [ScanSummaryOut.model_validate(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanDetailOut)
async def get_scan(scan_id: int, session: AsyncSession = Depends(get_session)):
    scan = await history_service.get_scan(session, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return ScanDetailOut.model_validate(scan)


@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: int):
    cancelled = await manager.cancel(scan_id)
    if not cancelled:
        raise HTTPException(status_code=409, detail="Scan is not running.")
    return {"status": "cancelling"}


@router.delete("/{scan_id}")
async def delete_scan(scan_id: int, session: AsyncSession = Depends(get_session)):
    await manager.cancel(scan_id)  # best-effort stop if still running
    deleted = await history_service.delete_scan(session, scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found.")
    manager.cleanup(scan_id)
    return {"status": "deleted"}


_CSV_COLUMNS = [
    "cidr",
    "status",
    "first_host",
    "method",
    "reachable_hosts",
    "response_ms",
    "hosts_total",
    "hosts_checked",
    "duration_ms",
    "error",
]


@router.get("/{scan_id}/export")
async def export_scan(
    scan_id: int,
    export_format: str = Query("csv", alias="format"),
    session: AsyncSession = Depends(get_session),
):
    scan = await history_service.get_scan(session, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")

    if export_format == "json":
        payload = ScanDetailOut.model_validate(scan).model_dump(mode="json")
        return JSONResponse(
            payload,
            headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.json"'},
        )
    if export_format == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(_CSV_COLUMNS)
        for row in scan.results:
            hosts = ";".join(h.get("host", "") for h in (row.reachable_hosts or []))
            writer.writerow(
                [
                    row.cidr,
                    row.status,
                    row.first_host or "",
                    row.method or "",
                    hosts,
                    "" if row.response_ms is None else row.response_ms,
                    row.hosts_total,
                    row.hosts_checked,
                    row.duration_ms,
                    row.error or "",
                ]
            )
        return PlainTextResponse(
            buffer.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.csv"'},
        )

    raise HTTPException(status_code=400, detail="format must be 'csv' or 'json'.")


def _sse(event: ScanEvent) -> str:
    return f"event: {event.type}\ndata: {json.dumps(event.data)}\n\n"


@router.get("/{scan_id}/stream")
async def stream_scan(scan_id: int, request: Request):
    job = manager.get(scan_id)
    if job is None:
        # No live job (already finished or unknown). Tell the client to fall back
        # to the REST detail endpoint.
        async def closed():
            yield 'event: closed\ndata: {"reason": "no active job"}\n\n'

        return StreamingResponse(closed(), media_type="text/event-stream")

    async def event_stream():
        queue = job.subscribe()
        try:
            # Replay the current state so a late subscriber is immediately in sync.
            yield f"event: snapshot\ndata: {json.dumps(job.snapshot)}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=_KEEPALIVE_SECONDS)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                yield _sse(event)
                if event.type in ("scan_complete", "error"):
                    break
        finally:
            job.unsubscribe(queue)

    return StreamingResponse(event_stream(), media_type="text/event-stream")
