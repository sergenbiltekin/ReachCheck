"""Server-rendered HTML routes (the dashboard and scan detail pages).

These are separate from the JSON API under /api. The dashboard hosts the new-scan
form and recent history; the detail page renders current results and, for a
running scan, updates them live from the SSE stream.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from app import __version__
from app.config import settings
from app.core import profiles
from app.db.session import get_session
from app.models.schemas import ScanCreate
from app.services import history_service, scan_service
from app.services.scan_service import ScanRequestError
from app.tasks.manager import manager

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter(tags=["web"])

MODES = [
    ("early_exit", "Stop on first reachable"),
    ("full", "Scan all hosts"),
]


def _base_context(request: Request, **extra) -> dict:
    ctx = {
        "request": request,
        "app_name": settings.app_name,
        "version": __version__,
        "debug": settings.debug,
        "profiles": list(profiles.PROFILES.values()),
        "modes": MODES,
    }
    ctx.update(extra)
    return ctx


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, session: AsyncSession = Depends(get_session)):
    scans = await history_service.list_scans(session, limit=20)
    return templates.TemplateResponse(request, "index.html", _base_context(request, scans=scans))


@router.post("/scans")
async def submit_scan(
    request: Request,
    cidrs: str = Form(...),
    profile: str = Form("normal"),
    mode: str = Form("early_exit"),
    parent_scan_id: Optional[int] = Form(None),
    session: AsyncSession = Depends(get_session),
):
    payload = ScanCreate(cidrs=cidrs, profile=profile, mode=mode, parent_scan_id=parent_scan_id)
    try:
        scan = await scan_service.start_scan(session, payload)
    except ScanRequestError as exc:
        scans = await history_service.list_scans(session, limit=20)
        ctx = _base_context(
            request,
            scans=scans,
            error=str(exc),
            form={"cidrs": cidrs, "profile": profile, "mode": mode},
        )
        return templates.TemplateResponse(request, "index.html", ctx, status_code=400)
    return RedirectResponse(url=f"/scans/{scan.id}", status_code=303)


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(scan_id: int, request: Request, session: AsyncSession = Depends(get_session)):
    scan = await history_service.get_scan(session, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    unreachable = [r.cidr for r in scan.results if r.status == "unreachable"]
    children = await history_service.get_child_scans(session, scan_id)
    escalated = profiles.escalate(scan.profile)
    return templates.TemplateResponse(
        request,
        "scan_detail.html",
        _base_context(
            request,
            scan=scan,
            unreachable=unreachable,
            children=children,
            escalated_profile=escalated,
        ),
    )


@router.post("/scans/{scan_id}/delete")
async def delete_scan_web(scan_id: int, session: AsyncSession = Depends(get_session)):
    await manager.cancel(scan_id)  # best-effort stop if still running
    await history_service.delete_scan(session, scan_id)
    manager.cleanup(scan_id)
    return RedirectResponse(url="/", status_code=303)
