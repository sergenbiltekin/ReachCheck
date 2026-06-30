"""Scan orchestration service: create scans, run them in the background, persist.

Kept free of FastAPI/HTTP concerns so it can be driven from the API, the CLI or
tests. ``run_scan`` takes its dependencies (session factory, job) explicitly to
make it injectable in tests.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import Optional

from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core import cidr, profiles
from app.core.scanner import ScanMode, Scanner, ScanProgress, SubnetResult, SubnetStatus
from app.db.session import async_session_factory
from app.models.scan import Scan, SubnetResultRow
from app.models.schemas import ScanCreate
from app.tasks.manager import ScanEvent, ScanJob, manager

_VALID_MODES = {ScanMode.EARLY_EXIT.value, ScanMode.FULL.value}


class ScanRequestError(ValueError):
    """Raised when a scan request is invalid (bad CIDR list, profile or mode)."""


async def create_scan(session, payload: ScanCreate) -> tuple[Scan, list[str]]:
    """Validate the request and persist a pending Scan row.

    Returns the Scan and the list of CIDR tokens to hand to the runner.
    """
    tokens = cidr.split_input(payload.cidrs)
    if not tokens:
        raise ScanRequestError("Provide at least one CIDR.")
    try:
        profiles.get_profile(payload.profile)
    except KeyError as exc:
        raise ScanRequestError(str(exc)) from exc
    if payload.mode not in _VALID_MODES:
        raise ScanRequestError(
            f"Unknown mode '{payload.mode}'. Valid modes: {', '.join(sorted(_VALID_MODES))}."
        )

    scan = Scan(
        profile=payload.profile,
        mode=payload.mode,
        status="pending",
        parent_scan_id=payload.parent_scan_id,
        total_subnets=len(tokens),
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    return scan, tokens


async def start_scan(session, payload: ScanCreate) -> Scan:
    """Create a scan and launch it in the background. Shared by the API and the UI."""
    scan, tokens = await create_scan(session, payload)
    job = manager.create(scan.id)
    manager.start(
        job,
        run_scan(scan.id, tokens, payload.profile, payload.mode, job=job),
    )
    return scan


def _reachable_hosts_payload(result: SubnetResult) -> list[dict]:
    return [
        {"host": h.host, "method": h.method, "response_ms": h.response_ms}
        for h in result.reachable_hosts
    ]


def _result_to_event_data(result: SubnetResult) -> dict:
    return {
        "cidr": result.cidr,
        "status": result.status.value,
        "first_host": result.first_host,
        "method": result.method,
        "response_ms": result.response_ms,
        "reachable_hosts": _reachable_hosts_payload(result),
        "hosts_total": result.hosts_total,
        "hosts_checked": result.hosts_checked,
        "duration_ms": result.duration_ms,
        "error": result.error,
    }


async def run_scan(
    scan_id: int,
    tokens: Sequence[str],
    profile_name: str,
    mode_value: str,
    *,
    session_factory: async_sessionmaker = async_session_factory,
    job: Optional[ScanJob] = None,
) -> None:
    """Background entry point: run the scan, persist results, emit live events."""
    profile = profiles.get_profile(profile_name)
    probe = profiles.build_probe(profile)
    scanner = Scanner(probe=probe, concurrency=profile.concurrency, mode=ScanMode(mode_value))

    def emit(event_type: str, data: dict) -> None:
        if job is not None:
            job.emit(ScanEvent(type=event_type, scan_id=scan_id, data=data))

    async with session_factory() as session:
        scan = await session.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = "running"
        await session.commit()
        emit("status", {"status": "running"})

        # Subnets are scanned concurrently, so their completion callbacks run
        # interleaved. A lock serialises DB writes (AsyncSession is single-use).
        db_lock = asyncio.Lock()
        reachable = 0

        def on_progress(progress: ScanProgress) -> None:
            emit(
                "progress",
                {
                    "cidr": progress.cidr,
                    "checked": progress.hosts_checked,
                    "total": progress.hosts_total,
                },
            )

        async def on_subnet_complete(result: SubnetResult) -> None:
            nonlocal reachable
            async with db_lock:
                session.add(
                    SubnetResultRow(
                        scan_id=scan_id,
                        cidr=result.cidr,
                        status=result.status.value,
                        first_host=result.first_host,
                        method=result.method,
                        response_ms=result.response_ms,
                        reachable_hosts=_reachable_hosts_payload(result),
                        hosts_total=result.hosts_total,
                        hosts_checked=result.hosts_checked,
                        duration_ms=result.duration_ms,
                        error=result.error,
                    )
                )
                await session.commit()
                if result.status is SubnetStatus.REACHABLE:
                    reachable += 1
            emit("subnet_complete", _result_to_event_data(result))

        try:
            await scanner.scan(
                list(tokens),
                on_progress=on_progress,
                on_subnet_complete=on_subnet_complete,
            )

            scan.reachable_subnets = reachable
            scan.status = "completed"
            await session.commit()
            emit(
                "scan_complete",
                {"status": "completed", "reachable": reachable, "total": len(tokens)},
            )
        except asyncio.CancelledError:
            scan.reachable_subnets = reachable
            scan.status = "cancelled"
            await session.commit()
            emit("scan_complete", {"status": "cancelled", "reachable": reachable})
            raise
        except Exception as exc:  # noqa: BLE001 - report any failure to the client
            scan.status = "error"
            scan.error = str(exc)
            await session.commit()
            emit("error", {"status": "error", "message": str(exc)})
