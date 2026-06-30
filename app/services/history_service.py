"""Read-side queries over stored scans (history)."""

from __future__ import annotations

from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.scan import Scan


async def list_scans(session: AsyncSession, limit: int = 50) -> list[Scan]:
    """Most recent scans first (summary only, results not loaded)."""
    result = await session.execute(select(Scan).order_by(Scan.id.desc()).limit(limit))
    return list(result.scalars().all())


async def get_scan(session: AsyncSession, scan_id: int) -> Optional[Scan]:
    """A single scan with its subnet results eagerly loaded."""
    result = await session.execute(
        select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.results))
    )
    return result.scalar_one_or_none()


async def get_unreachable_cidrs(session: AsyncSession, scan_id: int) -> list[str]:
    """CIDRs that were unreachable in a scan -- the seed for a re-scan."""
    scan = await get_scan(session, scan_id)
    if scan is None:
        return []
    return [r.cidr for r in scan.results if r.status == "unreachable"]


async def get_child_scans(session: AsyncSession, scan_id: int) -> list[Scan]:
    """Scans that were created as re-scans of this one (most recent first)."""
    result = await session.execute(
        select(Scan).where(Scan.parent_scan_id == scan_id).order_by(Scan.id.desc())
    )
    return list(result.scalars().all())


async def delete_scan(session: AsyncSession, scan_id: int) -> bool:
    """Delete a scan and its results. Returns False if it does not exist."""
    scan = await get_scan(session, scan_id)  # loads results so ORM cascade applies
    if scan is None:
        return False
    await session.delete(scan)
    await session.commit()
    return True
