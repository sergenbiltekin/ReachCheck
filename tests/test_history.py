"""Tests for history queries: child scans and deletion."""

from __future__ import annotations

from app.models.scan import Scan, SubnetResultRow
from app.services import history_service


async def _make_scan(session, **kwargs) -> Scan:
    scan = Scan(profile="fast", mode="early_exit", status="completed", **kwargs)
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    return scan


async def test_get_child_scans(session_factory):
    async with session_factory() as session:
        parent = await _make_scan(session, total_subnets=2)
        child_a = await _make_scan(session, parent_scan_id=parent.id)
        child_b = await _make_scan(session, parent_scan_id=parent.id)

        children = await history_service.get_child_scans(session, parent.id)
        ids = {c.id for c in children}
        assert ids == {child_a.id, child_b.id}

        assert await history_service.get_child_scans(session, child_a.id) == []


async def test_delete_scan_removes_results(session_factory):
    async with session_factory() as session:
        scan = await _make_scan(session, total_subnets=1)
        session.add(SubnetResultRow(scan_id=scan.id, cidr="10.0.0.0/30", status="unreachable"))
        await session.commit()
        scan_id = scan.id

    async with session_factory() as session:
        assert await history_service.delete_scan(session, scan_id) is True

    async with session_factory() as session:
        assert await history_service.get_scan(session, scan_id) is None
        # Results are gone too (cascade).
        from sqlalchemy import func, select

        count = await session.scalar(
            select(func.count())
            .select_from(SubnetResultRow)
            .where(SubnetResultRow.scan_id == scan_id)
        )
        assert count == 0


async def test_delete_missing_scan_returns_false(session_factory):
    async with session_factory() as session:
        assert await history_service.delete_scan(session, 99999) is False
