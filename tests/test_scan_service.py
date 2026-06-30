"""Tests for the scan service (create + background run + persistence)."""

from __future__ import annotations

import pytest

from app.core import profiles
from app.models.schemas import ScanCreate
from app.services import history_service
from app.services.scan_service import ScanRequestError, create_scan, run_scan


def _tcp_only_profile(name: str, port: int) -> profiles.ScanProfile:
    return profiles.ScanProfile(
        name=name,
        label="Test",
        concurrency=8,
        timeout=0.5,
        retries=0,
        tcp_ports=(port,),
        use_icmp=False,
    )


async def test_create_scan_rejects_empty_cidrs(session_factory):
    async with session_factory() as session:
        with pytest.raises(ScanRequestError):
            await create_scan(session, ScanCreate(cidrs="   ", profile="fast"))


async def test_create_scan_rejects_unknown_profile(session_factory):
    async with session_factory() as session:
        with pytest.raises(ScanRequestError):
            await create_scan(session, ScanCreate(cidrs="10.0.0.0/30", profile="turbo"))


async def test_run_scan_persists_reachable(session_factory, listener, monkeypatch):
    monkeypatch.setitem(profiles.PROFILES, "t", _tcp_only_profile("t", listener))
    async with session_factory() as session:
        scan, tokens = await create_scan(
            session, ScanCreate(cidrs="127.0.0.1/32", profile="t", mode="early_exit")
        )
        scan_id = scan.id

    await run_scan(scan_id, tokens, "t", "early_exit", session_factory=session_factory)

    async with session_factory() as session:
        scan = await history_service.get_scan(session, scan_id)
        assert scan.status == "completed"
        assert scan.reachable_subnets == 1
        assert len(scan.results) == 1
        assert scan.results[0].status == "reachable"
        assert scan.results[0].first_host == "127.0.0.1"
        # The reachable host list is persisted (used by "scan all" mode).
        hosts = scan.results[0].reachable_hosts
        assert hosts and hosts[0]["host"] == "127.0.0.1"


async def test_run_scan_persists_unreachable(session_factory, monkeypatch):
    # No listener -> closed high port on TEST-NET times out -> unreachable.
    monkeypatch.setitem(profiles.PROFILES, "t", _tcp_only_profile("t", 9))
    async with session_factory() as session:
        scan, tokens = await create_scan(
            session, ScanCreate(cidrs="192.0.2.1/32", profile="t", mode="early_exit")
        )
        scan_id = scan.id

    await run_scan(scan_id, tokens, "t", "early_exit", session_factory=session_factory)

    async with session_factory() as session:
        scan = await history_service.get_scan(session, scan_id)
        assert scan.status == "completed"
        assert scan.reachable_subnets == 0
        assert scan.results[0].status == "unreachable"


async def test_get_unreachable_cidrs(session_factory, monkeypatch):
    monkeypatch.setitem(profiles.PROFILES, "t", _tcp_only_profile("t", 9))
    async with session_factory() as session:
        scan, tokens = await create_scan(
            session, ScanCreate(cidrs="192.0.2.1/32 192.0.2.2/32", profile="t")
        )
        scan_id = scan.id

    await run_scan(scan_id, tokens, "t", "early_exit", session_factory=session_factory)

    async with session_factory() as session:
        unreachable = await history_service.get_unreachable_cidrs(session, scan_id)
        assert set(unreachable) == {"192.0.2.1/32", "192.0.2.2/32"}
