"""Tests for the TCP probe and the scan orchestrator.

These use a real loopback listener so the async connect path is exercised end to
end. RFC 5737 TEST-NET-1 (192.0.2.0/24) is used for the unreachable case as it is
guaranteed not to be routed.
"""

from __future__ import annotations

import asyncio
import time

from app.core.probes.base import ProbeResult, ProbeStatus
from app.core.probes.tcp import TCPProbe
from app.core.scanner import ScanMode, Scanner, SubnetStatus


async def _start_listener() -> tuple[asyncio.AbstractServer, int]:
    async def handle(reader, writer):
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def test_tcp_probe_open_port_is_reachable():
    server, port = await _start_listener()
    try:
        probe = TCPProbe(ports=(port,), timeout=1.0)
        result = await probe.probe("127.0.0.1")
        assert result.status is ProbeStatus.REACHABLE
        assert result.method == f"tcp:{port}"
        assert result.response_ms is not None
    finally:
        server.close()
        await server.wait_closed()


async def test_tcp_probe_refused_port_still_reachable(monkeypatch):
    # A refused connection (RST) proves the host is up. Mocked so the test does
    # not depend on platform-specific behaviour for closed ports.
    async def fake_open_connection(host, port):
        raise ConnectionRefusedError()

    monkeypatch.setattr("app.core.probes.tcp.asyncio.open_connection", fake_open_connection)
    probe = TCPProbe(ports=(12345,), timeout=1.0)
    result = await probe.probe("127.0.0.1")
    assert result.status is ProbeStatus.REACHABLE
    assert "refused" in (result.method or "")


async def test_tcp_probe_unreachable_times_out():
    probe = TCPProbe(ports=(80,), timeout=0.3)
    result = await probe.probe("192.0.2.1")  # TEST-NET-1, not routed
    assert result.status is ProbeStatus.UNREACHABLE


async def test_scan_subnet_reachable_early_exit():
    server, port = await _start_listener()
    try:
        scanner = Scanner(
            probe=TCPProbe(ports=(port,), timeout=1.0),
            concurrency=8,
            mode=ScanMode.EARLY_EXIT,
        )
        result = await scanner.scan_subnet("127.0.0.1/32")
        assert result.status is SubnetStatus.REACHABLE
        assert result.first_host == "127.0.0.1"
        # Early exit: should not have probed more hosts than needed.
        assert result.hosts_checked == 1
    finally:
        server.close()
        await server.wait_closed()


async def test_scan_subnet_invalid_cidr_is_error():
    scanner = Scanner(probe=TCPProbe(), concurrency=4)
    result = await scanner.scan_subnet("not-a-cidr")
    assert result.status is SubnetStatus.ERROR
    assert result.error


class _SlowProbe:
    """A probe that sleeps a fixed time, to test concurrency timing."""

    name = "slow"

    def __init__(self, delay: float):
        self.delay = delay

    async def probe(self, host: str) -> ProbeResult:
        await asyncio.sleep(self.delay)
        return ProbeResult(host=host, status=ProbeStatus.UNREACHABLE)


class _SelectiveProbe:
    """Reports a fixed set of hosts as reachable; everything else unreachable."""

    name = "selective"

    def __init__(self, reachable: set[str]):
        self.reachable = reachable

    async def probe(self, host: str) -> ProbeResult:
        if host in self.reachable:
            return ProbeResult(host, ProbeStatus.REACHABLE, method="tcp:80", response_ms=1.0)
        return ProbeResult(host, ProbeStatus.UNREACHABLE)


async def test_full_mode_collects_all_reachable_hosts():
    probe = _SelectiveProbe({"10.0.0.1", "10.0.0.3"})
    scanner = Scanner(probe=probe, concurrency=8, mode=ScanMode.FULL)
    result = (await scanner.scan(["10.0.0.0/29"]))[0]
    assert result.status is SubnetStatus.REACHABLE
    hosts = {h.host for h in result.reachable_hosts}
    assert hosts == {"10.0.0.1", "10.0.0.3"}
    assert result.first_host in hosts


async def test_early_exit_collects_single_host():
    probe = _SelectiveProbe({"10.0.0.1", "10.0.0.3"})
    # concurrency=1 makes the order deterministic: .1 (gateway candidate) is first.
    scanner = Scanner(probe=probe, concurrency=1, mode=ScanMode.EARLY_EXIT)
    result = (await scanner.scan(["10.0.0.0/29"]))[0]
    assert result.status is SubnetStatus.REACHABLE
    assert len(result.reachable_hosts) == 1


async def test_subnets_are_scanned_concurrently():
    # Four 1-host subnets, each probe sleeps 0.2s. Run concurrently they finish in
    # ~0.2s; one-at-a-time they would take ~0.8s.
    scanner = Scanner(probe=_SlowProbe(0.2), concurrency=8, mode=ScanMode.FULL)
    cidrs = ["192.0.2.1/32", "192.0.2.2/32", "192.0.2.3/32", "192.0.2.4/32"]
    start = time.perf_counter()
    results = await scanner.scan(cidrs)
    elapsed = time.perf_counter() - start
    assert len(results) == 4
    assert all(r.status is SubnetStatus.UNREACHABLE for r in results)
    assert elapsed < 0.5, f"expected concurrent (~0.2s), took {elapsed:.2f}s"


async def test_on_subnet_complete_fires_for_each_including_errors():
    completed = []

    async def on_complete(result):
        completed.append((result.cidr, result.status))

    scanner = Scanner(
        probe=TCPProbe(ports=(9,), timeout=0.2), concurrency=8, mode=ScanMode.FULL
    )
    results = await scanner.scan(
        ["192.0.2.1/32", "bad-cidr"], on_subnet_complete=on_complete
    )
    assert len(results) == 2
    cidrs_done = {cidr for cidr, _ in completed}
    assert cidrs_done == {"192.0.2.1/32", "bad-cidr"}
    statuses = dict(completed)
    assert statuses["bad-cidr"] is SubnetStatus.ERROR


async def test_scan_returns_one_result_per_cidr():
    server, port = await _start_listener()
    try:
        scanner = Scanner(probe=TCPProbe(ports=(port,), timeout=0.3), concurrency=8)
        results = await scanner.scan(["127.0.0.1/32", "bad-cidr"])
        assert len(results) == 2
        assert results[0].status is SubnetStatus.REACHABLE
        assert results[1].status is SubnetStatus.ERROR
    finally:
        server.close()
        await server.wait_closed()
