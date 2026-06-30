"""Tests for the ICMP, hybrid and retry probes.

icmplib is mocked throughout so these run deterministically without raw-socket
privileges.
"""

from __future__ import annotations

from dataclasses import dataclass

from icmplib.exceptions import SocketPermissionError

from app.core.probes.base import ProbeResult, ProbeStatus
from app.core.probes.hybrid import HybridProbe
from app.core.probes.icmp import ICMPProbe
from app.core.probes.retry import RetryProbe


@dataclass
class _FakeReply:
    is_alive: bool
    avg_rtt: float = 1.5


def _patch_ping(monkeypatch, *, alive=True, raises=None):
    async def fake_async_ping(host, **kwargs):
        if raises is not None:
            raise raises
        return _FakeReply(is_alive=alive)

    monkeypatch.setattr("app.core.probes.icmp.async_ping", fake_async_ping)


async def test_icmp_reachable(monkeypatch):
    _patch_ping(monkeypatch, alive=True)
    result = await ICMPProbe().probe("10.0.0.1")
    assert result.status is ProbeStatus.REACHABLE
    assert result.method == "icmp"


async def test_icmp_not_alive_is_unreachable(monkeypatch):
    _patch_ping(monkeypatch, alive=False)
    result = await ICMPProbe().probe("10.0.0.1")
    assert result.status is ProbeStatus.UNREACHABLE


async def test_icmp_permission_error_disables_probe(monkeypatch):
    _patch_ping(monkeypatch, raises=SocketPermissionError("no privileges"))
    probe = ICMPProbe()
    result = await probe.probe("10.0.0.1")
    assert result.status is ProbeStatus.UNREACHABLE
    assert probe.available is False
    # Subsequent calls short-circuit without invoking icmplib again.
    result2 = await probe.probe("10.0.0.2")
    assert result2.error == "icmp unavailable"


# --- Hybrid ---------------------------------------------------------------


class _StubProbe:
    """A non-slotted probe stub that records call count and returns a fixed result."""

    def __init__(self, status: ProbeStatus, method: str | None = None, *, available=True):
        self._status = status
        self._method = method
        self.available = available  # used when standing in for ICMP
        self.calls = 0
        self.name = "stub"

    async def probe(self, host: str) -> ProbeResult:
        self.calls += 1
        return ProbeResult(host=host, status=self._status, method=self._method)


async def test_hybrid_returns_icmp_when_reachable():
    icmp_stub = _StubProbe(ProbeStatus.REACHABLE, method="icmp")
    tcp_stub = _StubProbe(ProbeStatus.REACHABLE, method="tcp:443")
    hybrid = HybridProbe(icmp=icmp_stub, tcp=tcp_stub)  # type: ignore[arg-type]
    result = await hybrid.probe("10.0.0.1")
    assert result.method == "icmp"
    assert tcp_stub.calls == 0  # TCP must not be called when ICMP confirms


async def test_hybrid_falls_back_to_tcp_when_icmp_unreachable():
    icmp_stub = _StubProbe(ProbeStatus.UNREACHABLE)
    tcp_stub = _StubProbe(ProbeStatus.REACHABLE, method="tcp:443")
    hybrid = HybridProbe(icmp=icmp_stub, tcp=tcp_stub)  # type: ignore[arg-type]
    result = await hybrid.probe("10.0.0.1")
    assert result.method == "tcp:443"
    assert tcp_stub.calls == 1


async def test_hybrid_skips_icmp_when_unavailable():
    icmp_stub = _StubProbe(ProbeStatus.UNREACHABLE, available=False)
    tcp_stub = _StubProbe(ProbeStatus.REACHABLE, method="tcp:80")
    hybrid = HybridProbe(icmp=icmp_stub, tcp=tcp_stub)  # type: ignore[arg-type]
    result = await hybrid.probe("10.0.0.1")
    assert result.method == "tcp:80"
    assert icmp_stub.calls == 0  # unavailable ICMP is not probed
    assert tcp_stub.calls == 1


# --- Retry ----------------------------------------------------------------


async def test_retry_stops_on_first_reachable():
    results = [
        ProbeResult("x", ProbeStatus.UNREACHABLE),
        ProbeResult("x", ProbeStatus.REACHABLE, method="tcp:80"),
    ]

    class _Seq:
        name = "seq"

        def __init__(self):
            self.calls = 0

        async def probe(self, host):
            r = results[self.calls]
            self.calls += 1
            return r

    seq = _Seq()
    retry = RetryProbe(inner=seq, retries=3)
    result = await retry.probe("10.0.0.1")
    assert result.status is ProbeStatus.REACHABLE
    assert seq.calls == 2  # stopped as soon as reachable


async def test_retry_exhausts_attempts():
    class _AlwaysDown:
        name = "down"

        def __init__(self):
            self.calls = 0

        async def probe(self, host):
            self.calls += 1
            return ProbeResult(host, ProbeStatus.UNREACHABLE)

    down = _AlwaysDown()
    retry = RetryProbe(inner=down, retries=2)
    result = await retry.probe("10.0.0.1")
    assert result.status is ProbeStatus.UNREACHABLE
    assert down.calls == 3  # 1 initial + 2 retries
