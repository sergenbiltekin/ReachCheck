"""ICMP echo (ping) reachability probe.

ICMP requires raw-socket privileges (administrator on Windows, root/CAP_NET_RAW
on Linux). When those are missing, icmplib raises ``SocketPermissionError``. This
probe degrades gracefully: on the first permission error it disables itself and
reports every subsequent host as unreachable-by-icmp, so the hybrid probe can
fall back to TCP without paying the failure cost on every host.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from icmplib import async_ping
from icmplib.exceptions import ICMPLibError, SocketPermissionError

from app.core.probes.base import ProbeResult, ProbeStatus


@dataclass(slots=True)
class ICMPProbe:
    timeout: float = 1.0
    count: int = 1
    privileged: bool = True
    name: str = "icmp"
    # Flipped to False once we learn ICMP is unavailable in this process.
    available: bool = field(default=True)

    async def probe(self, host: str) -> ProbeResult:
        if not self.available:
            return ProbeResult(host=host, status=ProbeStatus.UNREACHABLE, error="icmp unavailable")

        try:
            reply = await async_ping(
                host,
                count=self.count,
                timeout=self.timeout,
                privileged=self.privileged,
            )
        except SocketPermissionError:
            # No privileges -> disable ICMP for the rest of this process.
            self.available = False
            return ProbeResult(
                host=host, status=ProbeStatus.UNREACHABLE, error="icmp permission denied"
            )
        except ICMPLibError as exc:
            return ProbeResult(host=host, status=ProbeStatus.UNREACHABLE, error=str(exc))

        if reply.is_alive:
            return ProbeResult(
                host=host,
                status=ProbeStatus.REACHABLE,
                method="icmp",
                response_ms=round(reply.avg_rtt, 2),
            )
        return ProbeResult(host=host, status=ProbeStatus.UNREACHABLE)
