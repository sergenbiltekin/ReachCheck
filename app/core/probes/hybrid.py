"""Hybrid reachability probe: ICMP first, TCP fallback.

A host can be unreachable by ICMP yet still reachable (ICMP filtered by a firewall
while a service port is open). So the rule is:

  1. Try ICMP. If it confirms the host is up, done.
  2. Otherwise -- ICMP unreachable *or* ICMP unavailable -- fall back to TCP.

This makes the tool work without privileges (ICMP simply disables itself and
every host goes through TCP) while still using the cheaper ICMP signal when it is
available.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.probes.base import Probe, ProbeResult
from app.core.probes.icmp import ICMPProbe
from app.core.probes.tcp import TCPProbe


@dataclass(slots=True)
class HybridProbe:
    icmp: ICMPProbe
    tcp: TCPProbe
    name: str = "hybrid"

    async def probe(self, host: str) -> ProbeResult:
        if self.icmp.available:
            icmp_result = await self.icmp.probe(host)
            if icmp_result.is_reachable:
                return icmp_result
        return await self.tcp.probe(host)


# Static type check: HybridProbe satisfies the Probe protocol.
_: type[Probe] = HybridProbe
