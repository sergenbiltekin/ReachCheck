"""Unprivileged TCP-connect reachability probe.

This probe works without elevated privileges on any platform, which makes it the
reliable default (and the fallback for the hybrid probe added in phase 2).

Reachability semantics for a *reachability* tool (not a port scanner):
  * connection succeeds          -> host is up  (port open)
  * connection actively refused  -> host is up  (it answered with a RST)
  * timeout / network error      -> this port did not prove the host is up

A host is reachable if *any* configured port yields one of the first two
outcomes. All ports timing out means unreachable (host down or fully filtered).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from app.core.probes.base import ProbeResult, ProbeStatus


@dataclass(slots=True)
class TCPProbe:
    ports: tuple[int, ...] = (80, 443)
    timeout: float = 1.0
    name: str = "tcp"

    async def probe(self, host: str) -> ProbeResult:
        start = time.perf_counter()

        tasks = [asyncio.create_task(self._check_port(host, p)) for p in self.ports]
        try:
            # Return as soon as a port proves the host is up; don't wait for slow
            # (filtered) ports to hit their full timeout.
            for coro in asyncio.as_completed(tasks):
                reachable, port, refused = await coro
                if reachable:
                    elapsed = (time.perf_counter() - start) * 1000
                    method = f"tcp:{port}" + (" (refused)" if refused else "")
                    return ProbeResult(
                        host=host,
                        status=ProbeStatus.REACHABLE,
                        method=method,
                        response_ms=round(elapsed, 2),
                    )
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        return ProbeResult(host=host, status=ProbeStatus.UNREACHABLE)

    async def _check_port(self, host: str, port: int) -> tuple[bool, int, bool]:
        """Return (reachable, port, refused) for a single port."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            return True, port, False
        except ConnectionRefusedError:
            return True, port, True
        except (asyncio.TimeoutError, OSError):
            return False, port, False
