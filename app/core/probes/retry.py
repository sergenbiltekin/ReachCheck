"""Retry decorator probe.

Wraps any probe and retries on an unreachable result, up to ``retries`` extra
attempts. Used by slower profiles to reduce false negatives from transient drops.
Composes via the same Probe protocol, so it is transparent to the scanner.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.probes.base import Probe, ProbeResult


@dataclass(slots=True)
class RetryProbe:
    inner: Probe
    retries: int = 0
    name: str = "retry"

    async def probe(self, host: str) -> ProbeResult:
        result = await self.inner.probe(host)
        attempts = 0
        while not result.is_reachable and attempts < self.retries:
            attempts += 1
            result = await self.inner.probe(host)
        return result
