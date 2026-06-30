"""Probe abstraction.

A probe answers a single question about one host: "is it reachable?". Different
strategies (TCP connect, ICMP echo, a hybrid of both) implement the same
``Probe`` protocol, so the scanner stays decoupled from *how* reachability is
determined. New strategies can be added without touching the scanner.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable


class ProbeStatus(str, Enum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"


@dataclass(slots=True)
class ProbeResult:
    """Outcome of probing a single host."""

    host: str
    status: ProbeStatus
    method: str | None = None  # e.g. "tcp:443", "tcp:80 (refused)", "icmp"
    response_ms: float | None = None
    error: str | None = None

    @property
    def is_reachable(self) -> bool:
        return self.status is ProbeStatus.REACHABLE


@runtime_checkable
class Probe(Protocol):
    """Strategy interface for reachability checks."""

    name: str

    async def probe(self, host: str) -> ProbeResult:
        """Probe a single host and return the result. Must not raise for an
        ordinary unreachable host -- return an UNREACHABLE result instead."""
        ...
