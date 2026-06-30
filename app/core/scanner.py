"""Async scan orchestrator.

Scans one or more subnets and reports, per subnet, whether it is reachable. The
unit of interest is the *subnet*, not individual hosts -- ReachCheck asks "can I
reach this VLAN?", not "how many hosts are in it?".

All subnets are scanned together by a single global worker pool of ``concurrency``
workers, fed a round-robin interleaving of every subnet's hosts. This keeps total
in-flight probes bounded by ``concurrency`` while letting many subnets make
progress at once (instead of one subnet at a time). In EARLY_EXIT mode a subnet
stops being probed the moment one of its hosts answers, and its result is reported
immediately via ``on_subnet_complete``.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Union

from app.core import cidr
from app.core.probes.base import Probe, ProbeResult


class ScanMode(str, Enum):
    EARLY_EXIT = "early_exit"  # stop a subnet on the first reachable host
    FULL = "full"  # probe every host in the subnet


class SubnetStatus(str, Enum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    ERROR = "error"  # invalid CIDR, subnet too large, etc.


@dataclass(slots=True)
class ScanProgress:
    """Emitted after each host is probed, for live progress reporting."""

    cidr: str
    hosts_total: int
    hosts_checked: int
    last_result: ProbeResult


@dataclass(slots=True)
class SubnetResult:
    cidr: str
    status: SubnetStatus
    first_host: str | None = None
    method: str | None = None
    response_ms: float | None = None
    hosts_total: int = 0
    hosts_checked: int = 0
    reachable_hosts: list[ProbeResult] = field(default_factory=list)
    duration_ms: float = 0.0
    error: str | None = None


ProgressCallback = Callable[[ScanProgress], Union[None, Awaitable[None]]]
SubnetCompleteCallback = Callable[[SubnetResult], Union[None, Awaitable[None]]]


class _SubnetState:
    """Mutable per-subnet scan state, used while a scan is in flight."""

    __slots__ = (
        "target",
        "error",
        "hosts",
        "total",
        "remaining",
        "found",
        "reachable",
        "checked",
        "finished",
        "result",
        "start",
    )

    def __init__(self, target: str):
        self.target = target
        self.error: str | None = None
        self.hosts: list[str] = []
        self.total = 0
        self.remaining = 0
        self.found = asyncio.Event()
        self.reachable: list[ProbeResult] = []
        self.checked = 0
        self.finished = False
        self.result: SubnetResult | None = None
        self.start = time.perf_counter()


@dataclass
class Scanner:
    probe: Probe
    concurrency: int = 128
    mode: ScanMode = ScanMode.EARLY_EXIT
    host_limit: int = cidr.DEFAULT_HOST_LIMIT

    async def scan(
        self,
        cidrs: list[str],
        *,
        on_progress: Optional[ProgressCallback] = None,
        on_subnet_complete: Optional[SubnetCompleteCallback] = None,
    ) -> list[SubnetResult]:
        """Scan all CIDRs concurrently; return per-subnet results in input order.

        ``on_subnet_complete`` (if given) is awaited as each subnet finishes, which
        may be out of input order.
        """
        states = [self._prepare(target) for target in cidrs]

        # Resolve invalid/empty subnets immediately, before spinning up workers.
        active: list[_SubnetState] = []
        for state in states:
            if state.error is not None or state.total == 0:
                await self._finish(state, on_subnet_complete)
            else:
                active.append(state)

        work = self._interleave(active)
        if work:
            cursor = {"i": 0}

            async def worker() -> None:
                while True:
                    i = cursor["i"]
                    if i >= len(work):
                        return
                    cursor["i"] = i + 1
                    state, host = work[i]

                    skip = self.mode is ScanMode.EARLY_EXIT and state.found.is_set()
                    if not skip:
                        result = await self.probe.probe(host)
                        state.checked += 1
                        if result.is_reachable:
                            state.reachable.append(result)
                            if self.mode is ScanMode.EARLY_EXIT:
                                state.found.set()
                        if on_progress is not None:
                            maybe = on_progress(
                                ScanProgress(
                                    cidr=state.target,
                                    hosts_total=state.total,
                                    hosts_checked=state.checked,
                                    last_result=result,
                                )
                            )
                            if inspect.isawaitable(maybe):
                                await maybe

                    state.remaining -= 1
                    if not state.finished and (
                        state.remaining == 0
                        or (self.mode is ScanMode.EARLY_EXIT and state.found.is_set())
                    ):
                        await self._finish(state, on_subnet_complete)

            worker_count = min(self.concurrency, len(work)) or 1
            await asyncio.gather(*(worker() for _ in range(worker_count)))

        # Safety net: finalize anything not yet finished.
        for state in states:
            if not state.finished:
                await self._finish(state, on_subnet_complete)

        return [self._build_result(state) for state in states]

    async def scan_subnet(
        self, target: str, *, on_progress: Optional[ProgressCallback] = None
    ) -> SubnetResult:
        """Convenience wrapper to scan a single subnet."""
        results = await self.scan([target], on_progress=on_progress)
        return results[0]

    # --- internals --------------------------------------------------------

    def _prepare(self, target: str) -> _SubnetState:
        state = _SubnetState(target)
        try:
            network = cidr.parse_cidr(target)
            hosts = cidr.ordered_hosts(network, limit=self.host_limit)
        except cidr.CidrError as exc:
            state.error = str(exc)
            return state
        state.hosts = hosts
        state.total = len(hosts)
        state.remaining = len(hosts)
        return state

    def _build_result(self, state: _SubnetState) -> SubnetResult:
        if state.result is not None:
            return state.result

        duration_ms = round((time.perf_counter() - state.start) * 1000, 2)
        if state.error is not None:
            result = SubnetResult(
                cidr=state.target,
                status=SubnetStatus.ERROR,
                error=state.error,
                duration_ms=duration_ms,
            )
        elif state.reachable:
            first = state.reachable[0]
            result = SubnetResult(
                cidr=state.target,
                status=SubnetStatus.REACHABLE,
                first_host=first.host,
                method=first.method,
                response_ms=first.response_ms,
                hosts_total=state.total,
                hosts_checked=state.checked,
                reachable_hosts=list(state.reachable),
                duration_ms=duration_ms,
            )
        else:
            result = SubnetResult(
                cidr=state.target,
                status=SubnetStatus.UNREACHABLE,
                hosts_total=state.total,
                hosts_checked=state.checked,
                duration_ms=duration_ms,
            )
        state.result = result
        return result

    async def _finish(
        self, state: _SubnetState, callback: Optional[SubnetCompleteCallback]
    ) -> None:
        state.finished = True
        result = self._build_result(state)
        if callback is not None:
            maybe = callback(result)
            if inspect.isawaitable(maybe):
                await maybe

    @staticmethod
    def _interleave(states: list[_SubnetState]) -> list[tuple[_SubnetState, str]]:
        """Round-robin the subnets' hosts so all subnets progress together.

        Each subnet's hosts are already ordered with likely-live gateways first,
        so round-robin puts every subnet's best candidates near the front.
        """
        iterators = [iter(state.hosts) for state in states]
        exhausted = [False] * len(states)
        work: list[tuple[_SubnetState, str]] = []
        while not all(exhausted):
            for idx, iterator in enumerate(iterators):
                if exhausted[idx]:
                    continue
                try:
                    work.append((states[idx], next(iterator)))
                except StopIteration:
                    exhausted[idx] = True
        return work
