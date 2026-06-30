"""Scan profiles.

Profiles are plain data describing how aggressive a scan is: how many hosts to
probe at once, how long to wait, how many retries, which TCP ports to try, and
whether to use ICMP. Defining them as data (not code) keeps them easy to tune and
to extend with new profiles.

``build_probe`` assembles the concrete probe stack for a profile, composing the
hybrid/retry probes from phase-1/2 building blocks.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.probes.base import Probe
from app.core.probes.hybrid import HybridProbe
from app.core.probes.icmp import ICMPProbe
from app.core.probes.retry import RetryProbe
from app.core.probes.tcp import TCPProbe


@dataclass(frozen=True, slots=True)
class ScanProfile:
    name: str
    label: str
    concurrency: int
    timeout: float
    retries: int
    tcp_ports: tuple[int, ...]
    use_icmp: bool = True


FAST = ScanProfile(
    name="fast",
    label="Fast",
    concurrency=256,
    timeout=0.5,
    retries=0,
    tcp_ports=(80, 443),
)

NORMAL = ScanProfile(
    name="normal",
    label="Normal",
    concurrency=128,
    timeout=1.0,
    retries=1,
    tcp_ports=(22, 80, 443, 3389),
)

SLOW = ScanProfile(
    name="slow",
    label="Slow",
    concurrency=32,
    timeout=2.5,
    retries=2,
    tcp_ports=(22, 80, 443, 445, 3389, 8080, 8443),
)

PROFILES: dict[str, ScanProfile] = {p.name: p for p in (FAST, NORMAL, SLOW)}
DEFAULT_PROFILE = NORMAL

# Fast -> Normal -> Slow, from least to most thorough.
ESCALATION_ORDER = ("fast", "normal", "slow")


def escalate(name: str) -> str:
    """Return the next more-thorough profile name (clamped at the slowest).

    Used by "re-scan harder" to confirm an unreachable result with longer
    timeouts, more ports and retries. Unknown names are returned unchanged.
    """
    if name not in ESCALATION_ORDER:
        return name
    index = ESCALATION_ORDER.index(name)
    return ESCALATION_ORDER[min(index + 1, len(ESCALATION_ORDER) - 1)]


def get_profile(name: str) -> ScanProfile:
    """Look up a profile by name, raising KeyError with a helpful message."""
    try:
        return PROFILES[name]
    except KeyError:
        valid = ", ".join(PROFILES)
        raise KeyError(f"Unknown profile '{name}'. Valid profiles: {valid}.") from None


def build_probe(profile: ScanProfile) -> Probe:
    """Assemble the probe stack for a profile."""
    tcp = TCPProbe(ports=profile.tcp_ports, timeout=profile.timeout)
    probe: Probe
    if profile.use_icmp:
        probe = HybridProbe(icmp=ICMPProbe(timeout=profile.timeout), tcp=tcp)
    else:
        probe = tcp
    if profile.retries > 0:
        probe = RetryProbe(inner=probe, retries=profile.retries)
    return probe
