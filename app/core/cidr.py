"""CIDR parsing, validation and host expansion helpers.

ReachCheck answers "is this subnet reachable?", so the host list only needs to be
good enough to find *one* live host quickly. Expansion is therefore capped by a
safety limit and ordered so likely-live addresses (gateways) are probed first.

IPv4 only for now; IPv6 expansion is impractical and explicitly rejected.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

# Safety cap on the number of hosts expanded per subnet. A /16 already yields
# ~65k hosts; anything larger almost certainly indicates a mistake.
DEFAULT_HOST_LIMIT = 65536


class CidrError(ValueError):
    """Raised when a CIDR string is invalid or unsupported."""


class SubnetTooLargeError(CidrError):
    """Raised when a subnet expands to more hosts than the allowed limit."""


def parse_cidr(value: str) -> ipaddress.IPv4Network:
    """Parse a single CIDR (or bare IP, treated as /32) into an IPv4Network.

    Host bits are tolerated (strict=False), so "10.0.0.5/24" normalises to
    "10.0.0.0/24".
    """
    value = (value or "").strip()
    if not value:
        raise CidrError("Empty CIDR value.")
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise CidrError(f"Invalid CIDR '{value}': {exc}") from exc
    if isinstance(network, ipaddress.IPv6Network):
        raise CidrError(f"IPv6 is not supported yet: '{value}'.")
    return network


def split_input(text: str) -> list[str]:
    """Split free-form user input into individual CIDR tokens.

    Accepts whitespace, commas or semicolons as separators (e.g. a textarea).
    """
    parts = re.split(r"[\s,;]+", (text or "").strip())
    return [p for p in parts if p]


def parse_many(values: Iterable[str]) -> list[ipaddress.IPv4Network]:
    """Parse an iterable of CIDR strings, raising CidrError on the first bad one."""
    return [parse_cidr(v) for v in values]


def host_count(network: ipaddress.IPv4Network) -> int:
    """Number of probeable hosts in a network.

    For /31 and /32 every address is usable; otherwise the network and broadcast
    addresses are excluded.
    """
    if network.prefixlen >= 31:
        return network.num_addresses
    return network.num_addresses - 2


def expand_hosts(network: ipaddress.IPv4Network, limit: int = DEFAULT_HOST_LIMIT) -> list[str]:
    """Return all probeable host addresses as strings, in numeric order.

    Raises SubnetTooLargeError if the subnet exceeds ``limit``.
    """
    count = host_count(network)
    if count > limit:
        raise SubnetTooLargeError(f"Subnet {network} expands to {count} hosts (limit {limit}).")
    if network.prefixlen >= 31:
        return [str(ip) for ip in network]
    return [str(ip) for ip in network.hosts()]


def _gateway_candidates(network: ipaddress.IPv4Network) -> list[str]:
    """Addresses most likely to be live (default gateways), best-effort.

    Common conventions: first usable (.1), last usable (.254-style), .2.
    """
    net = int(network.network_address)
    bcast = int(network.broadcast_address)
    candidate_ints = [net + 1, bcast - 1, net + 254, net + 2]

    out: list[str] = []
    for value in candidate_ints:
        if network.prefixlen >= 31 or net < value < bcast:
            out.append(str(ipaddress.ip_address(value)))
    return out


def ordered_hosts(network: ipaddress.IPv4Network, limit: int = DEFAULT_HOST_LIMIT) -> list[str]:
    """Like :func:`expand_hosts`, but with likely-live gateways moved to the front.

    This makes early-exit scans usually find a live host within the first few
    probes instead of walking the whole range.
    """
    hosts = expand_hosts(network, limit=limit)
    if len(hosts) <= 2:
        return hosts

    host_set = set(hosts)
    ordered: list[str] = []
    seen: set[str] = set()

    for ip in _gateway_candidates(network):
        if ip in host_set and ip not in seen:
            ordered.append(ip)
            seen.add(ip)
    for ip in hosts:
        if ip not in seen:
            ordered.append(ip)
            seen.add(ip)
    return ordered
