"""Command-line entry point for manual scan testing (no web server needed).

Examples:
    python -m app.cli 127.0.0.0/30 --ports 80 443 --mode early
    python -m app.cli 192.168.1.0/24 --timeout 0.5 --concurrency 256 --mode full

This is a developer/testing tool; the real interface is the web dashboard.
"""

from __future__ import annotations

import argparse
import asyncio

from app.core import profiles
from app.core.probes.tcp import TCPProbe
from app.core.scanner import ScanMode, Scanner, ScanProgress, SubnetStatus

_STATUS_LABEL = {
    SubnetStatus.REACHABLE: "REACHABLE",
    SubnetStatus.UNREACHABLE: "unreachable",
    SubnetStatus.ERROR: "ERROR",
}


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="reachcheck", description="Subnet reachability test")
    parser.add_argument("cidrs", nargs="+", help="One or more CIDRs, e.g. 10.0.0.0/24")
    parser.add_argument(
        "--profile",
        choices=list(profiles.PROFILES),
        help="Scan profile (overrides --ports/--timeout/--concurrency). "
        "Without it, a plain TCP probe is used.",
    )
    parser.add_argument("--ports", type=int, nargs="+", default=[80, 443])
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--concurrency", type=int, default=128)
    parser.add_argument(
        "--mode",
        choices=["early", "full"],
        default="early",
        help="early: stop a subnet on first reachable host; full: probe every host",
    )
    parser.add_argument("--verbose", action="store_true", help="print per-host progress")
    return parser.parse_args(argv)


async def _run(args: argparse.Namespace) -> None:
    if args.profile:
        profile = profiles.get_profile(args.profile)
        probe = profiles.build_probe(profile)
        concurrency = profile.concurrency
    else:
        probe = TCPProbe(ports=tuple(args.ports), timeout=args.timeout)
        concurrency = args.concurrency

    mode = ScanMode.EARLY_EXIT if args.mode == "early" else ScanMode.FULL
    scanner = Scanner(probe=probe, concurrency=concurrency, mode=mode)

    def on_progress(p: ScanProgress) -> None:
        if args.verbose:
            r = p.last_result
            print(f"  [{p.cidr}] {p.hosts_checked}/{p.hosts_total} {r.host} -> {r.status.value}")

    results = await scanner.scan(args.cidrs, on_progress=on_progress)

    print()
    for r in results:
        label = _STATUS_LABEL[r.status]
        if r.status is SubnetStatus.REACHABLE:
            detail = f"via {r.first_host} ({r.method}) in {r.response_ms} ms"
        elif r.status is SubnetStatus.ERROR:
            detail = r.error or ""
        else:
            detail = f"checked {r.hosts_checked}/{r.hosts_total} hosts in {r.duration_ms} ms"
        print(f"{r.cidr:<20} {label:<12} {detail}")


def main(argv: list[str] | None = None) -> None:
    asyncio.run(_run(_parse_args(argv)))


if __name__ == "__main__":
    main()
