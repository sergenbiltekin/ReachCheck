"""Tests for scan profiles and probe assembly."""

from __future__ import annotations

import pytest

from app.core import profiles
from app.core.probes.hybrid import HybridProbe
from app.core.probes.retry import RetryProbe
from app.core.probes.tcp import TCPProbe


def test_all_profiles_registered():
    assert set(profiles.PROFILES) == {"fast", "normal", "slow"}


def test_get_profile_unknown_raises():
    with pytest.raises(KeyError):
        profiles.get_profile("turbo")


def test_fast_profile_has_no_retries_and_two_ports():
    fast = profiles.get_profile("fast")
    assert fast.retries == 0
    assert fast.tcp_ports == (80, 443)


def test_build_probe_fast_is_hybrid_without_retry():
    probe = profiles.build_probe(profiles.FAST)
    assert isinstance(probe, HybridProbe)


def test_build_probe_slow_wraps_in_retry():
    probe = profiles.build_probe(profiles.SLOW)
    assert isinstance(probe, RetryProbe)
    assert probe.retries == 2
    assert isinstance(probe.inner, HybridProbe)


def test_escalate_steps_up_then_clamps():
    assert profiles.escalate("fast") == "normal"
    assert profiles.escalate("normal") == "slow"
    assert profiles.escalate("slow") == "slow"  # clamped at the slowest


def test_escalate_unknown_returns_same():
    assert profiles.escalate("mystery") == "mystery"


def test_build_probe_without_icmp_is_plain_tcp():
    profile = profiles.ScanProfile(
        name="tcponly",
        label="TCP only",
        concurrency=64,
        timeout=1.0,
        retries=0,
        tcp_ports=(443,),
        use_icmp=False,
    )
    probe = profiles.build_probe(profile)
    assert isinstance(probe, TCPProbe)
