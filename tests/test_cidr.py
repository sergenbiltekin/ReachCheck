"""Tests for CIDR parsing, expansion and ordering."""

from __future__ import annotations

import pytest

from app.core import cidr


def test_parse_cidr_normalises_host_bits():
    net = cidr.parse_cidr("10.0.0.5/24")
    assert str(net) == "10.0.0.0/24"


def test_parse_bare_ip_is_slash_32():
    net = cidr.parse_cidr("192.168.1.10")
    assert net.prefixlen == 32
    assert cidr.host_count(net) == 1


@pytest.mark.parametrize("bad", ["", "   ", "not-a-cidr", "10.0.0.0/33", "999.0.0.0/24"])
def test_parse_invalid_raises(bad):
    with pytest.raises(cidr.CidrError):
        cidr.parse_cidr(bad)


def test_ipv6_rejected():
    with pytest.raises(cidr.CidrError):
        cidr.parse_cidr("2001:db8::/32")


def test_host_count_excludes_network_and_broadcast():
    assert cidr.host_count(cidr.parse_cidr("10.0.0.0/24")) == 254
    assert cidr.host_count(cidr.parse_cidr("10.0.0.0/31")) == 2
    assert cidr.host_count(cidr.parse_cidr("10.0.0.0/32")) == 1


def test_expand_hosts_count_matches():
    net = cidr.parse_cidr("10.0.0.0/29")
    hosts = cidr.expand_hosts(net)
    assert len(hosts) == 6
    assert "10.0.0.0" not in hosts  # network
    assert "10.0.0.7" not in hosts  # broadcast


def test_expand_hosts_respects_limit():
    net = cidr.parse_cidr("10.0.0.0/24")
    with pytest.raises(cidr.SubnetTooLargeError):
        cidr.expand_hosts(net, limit=10)


def test_ordered_hosts_puts_gateways_first():
    net = cidr.parse_cidr("192.168.1.0/24")
    ordered = cidr.ordered_hosts(net)
    # .1 and .254 are the usual gateway conventions -> probed first.
    assert ordered[0] == "192.168.1.1"
    assert "192.168.1.254" in ordered[:4]
    assert len(ordered) == 254
    assert len(set(ordered)) == 254  # no duplicates


def test_split_input():
    assert cidr.split_input("10.0.0.0/24, 10.0.1.0/24\n10.0.2.0/24") == [
        "10.0.0.0/24",
        "10.0.1.0/24",
        "10.0.2.0/24",
    ]
