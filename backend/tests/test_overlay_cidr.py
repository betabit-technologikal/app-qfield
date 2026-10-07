"""Tests for IPv6-first allocation CIDR validation."""
import pytest

from backend.services.overlay_cidr import (
    IPV6_ALLOCATION_MAX_PREFIX,
    default_ipv6_allocation_cidr,
    validate_allocation_cidr,
)


def test_accepts_ula_64_and_96():
    assert validate_allocation_cidr("fd00:1::/64") == "fd00:1::/64"
    assert validate_allocation_cidr("FD00:2::0/96").endswith("/96")


def test_rejects_tighter_than_96():
    with pytest.raises(ValueError, match="/96"):
        validate_allocation_cidr("fd00:1::/97")
    with pytest.raises(ValueError, match="/96"):
        validate_allocation_cidr("fd00:1::/112")


def test_rejects_link_local_and_multicast():
    with pytest.raises(ValueError, match="link-local"):
        validate_allocation_cidr("fe80::/64")
    with pytest.raises(ValueError, match="multicast"):
        validate_allocation_cidr("ff00::/8")


def test_rejects_empty_and_garbage():
    with pytest.raises(ValueError, match="required"):
        validate_allocation_cidr("  ")
    with pytest.raises(ValueError, match="Invalid"):
        validate_allocation_cidr("not-a-cidr")


def test_default_is_random_ula_64():
    a = default_ipv6_allocation_cidr()
    b = default_ipv6_allocation_cidr()
    assert a.endswith("/64")
    assert b.endswith("/64")
    assert a.startswith("fd")
    # Extremely unlikely to collide
    assert a != b
    assert IPV6_ALLOCATION_MAX_PREFIX == 96
