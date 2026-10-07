"""Unit tests for cert_subnets helpers and multi -ip cert_sign args."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from backend.services.cert_networks import (
    DEFAULT_CERT_SUBNETS,
    effective_cert_subnets,
    host_cert_ip_cidrs,
    validate_cert_subnets,
)
from backend.utils.nebula_cert import cert_sign


def test_effective_default():
    assert effective_cert_subnets(None) == DEFAULT_CERT_SUBNETS
    assert effective_cert_subnets([]) == DEFAULT_CERT_SUBNETS


def test_validate_cert_subnets_ok():
    assert validate_cert_subnets(["fd00::/8", "fd00:1::/32"]) == [
        "fd00::/8",
        "fd00:1::/32",
    ]


def test_validate_cert_subnets_rejects_empty_and_bad():
    with pytest.raises(ValueError):
        validate_cert_subnets([])
    with pytest.raises(ValueError):
        validate_cert_subnets(["not-a-cidr"])
    with pytest.raises(ValueError):
        validate_cert_subnets(["ff00::/8"])  # multicast


def test_host_cert_ip_cidrs_allocation_plus_ula():
    cidrs = host_cert_ip_cidrs(
        "fd00:abcd:1:2::10",
        "fd00:abcd:1:2::/64",
        ["fd00::/8"],
    )
    assert cidrs == ["fd00:abcd:1:2::10/64", "fd00:abcd:1:2::10/8"]


def test_host_cert_ip_cidrs_skips_version_mismatch():
    cidrs = host_cert_ip_cidrs("10.0.0.5", "10.0.0.0/24", ["fd00::/8"])
    assert cidrs == ["10.0.0.5/24"]


def test_host_cert_ip_cidrs_outside_cert_subnet_warns_and_skips():
    # Allocation is ULA; cert claim is documentation space that does not contain it.
    cidrs = host_cert_ip_cidrs(
        "fd12::5",
        "fd12::/64",
        ["2001:db8::/32"],
    )
    assert cidrs == ["fd12::5/64"]


def test_cert_sign_passes_repeated_ip_flags(tmp_path: Path):
    ca_crt = tmp_path / "ca.crt"
    ca_key = tmp_path / "ca.key"
    out_crt = tmp_path / "host.crt"
    ca_crt.write_text("x")
    ca_key.write_text("y")
    with patch("backend.utils.nebula_cert.run_nebula_cert") as run:
        cert_sign(
            ca_crt,
            ca_key,
            name="node-a",
            ip="fd00:1::2",
            out_crt=out_crt,
            subnet_cidr="fd00:1::/64",
            cert_subnets=["fd00::/8"],
            allowed_roots=[tmp_path],
        )
    args = run.call_args[0][0]
    # Collect all -ip values
    ips = [args[i + 1] for i, a in enumerate(args) if a == "-ip"]
    assert ips == ["fd00:1::2/64", "fd00:1::2/8"]
