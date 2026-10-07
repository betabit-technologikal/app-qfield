"""Build Nebula host cert -ip network list from allocation + network cert_subnets."""
from __future__ import annotations

import ipaddress
import logging
from typing import Optional, Sequence, Union

logger = logging.getLogger(__name__)

IpNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

DEFAULT_CERT_SUBNETS = ["fd00::/8"]


def effective_cert_subnets(cert_subnets: Optional[Sequence[str]]) -> list[str]:
    """
    Network.cert_subnets with product default. None/empty -> [fd00::/8].
    """
    if not cert_subnets:
        return list(DEFAULT_CERT_SUBNETS)
    out: list[str] = []
    for raw in cert_subnets:
        s = (raw or "").strip()
        if not s:
            continue
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError as e:
            logger.error("Ignoring invalid cert_subnet %r: %s", raw, e)
            continue
        out.append(str(net))
    return out or list(DEFAULT_CERT_SUBNETS)


def validate_cert_subnets(cert_subnets: Sequence[str]) -> list[str]:
    """Parse/validate a cert_subnets list for API write. Raises ValueError."""
    if not cert_subnets:
        raise ValueError("cert_subnets must contain at least one CIDR")
    out: list[str] = []
    seen: set[str] = set()
    for raw in cert_subnets:
        s = (raw or "").strip()
        if not s:
            raise ValueError("cert_subnets entries must not be empty")
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid cert_subnet CIDR {raw!r}: {e}") from e
        if net.is_multicast or net.is_loopback or net.is_unspecified or net.is_link_local:
            raise ValueError(f"cert_subnet {net} is not a usable overlay range")
        key = str(net)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    if not out:
        raise ValueError("cert_subnets must contain at least one CIDR")
    logger.info("cert_subnets validated: %s", out)
    return out


def host_cert_ip_cidrs(
    allocated_ip: str,
    allocation_cidr: str,
    cert_subnets: Optional[Sequence[str]] = None,
) -> list[str]:
    """
    Nebula -ip values for a host cert: allocation membership plus every cert_subnet
    that contains the allocated address (same address, different prefix lengths).

    Example: allocated fd00:1::2 from fd00:1::/64 with cert_subnets [fd00::/8]
    -> ["fd00:1::2/64", "fd00:1::2/8"]
    """
    try:
        addr = ipaddress.ip_address(allocated_ip.strip())
    except ValueError as e:
        logger.error("host_cert_ip_cidrs: bad allocated_ip %r: %s", allocated_ip, e)
        raise ValueError(f"Invalid allocated IP: {allocated_ip!r}") from e
    try:
        alloc_net: IpNetwork = ipaddress.ip_network(allocation_cidr.strip(), strict=False)
    except ValueError as e:
        logger.error(
            "host_cert_ip_cidrs: bad allocation_cidr %r: %s", allocation_cidr, e
        )
        raise ValueError(f"Invalid allocation CIDR: {allocation_cidr!r}") from e

    if addr not in alloc_net:
        logger.error(
            "host_cert_ip_cidrs: allocated %s outside allocation %s", addr, alloc_net
        )
        raise ValueError(f"Allocated IP {addr} is outside allocation CIDR {alloc_net}")
    if addr.version != alloc_net.version:
        raise ValueError("Allocated IP version does not match allocation CIDR")

    cidrs: list[str] = [f"{addr}/{alloc_net.prefixlen}"]
    seen_prefix = {alloc_net.prefixlen}

    for raw in effective_cert_subnets(cert_subnets):
        net = ipaddress.ip_network(raw, strict=False)
        if net.version != addr.version:
            logger.warning(
                "host_cert_ip_cidrs: skip cert_subnet %s (version mismatch with %s)",
                net,
                addr,
            )
            continue
        if addr not in net:
            logger.warning(
                "host_cert_ip_cidrs: allocated %s not inside cert_subnet %s; "
                "not embedding this claim on the host cert",
                addr,
                net,
            )
            continue
        if net.prefixlen in seen_prefix:
            continue
        seen_prefix.add(net.prefixlen)
        cidrs.append(f"{addr}/{net.prefixlen}")

    logger.info(
        "host_cert_ip_cidrs allocated=%s allocation=%s cert_subnets=%s -> %s",
        addr,
        alloc_net,
        list(effective_cert_subnets(cert_subnets)),
        cidrs,
    )
    return cidrs
