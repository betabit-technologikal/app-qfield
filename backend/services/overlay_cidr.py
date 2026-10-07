"""Overlay allocation CIDR validation (IPv6-first)."""
from __future__ import annotations

import ipaddress
import logging
import secrets
from typing import Union

logger = logging.getLogger(__name__)

IpNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# Product floor for IPv6 allocation prefixes. Narrower than /96 is rejected so the
# allocator and cert paths stay simple (no /127-/128 edge cases in the overlay).
IPV6_ALLOCATION_MIN_PREFIX = 8   # fd00::/8 ULA ceiling is allowed as allocation (wide)
IPV6_ALLOCATION_MAX_PREFIX = 96  # tightest allowed overlay allocation


def validate_allocation_cidr(cidr: str) -> str:
    """
    Parse and validate a network allocation CIDR.

    Returns the canonical network string (e.g. 'fd00:1::/64').
    Raises ValueError with a user-facing message on failure.

    IPv6 is the supported overlay family. Prefix length must be between /8 and /96
    inclusive (nothing tighter than /96). IPv4 CIDRs are still accepted so existing
    tests keep working, but are not a product surface.
    """
    raw = (cidr or "").strip()
    if not raw:
        logger.error("allocation CIDR validation failed: empty value")
        raise ValueError("Subnet CIDR is required")
    try:
        net: IpNetwork = ipaddress.ip_network(raw, strict=False)
    except ValueError as e:
        logger.error("allocation CIDR validation failed: cannot parse %r: %s", raw, e)
        raise ValueError(f"Invalid subnet CIDR: {e}") from e

    if net.is_multicast:
        logger.error("allocation CIDR rejected (multicast): %s", net)
        raise ValueError("Subnet CIDR must not be a multicast range")
    if net.is_loopback:
        logger.error("allocation CIDR rejected (loopback): %s", net)
        raise ValueError("Subnet CIDR must not be a loopback range")
    if net.is_unspecified:
        logger.error("allocation CIDR rejected (unspecified): %s", net)
        raise ValueError("Subnet CIDR must not be the unspecified range")
    if net.is_link_local:
        logger.error("allocation CIDR rejected (link-local): %s", net)
        raise ValueError("Subnet CIDR must not be link-local")

    if net.version == 6:
        if net.prefixlen < IPV6_ALLOCATION_MIN_PREFIX:
            logger.error(
                "allocation CIDR rejected (IPv6 prefix /%s wider than /%s): %s",
                net.prefixlen,
                IPV6_ALLOCATION_MIN_PREFIX,
                net,
            )
            raise ValueError(
                f"IPv6 allocation CIDR must be /{IPV6_ALLOCATION_MIN_PREFIX} or tighter "
                f"(got /{net.prefixlen})"
            )
        if net.prefixlen > IPV6_ALLOCATION_MAX_PREFIX:
            logger.error(
                "allocation CIDR rejected (IPv6 prefix /%s tighter than /%s floor): %s",
                net.prefixlen,
                IPV6_ALLOCATION_MAX_PREFIX,
                net,
            )
            raise ValueError(
                f"IPv6 allocation CIDR must be /{IPV6_ALLOCATION_MAX_PREFIX} or larger "
                f"(got /{net.prefixlen}; minimum size is /{IPV6_ALLOCATION_MAX_PREFIX})"
            )
    elif net.version == 4:
        if net.prefixlen == 32:
            logger.error("allocation CIDR rejected (IPv4 /32 too small): %s", net)
            raise ValueError("Allocation CIDR is too small (need more than one host address)")
        logger.warning(
            "allocation CIDR is IPv4 (%s); product target is IPv6-only overlay",
            net,
        )
    else:
        logger.error("allocation CIDR rejected (unknown IP version): %s", net)
        raise ValueError("Subnet CIDR must be IPv4 or IPv6")

    canonical = str(net)
    logger.info(
        "allocation CIDR accepted: input=%r canonical=%s version=%s prefixlen=%s",
        raw,
        canonical,
        net.version,
        net.prefixlen,
    )
    return canonical


def default_ipv6_allocation_cidr() -> str:
    """Random ULA /64 for opinionated network create defaults (fdXX:...::/64)."""
    # RFC 4193-ish: fd + 40 random bits as /48 global id, then 16-bit subnet -> /64
    global_id = secrets.token_bytes(5)  # 40 bits
    subnet_id = secrets.token_bytes(2)  # 16 bits
    b = bytes([0xFD]) + global_id + subnet_id + bytes(8)
    addr = ipaddress.IPv6Address(b)
    cidr = str(ipaddress.IPv6Network((addr, 64)))
    logger.debug("generated default IPv6 allocation CIDR: %s", cidr)
    return cidr
