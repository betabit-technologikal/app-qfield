"""
IP allocation for Nebula networks. CIDR-based allocation with persistence.

Supports IPv4 and IPv6 allocation CIDRs. Never materializes the full host set
(critical for IPv6 /64 and larger prefixes).
"""
import ipaddress
import logging
from datetime import datetime
from typing import Iterator, Optional, Union

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import AllocatedIP, Network

logger = logging.getLogger(__name__)

IpNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IpAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


def canonical_ip(ip: str) -> str:
    """Normalize an IP string (compress IPv6, strip junk) for storage and comparison."""
    return str(ipaddress.ip_address(ip.strip()))


def _parse_network(subnet_cidr: str) -> IpNetwork:
    return ipaddress.ip_network(subnet_cidr.strip(), strict=False)


def _is_assignable(net: IpNetwork, ip: IpAddress) -> bool:
    """True if ip may be given to a host in net (same rules as ipaddress.hosts())."""
    if ip not in net:
        return False
    # Match ipaddress.hosts() without materializing the full set:
    # - IPv4: exclude network and broadcast (except /31 and /32 special cases).
    # - IPv6: exclude only the network address (last / subnet-router anycast is included).
    n = int(ip)
    network = int(net.network_address)
    broadcast = int(net.broadcast_address)
    if net.version == 4:
        if net.num_addresses <= 2:
            return any(ip == h for h in net.hosts())
        return network < n < broadcast
    if net.prefixlen >= 127:
        # /127 and /128: hosts() yields every address in the net
        return any(ip == h for h in net.hosts())
    return network < n <= broadcast


def iter_assignable_hosts(net: IpNetwork) -> Iterator[IpAddress]:
    """Assignable host addresses without building a list (IPv6-safe)."""
    yield from net.hosts()


class IPAllocator:
    """Allocate IPs from a network subnet, avoiding already-allocated IPs."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def _expire_quarantines(self, network_id: int) -> None:
        """Free addresses whose quarantine is over: the old certificate claiming them has
        expired, so nothing else can present that IP any more."""
        await self.session.execute(
            delete(AllocatedIP).where(
                AllocatedIP.network_id == network_id,
                AllocatedIP.quarantined_until.is_not(None),
                AllocatedIP.quarantined_until <= datetime.utcnow(),
            )
        )

    async def _used_ips(self, network_id: int) -> set[IpAddress]:
        """Canonical set of addresses already allocated or quarantined in this network."""
        result = await self.session.execute(
            select(AllocatedIP.ip_address).where(AllocatedIP.network_id == network_id)
        )
        used: set[IpAddress] = set()
        for (addr,) in result.fetchall():
            if not addr:
                continue
            try:
                used.add(ipaddress.ip_address(addr.strip()))
            except ValueError:
                logger.warning(
                    "Ignoring unparseable allocated IP %r in network %s", addr, network_id
                )
        return used

    async def allocate(
        self,
        network_id: int,
        subnet_cidr: str,
        suggested_ip: Optional[str] = None,
        node_id: Optional[int] = None,
    ) -> str:
        """
        Allocate an IP from the subnet. If suggested_ip is valid and free, use it.
        Otherwise pick the next available host IP.

        Quarantined addresses (released by revoke/delete/re-enroll while the old
        certificate is still valid) are never given to another node. node_id may
        reclaim its OWN quarantined address - its old certificate is blocklisted, so
        there's no conflict - and does so first, so a re-enrolled node keeps its IP.
        """
        await self._expire_quarantines(network_id)
        logger.debug(
            "allocate start network_id=%s subnet=%s suggested=%r node_id=%s",
            network_id,
            subnet_cidr,
            suggested_ip,
            node_id,
        )
        if node_id is not None:
            own = await self.session.scalar(
                select(AllocatedIP).where(
                    AllocatedIP.network_id == network_id,
                    AllocatedIP.node_id == node_id,
                    AllocatedIP.quarantined_until.is_not(None),
                )
            )
            if own is not None and (
                not suggested_ip
                or canonical_ip(suggested_ip) == canonical_ip(own.ip_address)
            ):
                own.quarantined_until = None
                try:
                    own.ip_address = canonical_ip(own.ip_address)
                except ValueError:
                    pass
                await self.session.flush()
                logger.info(
                    "allocate reclaim quarantined IP network_id=%s node_id=%s ip=%s",
                    network_id,
                    node_id,
                    own.ip_address,
                )
                return own.ip_address

        try:
            net = _parse_network(subnet_cidr)
        except ValueError as e:
            logger.error(
                "allocate failed: invalid subnet_cidr=%r network_id=%s: %s",
                subnet_cidr,
                network_id,
                e,
            )
            raise

        if net.version == 6 and net.prefixlen > 96:
            # Defense in depth if a caller bypasses API validation
            logger.error(
                "allocate refused IPv6 prefix tighter than /96: network_id=%s subnet=%s",
                network_id,
                net,
            )
            raise ValueError(
                f"IPv6 allocation CIDR must be /96 or larger (got /{net.prefixlen})"
            )

        used = await self._used_ips(network_id)
        logger.debug(
            "allocate pool network_id=%s version=%s prefixlen=%s used_count=%s",
            network_id,
            net.version,
            net.prefixlen,
            len(used),
        )

        if suggested_ip:
            try:
                ip = ipaddress.ip_address(suggested_ip.strip())
                if _is_assignable(net, ip) and ip not in used:
                    addr = str(ip)
                    alloc = AllocatedIP(
                        network_id=network_id,
                        ip_address=addr,
                        node_id=node_id,
                    )
                    self.session.add(alloc)
                    await self.session.flush()
                    logger.info(
                        "allocate suggested IP network_id=%s node_id=%s ip=%s",
                        network_id,
                        node_id,
                        addr,
                    )
                    return addr
                logger.warning(
                    "allocate suggested IP unavailable network_id=%s suggested=%r "
                    "assignable=%s already_used=%s; falling back to auto",
                    network_id,
                    suggested_ip,
                    _is_assignable(net, ip) if ip in net else False,
                    ip in used,
                )
                # Fall through to auto-allocate
            except ValueError as e:
                logger.warning(
                    "allocate suggested IP unparseable network_id=%s suggested=%r: %s",
                    network_id,
                    suggested_ip,
                    e,
                )

        for ip in iter_assignable_hosts(net):
            if ip not in used:
                addr = str(ip)
                alloc = AllocatedIP(
                    network_id=network_id,
                    ip_address=addr,
                    node_id=node_id,
                )
                self.session.add(alloc)
                await self.session.flush()
                logger.info(
                    "allocate auto IP network_id=%s node_id=%s ip=%s used_before=%s",
                    network_id,
                    node_id,
                    addr,
                    len(used),
                )
                return addr

        quarantined = await self.session.scalar(
            select(AllocatedIP.id)
            .where(
                AllocatedIP.network_id == network_id,
                AllocatedIP.quarantined_until.is_not(None),
            )
            .limit(1)
        )
        if quarantined is not None:
            logger.error(
                "allocate exhausted (quarantine holds) network_id=%s subnet=%s used=%s",
                network_id,
                subnet_cidr,
                len(used),
            )
            raise ValueError(
                f"No free IP in subnet {subnet_cidr} (some addresses are held until the "
                "certificates of revoked or deleted nodes expire)"
            )
        logger.error(
            "allocate exhausted network_id=%s subnet=%s used=%s",
            network_id,
            subnet_cidr,
            len(used),
        )
        raise ValueError(f"No free IP in subnet {subnet_cidr}")

    async def release(
        self,
        network_id: int,
        ip_address: str,
        quarantine_until: Optional[datetime] = None,
        node_id: Optional[int] = None,
    ) -> None:
        """Release an allocated IP.

        With quarantine_until (the expiry of the certificate that still claims this IP),
        the address is held instead of freed: only node_id may reclaim it before then.
        Pass node_id=None for a deleted node so nobody can.
        """
        try:
            canon = canonical_ip(ip_address)
        except ValueError:
            canon = ip_address.strip()

        result = await self.session.execute(
            select(AllocatedIP).where(
                AllocatedIP.network_id == network_id,
                AllocatedIP.ip_address == canon,
            )
        )
        row = result.scalar_one_or_none()
        if row is None and canon != ip_address.strip():
            # Legacy row may have a non-canonical string form
            result = await self.session.execute(
                select(AllocatedIP).where(
                    AllocatedIP.network_id == network_id,
                    AllocatedIP.ip_address == ip_address.strip(),
                )
            )
            row = result.scalar_one_or_none()
        if row is None:
            if quarantine_until is None or quarantine_until <= datetime.utcnow():
                return
            row = AllocatedIP(network_id=network_id, ip_address=canon)
            self.session.add(row)
        if quarantine_until is not None and quarantine_until > datetime.utcnow():
            row.quarantined_until = quarantine_until
            row.node_id = node_id
            row.ip_address = canon
        else:
            await self.session.delete(row)
        await self.session.flush()

    async def is_quarantined(self, network_id: int, ip_address: str) -> bool:
        """True if the IP is held because a revoked/deleted node's certificate for it
        hasn't expired yet."""
        await self._expire_quarantines(network_id)
        try:
            target = ipaddress.ip_address(ip_address.strip())
        except ValueError:
            return False
        result = await self.session.execute(
            select(AllocatedIP.ip_address).where(
                AllocatedIP.network_id == network_id,
                AllocatedIP.quarantined_until.is_not(None),
            )
        )
        for (addr,) in result.fetchall():
            try:
                if ipaddress.ip_address(addr.strip()) == target:
                    return True
            except ValueError:
                continue
        return False

    async def is_allocated(self, network_id: int, ip_address: str) -> bool:
        """Return True if the IP is already allocated (or still quarantined) in this network."""
        await self._expire_quarantines(network_id)
        try:
            target = ipaddress.ip_address(ip_address.strip())
        except ValueError:
            return False
        used = await self._used_ips(network_id)
        return target in used
