"""Unit tests for IPv4/IPv6-safe IP allocation."""
from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from backend.models import AllocatedIP, Base, Network
from backend.services.ip_allocator import IPAllocator, canonical_ip, iter_assignable_hosts
import ipaddress


@pytest_asyncio.fixture
async def session(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'alloc.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions() as s:
        s.add(Network(name="v4", subnet_cidr="10.100.0.0/30"))
        s.add(Network(name="v6", subnet_cidr="fd00:1::/64"))
        s.add(Network(name="v6small", subnet_cidr="fd00:2::/96"))
        await s.commit()
        yield s
    await engine.dispose()


@pytest.mark.asyncio
async def test_ipv4_sequential_skips_network_and_broadcast(session):
    alloc = IPAllocator(session)
    a = await alloc.allocate(1, "10.100.0.0/30")
    b = await alloc.allocate(1, "10.100.0.0/30")
    assert a == "10.100.0.1"
    assert b == "10.100.0.2"
    with pytest.raises(ValueError, match="No free IP"):
        await alloc.allocate(1, "10.100.0.0/30")


@pytest.mark.asyncio
async def test_ipv6_first_hosts_from_slash64_without_listing_all(session):
    alloc = IPAllocator(session)
    a = await alloc.allocate(2, "fd00:1::/64")
    b = await alloc.allocate(2, "fd00:1::/64")
    assert a == "fd00:1::1"
    assert b == "fd00:1::2"
    assert await alloc.is_allocated(2, "fd00:1::1")
    assert await alloc.is_allocated(2, "FD00:1::0001")


@pytest.mark.asyncio
async def test_ipv6_suggested_and_canonical(session):
    alloc = IPAllocator(session)
    got = await alloc.allocate(2, "fd00:1::/64", suggested_ip="FD00:1::00A0")
    assert got == "fd00:1::a0"
    # Already used (different string form) falls through to next free
    got2 = await alloc.allocate(2, "fd00:1::/64", suggested_ip="fd00:1::a0")
    assert got2 == "fd00:1::1"


@pytest.mark.asyncio
async def test_ipv6_refuses_tighter_than_slash96(session):
    alloc = IPAllocator(session)
    with pytest.raises(ValueError, match="/96"):
        await alloc.allocate(3, "fd00:2::/112")


@pytest.mark.asyncio
async def test_ipv6_slash96_allocates_first_hosts(session):
    alloc = IPAllocator(session)
    a = await alloc.allocate(3, "fd00:2::/96")
    b = await alloc.allocate(3, "fd00:2::/96")
    assert a == "fd00:2::1"
    assert b == "fd00:2::2"


@pytest.mark.asyncio
async def test_quarantine_and_reclaim(session):
    alloc = IPAllocator(session)
    ip = await alloc.allocate(2, "fd00:1::/64", node_id=42)
    until = datetime.utcnow() + timedelta(days=1)
    await alloc.release(2, ip, quarantine_until=until, node_id=42)
    assert await alloc.is_quarantined(2, ip)
    # Other node cannot take it
    other = await alloc.allocate(2, "fd00:1::/64", suggested_ip=ip, node_id=99)
    assert other != canonical_ip(ip)
    # Same node reclaims
    again = await alloc.allocate(2, "fd00:1::/64", node_id=42)
    assert again == canonical_ip(ip)


@pytest.mark.asyncio
async def test_iter_assignable_hosts_is_lazy_for_large_v6():
    net = ipaddress.ip_network("fd00::/8")
    gen = iter_assignable_hosts(net)
    first = next(gen)
    second = next(gen)
    assert first == ipaddress.ip_address("fd00::1")
    assert second == ipaddress.ip_address("fd00::2")
    # Must not have tried to list 2^120 hosts
