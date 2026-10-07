"""dnsmasq config must emit correct AAAA host-records for IPv6 overlays."""
from backend.api.dns import _build_dnsmasq_config, _dnsmasq_host_record
from backend.models import Node


def test_host_record_ipv6_leaves_ipv4_slot_empty():
    assert _dnsmasq_host_record("a.example", "fd00:1::2") == "host-record=a.example,,fd00:1::2"
    assert _dnsmasq_host_record("a.example", "10.1.2.3") == "host-record=a.example,10.1.2.3"


def test_build_dnsmasq_config_ipv6_nodes():
    nodes = [
        Node(id=1, network_id=1, hostname="lh", ip_address="fd00:1::1"),
        Node(id=2, network_id=1, hostname="app", ip_address="fd00:1::2"),
    ]
    body = _build_dnsmasq_config("mesh.internal", nodes, aliases=[], listen_ip="fd00:1::1")
    assert "listen-address=fd00:1::1" in body
    assert "host-record=lh.mesh.internal,,fd00:1::1" in body
    assert "host-record=app.mesh.internal,,fd00:1::2" in body
    assert "address=/mesh.internal/fd00:1::1" in body
