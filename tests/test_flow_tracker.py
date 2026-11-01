"""
Unit tests for bidirectional flow tracking.
"""

from core.flow_tracker import make_canonical_flow_key, build_flows
from core.models import PacketRecord


def test_make_canonical_flow_key():
    # Forward and reverse should produce identical key
    key1, ep_a1, ep_b1 = make_canonical_flow_key("TCP", "10.0.0.1", 50000, "10.0.0.2", 80)
    key2, ep_a2, ep_b2 = make_canonical_flow_key("TCP", "10.0.0.2", 80, "10.0.0.1", 50000)

    assert key1 == key2
    assert ep_a1 == ep_a2
    assert ep_b1 == ep_b2


def test_build_flows_bidirectional():
    p1 = PacketRecord(
        packet_number=1, timestamp=100.0, timestamp_iso="", captured_length=64, reported_length=64,
        highest_layer="TCP", protocol_stack=("TCP",), src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=50000, dst_port=80, transport_protocol="TCP", tcp_flags={"SYN": True, "ACK": False}
    )
    p2 = PacketRecord(
        packet_number=2, timestamp=100.1, timestamp_iso="", captured_length=64, reported_length=64,
        highest_layer="TCP", protocol_stack=("TCP",), src_ip="10.0.0.2", dst_ip="10.0.0.1",
        src_port=80, dst_port=50000, transport_protocol="TCP", tcp_flags={"SYN": True, "ACK": True}
    )
    p3 = PacketRecord(
        packet_number=3, timestamp=100.2, timestamp_iso="", captured_length=64, reported_length=64,
        highest_layer="TCP", protocol_stack=("TCP",), src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=50000, dst_port=80, transport_protocol="TCP", tcp_flags={"SYN": False, "ACK": True}
    )

    flows = build_flows([p1, p2, p3])
    assert len(flows) == 1
    flow = next(iter(flows.values()))
    assert flow.packet_count == 3
    assert flow.packets_a_to_b == 2
    assert flow.packets_b_to_a == 1
    assert flow.evidence_packets == [1, 2, 3]
    assert flow.state_summary == "ESTABLISHED"
