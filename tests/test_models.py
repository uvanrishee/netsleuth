"""
Unit tests for core models and data contracts.
"""

import pytest
from core.models import PacketRecord, FlowRecord, Finding, TimelineEvent, IncidentRecord


def test_packet_record_creation_with_defaults():
    pkt = PacketRecord(
        packet_number=1,
        timestamp=1700000000.0,
        timestamp_iso="2023-11-14T22:13:20+00:00",
        captured_length=64,
        reported_length=64,
        highest_layer="TCP",
        protocol_stack=("ETH", "IP", "TCP"),
        src_ip="192.168.1.5",
        dst_ip="192.168.1.1",
        src_port=49152,
        dst_port=80,
        transport_protocol="TCP",
        tcp_flags={"SYN": True, "ACK": False}
    )

    assert pkt.packet_number == 1
    assert pkt.src_ip == "192.168.1.5"
    assert pkt.dst_port == 80
    assert pkt.tcp_flags["SYN"] is True
    assert pkt.dns_query_name is None  # Defaults to None
    assert pkt.parse_warnings == ()


def test_finding_record_structure():
    finding = Finding(
        finding_id="F-TEST-001",
        category="NETWORK_FAULT",
        type="TCP_RESET",
        title="Test TCP Reset",
        classification="OBSERVATION",
        severity="LOW",
        confidence=0.85,
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        source_port=1234,
        destination_port=80,
        affected_hosts=["10.0.0.1", "10.0.0.2"],
        flow_ids=["TCP:10.0.0.1:1234<->10.0.0.2:80"],
        start_time=1700000000.0,
        end_time=1700000005.0,
        metrics={"reset_count": 1},
        evidence_packets=[10, 12],
        reason="Test condition met",
        likely_cause="Test likely cause",
        alternative_explanations=["Alternative 1"],
        recommendation="Verify service",
        limitations=["Test limitation"]
    )

    assert finding.finding_id == "F-TEST-001"
    assert finding.severity == "LOW"
    assert finding.confidence == 0.85
    assert len(finding.evidence_packets) == 2
