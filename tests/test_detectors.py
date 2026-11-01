"""
Unit and scenario tests for NetSleuth detectors.
"""

import pytest
from core.models import PacketRecord
from core.flow_tracker import build_flows
from core.host_profiler import build_host_profiles
from detectors.tcp_faults import TCPFaultDetector
from detectors.dns_faults import DNSFaultDetector
from detectors.arp_analysis import ARPAnalysisDetector
from detectors.port_scan import PortScanDetector
from detectors.dhcp_analysis import DHCPAnalysisDetector
from detectors.mtu_icmp import MTUICMPDetector


def test_tcp_reset_burst_detector():
    pkts = []
    for i in range(5):
        pkts.append(PacketRecord(
            packet_number=i + 1, timestamp=100.0 + (i * 0.1), timestamp_iso="", captured_length=64, reported_length=64,
            highest_layer="TCP", protocol_stack=("TCP",), src_ip="192.168.1.10", dst_ip="192.168.1.50",
            src_port=80, dst_port=40000 + i, transport_protocol="TCP", tcp_flags={"RST": True, "ACK": True}
        ))

    flows = build_flows(pkts)
    hosts = build_host_profiles(pkts, flows)
    detector = TCPFaultDetector()
    findings = detector.analyze(pkts, flows, hosts)

    reset_findings = [f for f in findings if f.type == "TCP_RESET"]
    assert len(reset_findings) == 1
    f = reset_findings[0]
    assert f.source_ip == "192.168.1.10"
    assert f.metrics["rst_count"] == 5
    assert f.metrics["is_burst"] is True
    assert f.classification == "OBSERVATION"


def test_dns_failure_detector():
    q = PacketRecord(
        packet_number=1, timestamp=100.0, timestamp_iso="", captured_length=64, reported_length=64,
        highest_layer="DNS", protocol_stack=("DNS",), src_ip="10.0.0.5", dst_ip="8.8.8.8",
        src_port=53123, dst_port=53, transport_protocol="UDP", dns_id=0x1234, dns_is_response=False,
        dns_query_name="bad-domain.invalid", dns_query_type="A"
    )
    r = PacketRecord(
        packet_number=2, timestamp=100.05, timestamp_iso="", captured_length=64, reported_length=64,
        highest_layer="DNS", protocol_stack=("DNS",), src_ip="8.8.8.8", dst_ip="10.0.0.5",
        src_port=53, dst_port=53123, transport_protocol="UDP", dns_id=0x1234, dns_is_response=True,
        dns_query_name="bad-domain.invalid", dns_query_type="A", dns_response_code=3  # NXDOMAIN
    )

    flows = build_flows([q, r])
    hosts = build_host_profiles([q, r], flows)
    detector = DNSFaultDetector()
    findings = detector.analyze([q, r], flows, hosts)

    assert len(findings) == 1
    f = findings[0]
    assert f.type == "DNS_FAILURE"
    assert "NXDOMAIN" in f.title
    assert f.evidence_packets == [1, 2]


def test_arp_conflict_detector():
    # Two distinct MACs claiming 192.168.1.1
    p1 = PacketRecord(
        packet_number=1, timestamp=100.0, timestamp_iso="", captured_length=42, reported_length=42,
        highest_layer="ARP", protocol_stack=("ARP",), transport_protocol="ARP",
        arp_operation="REPLY", arp_sender_ip="192.168.1.1", arp_sender_mac="00:11:22:33:44:01"
    )
    p2 = PacketRecord(
        packet_number=2, timestamp=100.5, timestamp_iso="", captured_length=42, reported_length=42,
        highest_layer="ARP", protocol_stack=("ARP",), transport_protocol="ARP",
        arp_operation="REPLY", arp_sender_ip="192.168.1.1", arp_sender_mac="00:aa:bb:cc:dd:99"
    )

    flows = build_flows([p1, p2])
    hosts = build_host_profiles([p1, p2], flows)
    detector = ARPAnalysisDetector()
    findings = detector.analyze([p1, p2], flows, hosts)

    assert len(findings) == 1
    f = findings[0]
    assert f.type == "ARP_CONFLICT"
    assert f.source_ip == "192.168.1.1"
    assert "00:11:22:33:44:01" in f.metrics["competing_macs"]
    assert "00:aa:bb:cc:dd:99" in f.metrics["competing_macs"]
    assert f.evidence_packets == [1, 2]


def test_port_scan_detector_vertical():
    pkts = []
    for port in range(20, 38):  # 18 ports >= 15 threshold
        pkts.append(PacketRecord(
            packet_number=len(pkts) + 1, timestamp=100.0 + (port * 0.05), timestamp_iso="", captured_length=64,
            reported_length=64, highest_layer="TCP", protocol_stack=("TCP",), src_ip="10.200.1.5",
            dst_ip="10.200.1.99", src_port=50000, dst_port=port, transport_protocol="TCP",
            tcp_flags={"SYN": True, "ACK": False}
        ))

    flows = build_flows(pkts)
    hosts = build_host_profiles(pkts, flows)
    detector = PortScanDetector()
    findings = detector.analyze(pkts, flows, hosts)

    scan_findings = [f for f in findings if f.type == "PORT_SCAN"]
    assert len(scan_findings) == 1
    f = scan_findings[0]
    assert f.source_ip == "10.200.1.5"
    assert f.destination_ip == "10.200.1.99"
    assert f.metrics["distinct_ports_contacted"] == 18
    assert f.classification == "SUSPICIOUS_ACTIVITY"


def test_dhcp_multi_server_detector():
    p1 = PacketRecord(
        packet_number=1, timestamp=100.0, timestamp_iso="", captured_length=300, reported_length=300,
        highest_layer="BOOTP", protocol_stack=("DHCP",), src_ip="192.168.1.1", dst_ip="192.168.1.100",
        src_port=67, dst_port=68, transport_protocol="UDP", dhcp_message_type="offer", dhcp_server_id="192.168.1.1"
    )
    p2 = PacketRecord(
        packet_number=2, timestamp=100.1, timestamp_iso="", captured_length=300, reported_length=300,
        highest_layer="BOOTP", protocol_stack=("DHCP",), src_ip="192.168.1.254", dst_ip="192.168.1.100",
        src_port=67, dst_port=68, transport_protocol="UDP", dhcp_message_type="offer", dhcp_server_id="192.168.1.254"
    )

    flows = build_flows([p1, p2])
    hosts = build_host_profiles([p1, p2], flows)
    detector = DHCPAnalysisDetector()
    findings = detector.analyze([p1, p2], flows, hosts)

    assert len(findings) == 1
    f = findings[0]
    assert f.type == "MULTIPLE_DHCP_SERVERS"
    assert "192.168.1.1" in f.metrics["distinct_dhcp_servers"]
    assert "192.168.1.254" in f.metrics["distinct_dhcp_servers"]


def test_port_scan_detector_horizontal():
    pkts = []
    # Probe port 445 on 10 distinct targets (>= 8 threshold)
    for host_id in range(1, 11):
        pkts.append(PacketRecord(
            packet_number=len(pkts) + 1, timestamp=100.0 + (host_id * 0.1), timestamp_iso="",
            captured_length=64, reported_length=64, highest_layer="TCP", protocol_stack=("TCP",),
            src_ip="192.168.1.50", dst_ip=f"192.168.1.{100 + host_id}", src_port=52000, dst_port=445,
            transport_protocol="TCP", tcp_flags={"SYN": True, "ACK": False}
        ))

    flows = build_flows(pkts)
    hosts = build_host_profiles(pkts, flows)
    detector = PortScanDetector()
    findings = detector.analyze(pkts, flows, hosts)

    sweep_findings = [f for f in findings if f.type == "PORT_SWEEP"]
    assert len(sweep_findings) == 1
    f = sweep_findings[0]
    assert f.source_ip == "192.168.1.50"
    assert f.destination_port == 445
    assert f.metrics["distinct_hosts_probed"] == 10
    assert f.classification == "SUSPICIOUS_ACTIVITY"


def test_mtu_icmp_detector():
    p = PacketRecord(
        packet_number=1, timestamp=100.0, timestamp_iso="", captured_length=70, reported_length=70,
        highest_layer="ICMP", protocol_stack=("ICMP",), src_ip="10.0.0.1", dst_ip="192.168.1.50",
        transport_protocol="ICMP", icmp_type=3, icmp_code=4, icmp_mtu=1420
    )

    flows = build_flows([p])
    hosts = build_host_profiles([p], flows)
    detector = MTUICMPDetector()
    findings = detector.analyze([p], flows, hosts)

    assert len(findings) == 1
    f = findings[0]
    assert f.type == "MTU_FRAGMENTATION_NEEDED"
    assert f.metrics["advertised_next_hop_mtu"] == 1420
    assert f.evidence_packets == [1]


def test_incomplete_handshake_detector():
    # SYN packet with no response
    p = PacketRecord(
        packet_number=1, timestamp=100.0, timestamp_iso="", captured_length=64, reported_length=64,
        highest_layer="TCP", protocol_stack=("TCP",), src_ip="10.10.10.5", dst_ip="10.10.10.80",
        src_port=45000, dst_port=80, transport_protocol="TCP", tcp_flags={"SYN": True, "ACK": False}
    )

    flows = build_flows([p])
    hosts = build_host_profiles([p], flows)
    detector = TCPFaultDetector()
    findings = detector.analyze([p], flows, hosts)

    syn_findings = [f for f in findings if f.type == "INCOMPLETE_HANDSHAKE"]
    assert len(syn_findings) == 1
    f = syn_findings[0]
    assert f.source_ip == "10.10.10.5"
    assert f.destination_port == 80
    assert f.evidence_packets == [1]


def test_tcp_retransmission_detector():
    pkts = []
    # 4 packets in same flow with repeated sequence 1000 and payload 100
    for i in range(4):
        pkts.append(PacketRecord(
            packet_number=i + 1, timestamp=100.0 + (i * 0.2), timestamp_iso="",
            captured_length=154, reported_length=154, highest_layer="TCP", protocol_stack=("TCP",),
            src_ip="10.0.0.5", dst_ip="10.0.0.1", src_port=50001, dst_port=443,
            transport_protocol="TCP", tcp_flags={"ACK": True}, tcp_seq=1000, tcp_payload_length=100
        ))

    flows = build_flows(pkts)
    hosts = build_host_profiles(pkts, flows)
    detector = TCPFaultDetector()
    findings = detector.analyze(pkts, flows, hosts)

    retx_findings = [f for f in findings if f.type == "TCP_RETRANSMISSION"]
    assert len(retx_findings) == 1
    f = retx_findings[0]
    assert f.metrics["retransmission_events"] >= 3
    assert len(f.evidence_packets) >= 3
