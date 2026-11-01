"""
End-to-end integration tests using real synthetic PCAP files and TShark.
Verifies the full pipeline: Parse -> Aggregate -> Detect -> Events -> Correlate.
"""

import os
import pytest
from analysis.pipeline import run_pipeline
from core.config import AppConfig


@pytest.mark.integration
def test_pipeline_normal_traffic():
    pcap_path = os.path.join("sample_pcaps", "normal_traffic.pcap")
    assert os.path.exists(pcap_path)

    res = run_pipeline(pcap_path)
    assert res.total_packets_read > 0
    assert len(res.packets) == res.total_packets_read
    assert len(res.flows) > 0
    assert len(res.hosts) >= 2


@pytest.mark.integration
def test_pipeline_tcp_reset_burst():
    pcap_path = os.path.join("sample_pcaps", "tcp_reset_burst.pcap")
    assert os.path.exists(pcap_path)

    res = run_pipeline(pcap_path)
    assert res.total_packets_read > 0
    # Must have detected TCP reset
    rst_findings = [f for f in res.findings if f.type == "TCP_RESET"]
    assert len(rst_findings) >= 1
    assert len(rst_findings[0].evidence_packets) > 0
    # Evidence packets must exist in res.packets
    all_pkt_nums = {p.packet_number for p in res.packets}
    for ep in rst_findings[0].evidence_packets:
        assert ep in all_pkt_nums


@pytest.mark.integration
def test_pipeline_dns_failures():
    pcap_path = os.path.join("sample_pcaps", "dns_failures.pcap")
    assert os.path.exists(pcap_path)

    res = run_pipeline(pcap_path)
    assert res.total_packets_read > 0
    dns_findings = [f for f in res.findings if "DNS" in f.type]
    assert len(dns_findings) >= 1


@pytest.mark.integration
def test_pipeline_port_scan():
    pcap_path = os.path.join("sample_pcaps", "port_scan_recon.pcap")
    assert os.path.exists(pcap_path)

    res = run_pipeline(pcap_path)
    assert res.total_packets_read > 0
    scan_findings = [f for f in res.findings if "PORT" in f.type or "SCAN" in f.type or "SWEEP" in f.type]
    assert len(scan_findings) >= 1
    # Check incidents
    assert len(res.incidents) >= 1


@pytest.mark.integration
def test_pipeline_arp_conflict():
    pcap_path = os.path.join("sample_pcaps", "arp_conflict.pcap")
    assert os.path.exists(pcap_path)

    res = run_pipeline(pcap_path)
    assert res.total_packets_read > 0
    arp_findings = [f for f in res.findings if f.type == "ARP_CONFLICT"]
    assert len(arp_findings) >= 1
    assert "192.168.1.1" in arp_findings[0].source_ip
    assert len(res.incidents) >= 1


@pytest.mark.integration
def test_pipeline_dhcp_multi_server():
    pcap_path = os.path.join("sample_pcaps", "dhcp_multi_server.pcap")
    assert os.path.exists(pcap_path)

    res = run_pipeline(pcap_path)
    assert res.total_packets_read > 0
    dhcp_findings = [f for f in res.findings if f.type == "MULTIPLE_DHCP_SERVERS"]
    assert len(dhcp_findings) >= 1
    assert len(res.incidents) >= 1


@pytest.mark.integration
def test_pipeline_incomplete_handshake():
    pcap_path = os.path.join("sample_pcaps", "incomplete_handshake.pcap")
    assert os.path.exists(pcap_path)

    res = run_pipeline(pcap_path)
    assert res.total_packets_read > 0
    handshake_findings = [f for f in res.findings if f.type == "INCOMPLETE_HANDSHAKE"]
    assert len(handshake_findings) >= 1


@pytest.mark.integration
def test_pipeline_tcp_retransmission():
    pcap_path = os.path.join("sample_pcaps", "tcp_retransmission.pcap")
    assert os.path.exists(pcap_path)

    res = run_pipeline(pcap_path)
    assert res.total_packets_read > 0
    retx_findings = [f for f in res.findings if f.type == "TCP_RETRANSMISSION"]
    assert len(retx_findings) >= 1
    assert len(retx_findings[0].evidence_packets) >= 3
