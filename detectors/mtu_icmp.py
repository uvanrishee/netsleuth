"""
MTU and ICMP Clues Detector.
Identifies Path MTU Discovery issues, ICMP Fragmentation Needed messages, and next-hop MTU constraints.
"""

from __future__ import annotations

import logging
from typing import Mapping, Sequence

from core.config import AppConfig, DEFAULT_CONFIG
from core.models import Finding, FlowRecord, HostProfile, PacketRecord
from detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class MTUICMPDetector(BaseDetector):
    """
    Detects ICMP Type 3 Code 4 (Fragmentation Needed), advertised next-hop MTUs, and IP fragmentation clues.
    """

    @property
    def detector_name(self) -> str:
        return "MTU & ICMP Clues Detector"

    def analyze(
        self,
        packets: Sequence[PacketRecord],
        flows: Mapping[str, FlowRecord],
        hosts: Mapping[str, HostProfile]
    ) -> list[Finding]:
        findings: list[Finding] = []

        frag_needed_packets: list[PacketRecord] = []
        fragmented_packets: list[PacketRecord] = []

        for pkt in packets:
            # ICMP Fragmentation Needed (Type 3 Code 4)
            if pkt.transport_protocol == "ICMP" and pkt.icmp_type == 3 and pkt.icmp_code == 4:
                frag_needed_packets.append(pkt)

            # IP fragmentation observations
            if pkt.more_fragments or (pkt.fragment_offset and pkt.fragment_offset > 0):
                fragmented_packets.append(pkt)

        finding_counter = 1

        # 1. ICMP Fragmentation Needed
        if frag_needed_packets:
            evidence = [p.packet_number for p in frag_needed_packets]
            next_hop_mtus = [p.icmp_mtu for p in frag_needed_packets if p.icmp_mtu]
            advertised_mtu = next_hop_mtus[0] if next_hop_mtus else "Unknown"

            gateway_ip = frag_needed_packets[0].src_ip
            sender_ip = frag_needed_packets[0].dst_ip

            f_id = f"F-MTU-ICMP-{finding_counter:03d}"
            finding_counter += 1

            findings.append(Finding(
                finding_id=f_id,
                category="NETWORK_FAULT",
                type="MTU_FRAGMENTATION_NEEDED",
                title=f"Path MTU Bottleneck (Next-Hop MTU: {advertised_mtu} bytes)",
                classification="OBSERVATION",
                severity="MEDIUM",
                confidence=0.95,
                source_ip=gateway_ip,
                destination_ip=sender_ip,
                source_port=None,
                destination_port=None,
                affected_hosts=[h for h in (gateway_ip, sender_ip) if h],
                flow_ids=[],
                start_time=frag_needed_packets[0].timestamp,
                end_time=frag_needed_packets[-1].timestamp,
                metrics={
                    "advertised_next_hop_mtu": advertised_mtu,
                    "icmp_messages_count": len(frag_needed_packets)
                },
                evidence_packets=evidence[:10],
                reason=f"Intermediate router {gateway_ip} sent ICMP Destination Unreachable (Fragmentation Needed) to {sender_ip} indicating MTU bottleneck.",
                likely_cause="Packet size exceeded the Maximum Transmission Unit (MTU) of an intermediate link (e.g., VPN tunnel, PPPoE encapsulation) with DF bit set.",
                alternative_explanations=[
                    "Path MTU Discovery (PMTUD) functioning normally to negotiate optimal TCP MSS",
                    "Misconfigured router interface MTU or firewall blocking PMTUD responses (PMTU black hole)"
                ],
                recommendation=f"Review MTU configurations across network paths, ensure ICMP Type 3 Code 4 is not blocked by firewalls, and consider TCP MSS clamping at {advertised_mtu if isinstance(advertised_mtu, int) else 1400} bytes.",
                limitations=[
                    "PCAP confirms reception of ICMP fragmentation messages; it does not confirm whether endpoints successfully adjusted their MSS."
                ]
            ))

        # 2. General IP Fragmentation
        if len(fragmented_packets) >= 5:
            evidence = [p.packet_number for p in fragmented_packets]
            f_id = f"F-MTU-FRAG-{finding_counter:03d}"
            finding_counter += 1

            findings.append(Finding(
                finding_id=f_id,
                category="NETWORK_FAULT",
                type="IP_FRAGMENTATION_OBSERVED",
                title=f"Frequent IP Fragmentation Observed ({len(fragmented_packets)} fragmented packets)",
                classification="OBSERVATION",
                severity="LOW",
                confidence=0.9,
                source_ip=fragmented_packets[0].src_ip,
                destination_ip=fragmented_packets[0].dst_ip,
                source_port=None,
                destination_port=None,
                affected_hosts=list({p.src_ip for p in fragmented_packets if p.src_ip}),
                flow_ids=[],
                start_time=fragmented_packets[0].timestamp,
                end_time=fragmented_packets[-1].timestamp,
                metrics={
                    "fragmented_packet_count": len(fragmented_packets)
                },
                evidence_packets=evidence[:10],
                reason=f"Observed {len(fragmented_packets)} IP fragments in traffic, indicating transmitted segments exceed local MTU.",
                likely_cause="Application sending UDP or raw IP datagrams larger than the link MTU without Path MTU discovery.",
                alternative_explanations=[
                    "Normal behavior for protocols requiring large payloads over UDP (e.g. NFS over UDP, large DNS responses)",
                    "IP fragmentation attack simulation or evasion technique (rare)"
                ],
                recommendation="Evaluate whether transmitting applications can migrate to TCP with PMTUD or reduce datagram payload sizes to prevent IP reassembly overhead.",
                limitations=[
                    "Fragmented IP packets are a normal feature of the IP protocol and not necessarily indicative of failure unless reassembly drops occur."
                ]
            ))

        return findings
