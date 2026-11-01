"""
TCP Fault Detectors:
1. TCP Retransmissions (sequence range overlap)
2. TCP Resets (direction, connection context, isolated vs burst)
3. Incomplete TCP Handshakes (unanswered SYN or missing final ACK)
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Mapping, Sequence

from core.config import AppConfig, DEFAULT_CONFIG
from core.models import Finding, FlowRecord, HostProfile, PacketRecord
from detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class TCPFaultDetector(BaseDetector):
    """
    Analyzes TCP conversations for sequence retransmissions, resets, and incomplete handshakes.
    """

    @property
    def detector_name(self) -> str:
        return "TCP Fault Detector"

    def analyze(
        self,
        packets: Sequence[PacketRecord],
        flows: Mapping[str, FlowRecord],
        hosts: Mapping[str, HostProfile]
    ) -> list[Finding]:
        findings: list[Finding] = []

        # 1. TCP Retransmissions
        findings.extend(self._detect_retransmissions(packets, flows))

        # 2. TCP Resets
        findings.extend(self._detect_resets(packets, flows))

        # 3. Incomplete Handshakes
        findings.extend(self._detect_incomplete_handshakes(packets, flows))

        return findings

    def _detect_retransmissions(
        self,
        packets: Sequence[PacketRecord],
        flows: Mapping[str, FlowRecord]
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Group packets by unidirectional stream: (src_ip, src_port, dst_ip, dst_port)
        streams: dict[tuple[str, int, str, int], list[PacketRecord]] = defaultdict(list)
        for pkt in packets:
            if pkt.transport_protocol == "TCP" and pkt.src_ip and pkt.dst_ip and pkt.src_port and pkt.dst_port:
                if pkt.tcp_seq is not None:
                    streams[(pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)].append(pkt)

        finding_counter = 1
        for (src_ip, src_port, dst_ip, dst_port), stream_pkts in streams.items():
            if len(stream_pkts) < self.config.tcp_retransmission_min_count:
                continue

            # Track sequence intervals seen: list of (start_seq, end_seq, packet_num)
            seen_intervals: list[tuple[int, int, int]] = []
            retrans_evidence: list[int] = []
            total_data_packets = 0

            for pkt in stream_pkts:
                payload_len = pkt.tcp_payload_length or 0
                seq = pkt.tcp_seq
                if seq is None:
                    continue

                # Account for SYN consuming 1 sequence number
                if pkt.tcp_flags and pkt.tcp_flags.get("SYN"):
                    payload_len = max(payload_len, 1)

                if payload_len == 0:
                    continue  # Pure ACKs without payload don't trigger payload retransmission

                total_data_packets += 1
                end_seq = seq + payload_len

                # Check if this interval overlaps with a previously seen interval
                is_retrans = False
                for seen_start, seen_end, seen_pkt in seen_intervals:
                    # Overlap or repeated sequence
                    if max(seq, seen_start) < min(end_seq, seen_end):
                        is_retrans = True
                        if seen_pkt not in retrans_evidence:
                            retrans_evidence.append(seen_pkt)
                        retrans_evidence.append(pkt.packet_number)
                        break

                if not is_retrans:
                    seen_intervals.append((seq, end_seq, pkt.packet_number))

            if total_data_packets > 0:
                retrans_count = len(retrans_evidence) // 2  # Approximate distinct retransmitted chunks
                ratio = len(retrans_evidence) / (total_data_packets * 2) if total_data_packets else 0.0

                if len(retrans_evidence) >= self.config.tcp_retransmission_min_count and ratio >= self.config.tcp_retransmission_min_ratio:
                    f_id = f"F-TCP-RETX-{finding_counter:03d}"
                    finding_counter += 1

                    findings.append(Finding(
                        finding_id=f_id,
                        category="NETWORK_FAULT",
                        type="TCP_RETRANSMISSION",
                        title=f"TCP Retransmission Pattern ({src_ip}:{src_port} -> {dst_ip}:{dst_port})",
                        classification="OBSERVATION",
                        severity="MEDIUM" if ratio > 0.15 else "LOW",
                        confidence=min(0.9, 0.5 + (len(retrans_evidence) * 0.05)),
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        source_port=src_port,
                        destination_port=dst_port,
                        affected_hosts=[src_ip, dst_ip],
                        flow_ids=[f"TCP:{min(src_ip, dst_ip)}<->{max(src_ip, dst_ip)}"],
                        start_time=stream_pkts[0].timestamp,
                        end_time=stream_pkts[-1].timestamp,
                        metrics={
                            "retransmission_events": len(retrans_evidence),
                            "total_data_packets": total_data_packets,
                            "retransmission_ratio": round(ratio, 4)
                        },
                        evidence_packets=retrans_evidence[:20],  # Keep representative evidence
                        reason=f"Observed repeated TCP sequence ranges across {len(retrans_evidence)} packets ({ratio:.1%} retransmission ratio).",
                        likely_cause="Packet loss on intermediate network path or congestion resulting in dropped TCP segments.",
                        alternative_explanations=[
                            "NIC segmentation offload (TSO/LRO) artefacts creating artificial duplicates",
                            "Packet reordering across multi-path routing causing spurious retransmissions",
                            "Capture tool observing duplicates from multiple monitoring tap points"
                        ],
                        recommendation="Check link error counters, MTU consistency, buffer drops on routers, and endpoint TCP congestion control state.",
                        limitations=[
                            "PCAP captures packets at one vantage point; it cannot determine exactly where between source and destination segments were dropped."
                        ]
                    ))

        return findings

    def _detect_resets(
        self,
        packets: Sequence[PacketRecord],
        flows: Mapping[str, FlowRecord]
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Find all TCP RST packets
        rst_by_host: dict[str, list[PacketRecord]] = defaultdict(list)
        for pkt in packets:
            if pkt.transport_protocol == "TCP" and pkt.tcp_flags and pkt.tcp_flags.get("RST"):
                if pkt.src_ip:
                    rst_by_host[pkt.src_ip].append(pkt)

        finding_counter = 1
        for src_ip, rst_pkts in rst_by_host.items():
            count = len(rst_pkts)
            evidence = [p.packet_number for p in rst_pkts]
            start_t = rst_pkts[0].timestamp
            end_t = rst_pkts[-1].timestamp
            time_span = max(0.1, end_t - start_t)

            is_burst = count >= self.config.tcp_rst_burst_threshold and (time_span <= self.config.tcp_rst_burst_window_seconds or count >= 5)

            dest_ips = list({p.dst_ip for p in rst_pkts if p.dst_ip})
            dest_ports = list({p.dst_port for p in rst_pkts if p.dst_port})

            f_id = f"F-TCP-RST-{finding_counter:03d}"
            finding_counter += 1

            findings.append(Finding(
                finding_id=f_id,
                category="NETWORK_FAULT",
                type="TCP_RESET",
                title=f"{'Burst of ' if is_burst else ''}TCP Resets Sent by {src_ip} ({count} resets)",
                classification="OBSERVATION",
                severity="MEDIUM" if is_burst else "LOW",
                confidence=0.85,
                source_ip=src_ip,
                destination_ip=dest_ips[0] if len(dest_ips) == 1 else None,
                source_port=None,
                destination_port=dest_ports[0] if len(dest_ports) == 1 else None,
                affected_hosts=[src_ip] + dest_ips,
                flow_ids=[],
                start_time=start_t,
                end_time=end_t,
                metrics={
                    "rst_count": count,
                    "is_burst": is_burst,
                    "time_span_seconds": round(time_span, 2),
                    "unique_targets_contacted": len(dest_ips)
                },
                evidence_packets=evidence[:20],
                reason=f"Host {src_ip} transmitted {count} TCP RST packet(s) across {time_span:.1f}s.",
                likely_cause="Target service rejected the connection (closed port), connection timed out, or endpoint application terminated abruptly.",
                alternative_explanations=[
                    "Normal application protocol teardown (some HTTP/RPC clients reset rather than FIN/ACK)",
                    "Stateful firewall or middlebox actively terminating unauthorized flows",
                    "Port scan response (closed ports returning RST to scanning SYN)"
                ],
                recommendation="Inspect server application status and verify whether target ports are actively listening and permitted by firewalls.",
                limitations=[
                    "A TCP RST is a normal protocol notification; a capture alone cannot prove whether the reset was caused by an outage, scan, or expected app teardown."
                ]
            ))

        return findings

    def _detect_incomplete_handshakes(
        self,
        packets: Sequence[PacketRecord],
        flows: Mapping[str, FlowRecord]
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Map SYN packets: (src_ip, src_port, dst_ip, dst_port) -> PacketRecord
        syn_packets: list[PacketRecord] = []
        syn_ack_pairs: set[tuple[str, int, str, int]] = set()
        ack_pairs: set[tuple[str, int, str, int]] = set()

        for pkt in packets:
            if pkt.transport_protocol == "TCP" and pkt.src_ip and pkt.dst_ip and pkt.src_port and pkt.dst_port:
                flags = pkt.tcp_flags or {}
                is_syn = flags.get("SYN", False)
                is_ack = flags.get("ACK", False)

                if is_syn and not is_ack:
                    syn_packets.append(pkt)
                elif is_syn and is_ack:
                    # SYN-ACK sent from dst_ip:dst_port back to src_ip:src_port
                    syn_ack_pairs.add((pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port))
                elif not is_syn and is_ack:
                    ack_pairs.add((pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port))

        unanswered_syns: list[PacketRecord] = []
        missing_final_acks: list[PacketRecord] = []

        for syn in syn_packets:
            key = (syn.src_ip, syn.src_port, syn.dst_ip, syn.dst_port)
            if key not in syn_ack_pairs:
                unanswered_syns.append(syn)
            elif key not in ack_pairs:
                missing_final_acks.append(syn)

        finding_counter = 1
        if unanswered_syns:
            # Group by target
            targets = defaultdict(list)
            for s in unanswered_syns:
                targets[(s.src_ip, s.dst_ip, s.dst_port)].append(s)

            for (src_ip, dst_ip, dst_port), syn_list in targets.items():
                evidence = [s.packet_number for s in syn_list]
                f_id = f"F-TCP-HSK-{finding_counter:03d}"
                finding_counter += 1

                findings.append(Finding(
                    finding_id=f_id,
                    category="NETWORK_FAULT",
                    type="INCOMPLETE_HANDSHAKE",
                    title=f"Unanswered TCP Handshake SYN ({src_ip} -> {dst_ip}:{dst_port})",
                    classification="OBSERVATION",
                    severity="MEDIUM" if len(syn_list) >= 3 else "LOW",
                    confidence=0.8,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=syn_list[0].src_port,
                    destination_port=dst_port,
                    affected_hosts=[src_ip, dst_ip],
                    flow_ids=[],
                    start_time=syn_list[0].timestamp,
                    end_time=syn_list[-1].timestamp,
                    metrics={
                        "unanswered_syn_count": len(syn_list),
                        "target_port": dst_port
                    },
                    evidence_packets=evidence[:10],
                    reason=f"Observed {len(syn_list)} TCP SYN request(s) from {src_ip} to {dst_ip}:{dst_port} with no matching SYN-ACK response.",
                    likely_cause="Destination host is offline, firewall is dropping SYN packets silently, or routing failure prevented reachability.",
                    alternative_explanations=[
                        "Capture ended or started mid-handshake",
                        "Asymmetric routing where response return path bypassed the capture interface",
                        "Port scanning probe to a closed or filtered port"
                    ],
                    recommendation="Verify network route to destination, test ICMP reachability, and check destination service listening state.",
                    limitations=[
                        "The capture vantage point may not see reverse traffic if asymmetric routing is active on the network."
                    ]
                ))

        return findings
