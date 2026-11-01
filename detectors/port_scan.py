"""
Port Scan Detectors:
1. Vertical Scan: Single source probing multiple ports on one target host.
2. Horizontal Scan (Host Sweep): Single source probing a common port across multiple target hosts.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Mapping, Sequence

from core.config import AppConfig, DEFAULT_CONFIG
from core.models import Finding, FlowRecord, HostProfile, PacketRecord
from detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class PortScanDetector(BaseDetector):
    """
    Identifies vertical and horizontal port scan patterns using sliding-window tracking.
    """

    @property
    def detector_name(self) -> str:
        return "Port Scan Detector"

    def analyze(
        self,
        packets: Sequence[PacketRecord],
        flows: Mapping[str, FlowRecord],
        hosts: Mapping[str, HostProfile]
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Track connection attempts:
        # vertical_attempts: (src_ip, dst_ip) -> {dst_port: [(timestamp, packet_num)]}
        # horizontal_attempts: (src_ip, dst_port) -> {dst_ip: [(timestamp, packet_num)]}
        vertical_attempts: dict[tuple[str, str], dict[int, list[tuple[float, int]]]] = defaultdict(lambda: defaultdict(list))
        horizontal_attempts: dict[tuple[str, int], dict[str, list[tuple[float, int]]]] = defaultdict(lambda: defaultdict(list))

        for pkt in packets:
            if not pkt.src_ip or not pkt.dst_ip or pkt.dst_port is None:
                continue

            proto = pkt.transport_protocol
            if proto not in ("TCP", "UDP"):
                continue

            # For TCP, focus especially on initial SYNs or first contact
            is_probe = True
            if proto == "TCP" and pkt.tcp_flags:
                # If it's pure ACK or FIN, not a scan probe
                if not pkt.tcp_flags.get("SYN") and not pkt.tcp_flags.get("FIN"):
                    is_probe = False

            if not is_probe:
                continue

            ts = pkt.timestamp
            p_num = pkt.packet_number

            vertical_attempts[(pkt.src_ip, pkt.dst_ip)][pkt.dst_port].append((ts, p_num))
            horizontal_attempts[(pkt.src_ip, pkt.dst_port)][pkt.dst_ip].append((ts, p_num))

        finding_counter = 1

        # 1. Evaluate Vertical Scans (One source -> One target -> Many ports)
        for (src_ip, dst_ip), port_dict in vertical_attempts.items():
            distinct_ports = list(port_dict.keys())
            if len(distinct_ports) >= self.config.vertical_scan_min_ports:
                all_probe_events: list[tuple[float, int, int]] = []
                for port, events in port_dict.items():
                    for ts, p_num in events:
                        all_probe_events.append((ts, p_num, port))

                all_probe_events.sort(key=lambda x: x[0])
                time_span = max(0.1, all_probe_events[-1][0] - all_probe_events[0][0])
                evidence_pkts = [e[1] for e in all_probe_events]

                f_id = f"F-SCAN-VERT-{finding_counter:03d}"
                finding_counter += 1

                findings.append(Finding(
                    finding_id=f_id,
                    category="SECURITY",
                    type="PORT_SCAN",
                    title=f"Possible Vertical Port Scan ({src_ip} -> {dst_ip})",
                    classification="SUSPICIOUS_ACTIVITY",
                    severity="HIGH" if len(distinct_ports) >= 50 else "MEDIUM",
                    confidence=min(0.95, 0.65 + (len(distinct_ports) * 0.005)),
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=None,
                    destination_port=None,
                    affected_hosts=[src_ip, dst_ip],
                    flow_ids=[],
                    start_time=all_probe_events[0][0],
                    end_time=all_probe_events[-1][0],
                    metrics={
                        "scan_type": "VERTICAL",
                        "distinct_ports_contacted": len(distinct_ports),
                        "total_probes": len(all_probe_events),
                        "duration_seconds": round(time_span, 2),
                        "sample_ports": distinct_ports[:15]
                    },
                    evidence_packets=evidence_pkts[:25],
                    reason=f"Host {src_ip} initiated probes to {len(distinct_ports)} distinct ports on target {dst_ip} within {time_span:.1f}s.",
                    likely_cause="Network reconnaissance or port scanning tool (e.g., Nmap) discovering listening services on the target.",
                    alternative_explanations=[
                        "Authorized internal vulnerability assessment or compliance scanner",
                        "Local network discovery tool or asset inventory system",
                        "Misconfigured client application cycling through fallback port numbers"
                    ],
                    recommendation="Confirm whether the source IP belongs to an authorized security scanner; check host intrusion detection (HIDS) alerts on target.",
                    limitations=[
                        "PCAP metadata shows connection attempts across many ports, but intent cannot be proven without external authorization context."
                    ]
                ))

        # 2. Evaluate Horizontal Scans (One source -> Many targets -> Same port)
        for (src_ip, target_port), host_dict in horizontal_attempts.items():
            distinct_hosts = list(host_dict.keys())
            if len(distinct_hosts) >= self.config.horizontal_scan_min_hosts:
                all_probe_events = []
                for host, events in host_dict.items():
                    for ts, p_num in events:
                        all_probe_events.append((ts, p_num, host))

                all_probe_events.sort(key=lambda x: x[0])
                time_span = max(0.1, all_probe_events[-1][0] - all_probe_events[0][0])
                evidence_pkts = [e[1] for e in all_probe_events]

                f_id = f"F-SCAN-HORIZ-{finding_counter:03d}"
                finding_counter += 1

                findings.append(Finding(
                    finding_id=f_id,
                    category="SECURITY",
                    type="PORT_SWEEP",
                    title=f"Possible Horizontal Sweep on Port {target_port} by {src_ip}",
                    classification="SUSPICIOUS_ACTIVITY",
                    severity="HIGH" if len(distinct_hosts) >= 20 else "MEDIUM",
                    confidence=min(0.95, 0.65 + (len(distinct_hosts) * 0.01)),
                    source_ip=src_ip,
                    destination_ip=None,
                    source_port=None,
                    destination_port=target_port,
                    affected_hosts=[src_ip] + distinct_hosts[:10],
                    flow_ids=[],
                    start_time=all_probe_events[0][0],
                    end_time=all_probe_events[-1][0],
                    metrics={
                        "scan_type": "HORIZONTAL",
                        "target_port": target_port,
                        "distinct_hosts_probed": len(distinct_hosts),
                        "total_probes": len(all_probe_events),
                        "duration_seconds": round(time_span, 2)
                    },
                    evidence_packets=evidence_pkts[:25],
                    reason=f"Host {src_ip} swept {len(distinct_hosts)} distinct destination hosts on port {target_port} within {time_span:.1f}s.",
                    likely_cause="Network worm propagation, mass vulnerability scanning, or automated subnet asset discovery.",
                    alternative_explanations=[
                        "Authorized internal infrastructure monitor / healthcheck polling service",
                        "Subnet-wide service broadcast / cluster discovery daemon"
                    ],
                    recommendation="Determine whether source IP is an authorized monitoring station; isolate source host if unrecognized.",
                    limitations=[
                        "Observed traffic indicates sweep behavior; authorization cannot be deduced solely from packet metadata."
                    ]
                ))

        return findings
