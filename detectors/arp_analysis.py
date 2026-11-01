"""
ARP Conflict and Spoofing Indicator Detector.
Identifies IP-to-MAC mapping discrepancies, competing MAC claims, and gratuitous ARP bursts.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Mapping, Sequence

from core.config import AppConfig, DEFAULT_CONFIG
from core.models import Finding, FlowRecord, HostProfile, PacketRecord
from detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class ARPAnalysisDetector(BaseDetector):
    """
    Detects duplicate IP addresses, ARP mapping conflicts, and potential ARP spoofing indicators.
    """

    @property
    def detector_name(self) -> str:
        return "ARP Analysis Detector"

    def analyze(
        self,
        packets: Sequence[PacketRecord],
        flows: Mapping[str, FlowRecord],
        hosts: Mapping[str, HostProfile]
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Track IP -> MAC claims: {ip: {mac: [(timestamp, packet_number, op)]}}
        ip_claims: dict[str, dict[str, list[tuple[float, int, str]]]] = defaultdict(lambda: defaultdict(list))
        gratuitous_arp_by_mac: dict[str, list[tuple[float, int, str]]] = defaultdict(list)

        for pkt in packets:
            ts = pkt.timestamp
            pkt_num = pkt.packet_number

            # ARP packets
            if pkt.transport_protocol == "ARP" and pkt.arp_sender_ip and pkt.arp_sender_mac:
                op = pkt.arp_operation or "ARP"
                ip_claims[pkt.arp_sender_ip][pkt.arp_sender_mac].append((ts, pkt_num, op))

                # Gratuitous ARP: sender IP equals target IP, or broadcast announcement
                if pkt.arp_sender_ip == pkt.arp_target_ip or pkt.dst_mac in ("ff:ff:ff:ff:ff:ff", None):
                    gratuitous_arp_by_mac[pkt.arp_sender_mac].append((ts, pkt_num, pkt.arp_sender_ip))

            # General IP packets can also reveal MAC-IP binding
            elif pkt.src_ip and pkt.src_mac:
                ip_claims[pkt.src_ip][pkt.src_mac].append((ts, pkt_num, "IP_TRAFFIC"))

        finding_counter = 1

        # Check for multiple MACs claiming the same IP
        for ip, mac_dict in ip_claims.items():
            # Filter out broadcast / zero MACs if any
            valid_macs = {m: claims for m, claims in mac_dict.items() if m and m not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff")}

            if len(valid_macs) > 1:
                # We have a conflict!
                mac_list = list(valid_macs.keys())
                all_claims: list[tuple[float, int, str, str]] = []
                for m, claims in valid_macs.items():
                    for ts, pkt_num, op in claims:
                        all_claims.append((ts, pkt_num, m, op))

                all_claims.sort(key=lambda x: x[0])  # Sort by timestamp

                time_span = all_claims[-1][0] - all_claims[0][0]
                evidence_pkts = [c[1] for c in all_claims]

                # Rapid alternation suggests aggressive spoofing
                is_rapid = time_span <= self.config.arp_conflict_window_seconds
                has_garp_burst = any(
                    len(gratuitous_arp_by_mac.get(m, [])) >= self.config.arp_gratuitous_burst_threshold
                    for m in mac_list
                )

                classification = "POSSIBLE_ATTACK_INDICATOR" if (is_rapid and has_garp_burst) else "SUSPICIOUS_ACTIVITY"
                category = "SECURITY" if classification == "POSSIBLE_ATTACK_INDICATOR" else "NETWORK_FAULT"
                severity = "HIGH" if classification == "POSSIBLE_ATTACK_INDICATOR" else "MEDIUM"

                f_id = f"F-ARP-CONF-{finding_counter:03d}"
                finding_counter += 1

                findings.append(Finding(
                    finding_id=f_id,
                    category=category,
                    type="ARP_CONFLICT",
                    title=f"IP-to-MAC Conflict for {ip} ({', '.join(mac_list)})",
                    classification=classification,
                    severity=severity,
                    confidence=0.85,
                    source_ip=ip,
                    destination_ip=None,
                    source_port=None,
                    destination_port=None,
                    affected_hosts=[ip],
                    flow_ids=[],
                    start_time=all_claims[0][0],
                    end_time=all_claims[-1][0],
                    metrics={
                        "conflicting_ip": ip,
                        "competing_macs": mac_list,
                        "total_claim_events": len(all_claims),
                        "conflict_duration_seconds": round(time_span, 2),
                        "has_gratuitous_burst": has_garp_burst
                    },
                    evidence_packets=evidence_pkts[:15],
                    reason=f"Observed multiple distinct MAC addresses ({', '.join(mac_list)}) claiming ownership of IP {ip} within {time_span:.1f}s.",
                    likely_cause="Duplicate static IP configuration on the subnet, router failover (VRRP/HSRP), or possible ARP cache poisoning attempt.",
                    alternative_explanations=[
                        "High-availability cluster or gateway failover (VRRP/HSRP/CARP)",
                        "Virtual machine live migration to a new physical hypervisor interface",
                        "DHCP IP address re-assignment to a new physical host",
                        "Network interface card (NIC) teaming / failover bonding"
                    ],
                    recommendation="Inspect managed switch MAC address tables (CAM tables), review DHCP server active lease tables, and verify IP allocation policies.",
                    limitations=[
                        "An IP-to-MAC conflict proves multiple devices asserted the same address, but packet capture alone cannot differentiate an administrative misconfiguration from an active ARP poisoning attack."
                    ]
                ))

        return findings
