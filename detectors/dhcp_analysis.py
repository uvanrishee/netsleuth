"""
DHCP Analysis Detector:
Identifies multiple active DHCP servers offering leases on a single subnet (possible rogue DHCP).
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Mapping, Sequence

from core.config import AppConfig, DEFAULT_CONFIG
from core.models import Finding, FlowRecord, HostProfile, PacketRecord
from detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class DHCPAnalysisDetector(BaseDetector):
    """
    Detects multiple distinct DHCP servers responding to client Discover/Request messages.
    """

    @property
    def detector_name(self) -> str:
        return "DHCP Analysis Detector"

    def analyze(
        self,
        packets: Sequence[PacketRecord],
        flows: Mapping[str, FlowRecord],
        hosts: Mapping[str, HostProfile]
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Track servers offering leases: server_id / src_ip -> [(timestamp, packet_number, offered_ip)]
        dhcp_servers: dict[str, list[tuple[float, int, str | None]]] = defaultdict(list)
        all_dhcp_packets: list[PacketRecord] = []

        for pkt in packets:
            is_dhcp = (
                pkt.dhcp_message_type is not None or
                pkt.dhcp_server_id is not None or
                pkt.src_port in (67, 68) or
                pkt.dst_port in (67, 68)
            )
            if is_dhcp:
                all_dhcp_packets.append(pkt)
                # If packet is an Offer or ACK from a server
                server_ident = pkt.dhcp_server_id or pkt.src_ip
                msg_type = (pkt.dhcp_message_type or "").upper()

                if server_ident and ("OFFER" in msg_type or "ACK" in msg_type or pkt.src_port == 67):
                    dhcp_servers[server_ident].append((pkt.timestamp, pkt.packet_number, pkt.dhcp_offered_ip))

        if len(dhcp_servers) > 1:
            server_list = list(dhcp_servers.keys())
            evidence: list[int] = []
            for s_id, events in dhcp_servers.items():
                for ts, p_num, off_ip in events:
                    evidence.append(p_num)

            evidence.sort()
            f_id = "F-DHCP-MULTI-001"

            findings.append(Finding(
                finding_id=f_id,
                category="SECURITY",
                type="MULTIPLE_DHCP_SERVERS",
                title=f"Multiple DHCP Servers Observed ({', '.join(server_list)})",
                classification="SUSPICIOUS_ACTIVITY",
                severity="HIGH",
                confidence=0.85,
                source_ip=server_list[0],
                destination_ip=None,
                source_port=67,
                destination_port=68,
                affected_hosts=server_list,
                flow_ids=[],
                start_time=all_dhcp_packets[0].timestamp if all_dhcp_packets else 0.0,
                end_time=all_dhcp_packets[-1].timestamp if all_dhcp_packets else 0.0,
                metrics={
                    "distinct_dhcp_servers": server_list,
                    "server_count": len(server_list),
                    "total_dhcp_events": len(all_dhcp_packets)
                },
                evidence_packets=evidence[:15],
                reason=f"Observed {len(server_list)} distinct DHCP server identities ({', '.join(server_list)}) offering IP leases.",
                likely_cause="Accidental secondary DHCP router plugged into the subnet, or unauthorized (rogue) DHCP server attempting a Man-in-the-Middle attack.",
                alternative_explanations=[
                    "Authorized High-Availability (HA) DHCP failover cluster",
                    "Dual-stack or multi-subnet router relaying DHCP requests",
                    "Lab testing environment with deliberately segregated test servers"
                ],
                recommendation="Inspect switch ports delivering DHCP offers using DHCP Snooping; confirm MAC addresses of both servers against network inventory.",
                limitations=[
                    "NetSleuth observes multiple DHCP server offers but cannot determine which server is authorized without a predefined network allowlist."
                ]
            ))

        return findings
