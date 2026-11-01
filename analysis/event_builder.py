"""
Timeline event builder.
Transforms notable packet occurrences and detector findings into chronological timeline events.
"""

from __future__ import annotations

import logging
from typing import Sequence

from core.models import Finding, PacketRecord, TimelineEvent

logger = logging.getLogger(__name__)


def build_timeline_events(
    packets: Sequence[PacketRecord],
    findings: Sequence[Finding]
) -> list[TimelineEvent]:
    """
    Generates a consolidated, chronologically ordered list of events.
    Filters out routine payload/ACK packets so the timeline remains focused and readable.
    """
    events: list[TimelineEvent] = []
    event_idx = 1

    # 1. Packet-level protocol events
    for pkt in packets:
        ev: TimelineEvent | None = None
        src = pkt.src_ip or pkt.src_mac or "Unknown"
        dst = pkt.dst_ip or pkt.dst_mac or "Unknown"
        proto = pkt.transport_protocol or pkt.highest_layer

        # A. TCP Flags
        if pkt.transport_protocol == "TCP" and pkt.tcp_flags:
            flags = pkt.tcp_flags
            p_desc = f"{src}:{pkt.src_port} -> {dst}:{pkt.dst_port}"

            if flags.get("RST"):
                ev = TimelineEvent(
                    event_id=f"EV-PKT-{event_idx:04d}",
                    timestamp=pkt.timestamp,
                    timestamp_iso=pkt.timestamp_iso,
                    packet_number=pkt.packet_number,
                    event_type="TCP_RST",
                    category="FAULT",
                    source=src,
                    destination=dst,
                    protocol="TCP",
                    severity="MEDIUM",
                    description=f"TCP Reset sent by {src} ({p_desc})",
                    evidence_packets=[pkt.packet_number]
                )
            elif flags.get("SYN") and flags.get("ACK"):
                ev = TimelineEvent(
                    event_id=f"EV-PKT-{event_idx:04d}",
                    timestamp=pkt.timestamp,
                    timestamp_iso=pkt.timestamp_iso,
                    packet_number=pkt.packet_number,
                    event_type="TCP_SYN_ACK",
                    category="PROTOCOL",
                    source=src,
                    destination=dst,
                    protocol="TCP",
                    severity="INFO",
                    description=f"TCP Handshake SYN-ACK from {src} to {dst}:{pkt.dst_port}",
                    evidence_packets=[pkt.packet_number]
                )
            elif flags.get("SYN"):
                ev = TimelineEvent(
                    event_id=f"EV-PKT-{event_idx:04d}",
                    timestamp=pkt.timestamp,
                    timestamp_iso=pkt.timestamp_iso,
                    packet_number=pkt.packet_number,
                    event_type="TCP_SYN",
                    category="PROTOCOL",
                    source=src,
                    destination=dst,
                    protocol="TCP",
                    severity="INFO",
                    description=f"TCP Connection Request (SYN) to {dst}:{pkt.dst_port}",
                    evidence_packets=[pkt.packet_number]
                )
            elif flags.get("FIN"):
                ev = TimelineEvent(
                    event_id=f"EV-PKT-{event_idx:04d}",
                    timestamp=pkt.timestamp,
                    timestamp_iso=pkt.timestamp_iso,
                    packet_number=pkt.packet_number,
                    event_type="TCP_FIN",
                    category="PROTOCOL",
                    source=src,
                    destination=dst,
                    protocol="TCP",
                    severity="INFO",
                    description=f"TCP Graceful Teardown (FIN) from {src} to {dst}",
                    evidence_packets=[pkt.packet_number]
                )

        # B. DNS Query / Response
        elif pkt.dns_id is not None:
            qname = pkt.dns_query_name or "unknown domain"
            if pkt.dns_is_response:
                rcode_text = f" (RCODE: {pkt.dns_response_code})" if pkt.dns_response_code else ""
                ans_text = f" -> {', '.join(pkt.dns_answers[:2])}" if pkt.dns_answers else ""
                ev = TimelineEvent(
                    event_id=f"EV-PKT-{event_idx:04d}",
                    timestamp=pkt.timestamp,
                    timestamp_iso=pkt.timestamp_iso,
                    packet_number=pkt.packet_number,
                    event_type="DNS_RESPONSE",
                    category="FAULT" if pkt.dns_response_code else "PROTOCOL",
                    source=src,
                    destination=dst,
                    protocol="DNS",
                    severity="HIGH" if pkt.dns_response_code == 2 else "INFO",
                    description=f"DNS Response for '{qname}'{rcode_text}{ans_text}",
                    evidence_packets=[pkt.packet_number]
                )
            else:
                ev = TimelineEvent(
                    event_id=f"EV-PKT-{event_idx:04d}",
                    timestamp=pkt.timestamp,
                    timestamp_iso=pkt.timestamp_iso,
                    packet_number=pkt.packet_number,
                    event_type="DNS_QUERY",
                    category="PROTOCOL",
                    source=src,
                    destination=dst,
                    protocol="DNS",
                    severity="INFO",
                    description=f"DNS Query for '{qname}'",
                    evidence_packets=[pkt.packet_number]
                )

        # C. ARP Requests & Replies
        elif pkt.transport_protocol == "ARP":
            op = pkt.arp_operation or "ARP"
            ev = TimelineEvent(
                event_id=f"EV-PKT-{event_idx:04d}",
                timestamp=pkt.timestamp,
                timestamp_iso=pkt.timestamp_iso,
                packet_number=pkt.packet_number,
                event_type=f"ARP_{op}",
                category="PROTOCOL",
                source=pkt.arp_sender_ip or src,
                destination=pkt.arp_target_ip or dst,
                protocol="ARP",
                severity="INFO",
                description=f"ARP {op}: {pkt.arp_sender_ip} ({pkt.arp_sender_mac}) -> {pkt.arp_target_ip}",
                evidence_packets=[pkt.packet_number]
            )

        # D. ICMP Errors
        elif pkt.transport_protocol == "ICMP" and pkt.icmp_type is not None:
            ev = TimelineEvent(
                event_id=f"EV-PKT-{event_idx:04d}",
                timestamp=pkt.timestamp,
                timestamp_iso=pkt.timestamp_iso,
                packet_number=pkt.packet_number,
                event_type="ICMP_MESSAGE",
                category="FAULT",
                source=src,
                destination=dst,
                protocol="ICMP",
                severity="MEDIUM" if pkt.icmp_type == 3 else "INFO",
                description=f"ICMP Type {pkt.icmp_type} Code {pkt.icmp_code} ({src} -> {dst})",
                evidence_packets=[pkt.packet_number]
            )

        # E. DHCP Events
        elif pkt.dhcp_message_type:
            ev = TimelineEvent(
                event_id=f"EV-PKT-{event_idx:04d}",
                timestamp=pkt.timestamp,
                timestamp_iso=pkt.timestamp_iso,
                packet_number=pkt.packet_number,
                event_type=f"DHCP_{pkt.dhcp_message_type.upper()}",
                category="PROTOCOL",
                source=src,
                destination=dst,
                protocol="DHCP",
                severity="INFO",
                description=f"DHCP {pkt.dhcp_message_type} (Server: {pkt.dhcp_server_id or src})",
                evidence_packets=[pkt.packet_number]
            )

        if ev:
            events.append(ev)
            event_idx += 1

    # 2. Finding-level events
    for f in findings:
        primary_pkt = f.evidence_packets[0] if f.evidence_packets else None
        iso_str = ""
        # Find timestamp iso from primary packet if possible
        for p in packets:
            if p.packet_number == primary_pkt:
                iso_str = p.timestamp_iso
                break

        events.append(TimelineEvent(
            event_id=f"EV-FND-{event_idx:04d}",
            timestamp=f.start_time,
            timestamp_iso=iso_str,
            packet_number=primary_pkt,
            event_type=f"DETECTION_{f.type}",
            category="SECURITY" if f.category == "SECURITY" else "FAULT",
            source=f.source_ip or "Multiple",
            destination=f.destination_ip or "Multiple",
            protocol=f.type.split("_")[0],
            severity=f.severity,
            description=f"Finding: {f.title}",
            finding_id=f.finding_id,
            evidence_packets=f.evidence_packets
        ))
        event_idx += 1

    # Sort all events chronologically
    events.sort(key=lambda e: e.timestamp)
    return events
