"""
Host profiling and endpoint aggregation layer.
Aggregates activity, protocols, MAC bindings, and peer relationships per observed host.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Mapping, Sequence

from core.models import FlowRecord, HostProfile, PacketRecord

logger = logging.getLogger(__name__)


def build_host_profiles(
    packets: Sequence[PacketRecord],
    flows: Mapping[str, FlowRecord]
) -> dict[str, HostProfile]:
    """
    Builds host-level profiles from packet records and associated flow summaries.
    """
    profiles: dict[str, HostProfile] = {}

    def get_or_create_host(ip: str, ts: float) -> HostProfile:
        if ip not in profiles:
            profiles[ip] = HostProfile(
                ip_address=ip,
                first_seen=ts,
                last_seen=ts
            )
        return profiles[ip]

    for pkt in packets:
        ts = pkt.timestamp
        length = pkt.captured_length or 0

        # Source host
        if pkt.src_ip:
            h = get_or_create_host(pkt.src_ip, ts)
            h.first_seen = min(h.first_seen, ts)
            h.last_seen = max(h.last_seen, ts)
            h.packet_count += 1
            h.byte_count += length

            if pkt.src_mac:
                h.mac_addresses.add(pkt.src_mac)
            if pkt.transport_protocol:
                h.protocols_used.add(pkt.transport_protocol)
            if pkt.src_port:
                h.ports_contacted.add(pkt.src_port)
            if pkt.dst_ip:
                h.peers.add(pkt.dst_ip)

        # Destination host
        if pkt.dst_ip:
            h = get_or_create_host(pkt.dst_ip, ts)
            h.first_seen = min(h.first_seen, ts)
            h.last_seen = max(h.last_seen, ts)
            h.packet_count += 1
            h.byte_count += length

            if pkt.dst_mac:
                h.mac_addresses.add(pkt.dst_mac)
            if pkt.transport_protocol:
                h.protocols_used.add(pkt.transport_protocol)
            if pkt.dst_port:
                h.ports_contacted.add(pkt.dst_port)
            if pkt.src_ip:
                h.peers.add(pkt.src_ip)

        # Associate ARP mappings
        if pkt.arp_sender_ip and pkt.arp_sender_mac:
            h = get_or_create_host(pkt.arp_sender_ip, ts)
            h.mac_addresses.add(pkt.arp_sender_mac)

    # Link flow IDs to host profiles
    for flow_id, fl in flows.items():
        ip_a = fl.endpoint_a[0]
        ip_b = fl.endpoint_b[0]

        if ip_a in profiles:
            profiles[ip_a].associated_flow_ids.append(flow_id)
        if ip_b in profiles and ip_b != ip_a:
            profiles[ip_b].associated_flow_ids.append(flow_id)

    return profiles
