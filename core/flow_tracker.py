"""
Bidirectional flow tracking and state aggregation.
Groups TCP and UDP packets into conversation flows using canonical 5-tuples.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Sequence

from core.models import FlowRecord, PacketRecord

logger = logging.getLogger(__name__)


def make_canonical_flow_key(
    protocol: str,
    ip1: str,
    port1: int,
    ip2: str,
    port2: int
) -> tuple[str, tuple[str, int], tuple[str, int]]:
    """
    Produces a deterministic bidirectional key:
    (protocol, (ip_a, port_a), (ip_b, port_b)) where (ip_a, port_a) <= (ip_b, port_b).
    """
    ep1 = (ip1, port1)
    ep2 = (ip2, port2)
    if ep1 <= ep2:
        return f"{protocol}:{ip1}:{port1}<->{ip2}:{port2}", ep1, ep2
    return f"{protocol}:{ip2}:{port2}<->{ip1}:{port1}", ep2, ep1


def build_flows(packets: Sequence[PacketRecord]) -> dict[str, FlowRecord]:
    """
    Processes normalized packets and aggregates them into bidirectional FlowRecord objects.
    Only TCP and UDP packets with valid IPs and ports are tracked into flows.
    """
    flows: dict[str, FlowRecord] = {}

    for pkt in packets:
        proto = pkt.transport_protocol
        if proto not in ("TCP", "UDP"):
            continue

        if not pkt.src_ip or not pkt.dst_ip or pkt.src_port is None or pkt.dst_port is None:
            continue

        flow_id, ep_a, ep_b = make_canonical_flow_key(
            proto, pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port
        )

        pkt_len = pkt.captured_length or 0
        pkt_ep = (pkt.src_ip, pkt.src_port)
        is_a_to_b = (pkt_ep == ep_a)

        if flow_id not in flows:
            flows[flow_id] = FlowRecord(
                flow_id=flow_id,
                protocol=proto,
                endpoint_a=ep_a,
                endpoint_b=ep_b,
                start_time=pkt.timestamp,
                end_time=pkt.timestamp,
                packet_count=1,
                byte_count=pkt_len,
                packets_a_to_b=1 if is_a_to_b else 0,
                packets_b_to_a=0 if is_a_to_b else 1,
                bytes_a_to_b=pkt_len if is_a_to_b else 0,
                bytes_b_to_a=0 if is_a_to_b else pkt_len,
                tcp_flags_summary=defaultdict(int),
                evidence_packets=[pkt.packet_number],
                state_summary="INIT"
            )
        else:
            fl = flows[flow_id]
            fl.packet_count += 1
            fl.byte_count += pkt_len
            fl.end_time = max(fl.end_time, pkt.timestamp)
            if is_a_to_b:
                fl.packets_a_to_b += 1
                fl.bytes_a_to_b += pkt_len
            else:
                fl.packets_b_to_a += 1
                fl.bytes_b_to_a += pkt_len
            fl.evidence_packets.append(pkt.packet_number)

        # Accumulate TCP flags
        if proto == "TCP" and pkt.tcp_flags:
            fl = flows[flow_id]
            for flag, is_set in pkt.tcp_flags.items():
                if is_set:
                    fl.tcp_flags_summary[flag] = fl.tcp_flags_summary.get(flag, 0) + 1

    # Summarize state for each flow
    for fl in flows.values():
        if fl.protocol == "TCP":
            flags = fl.tcp_flags_summary
            syns = flags.get("SYN", 0)
            acks = flags.get("ACK", 0)
            rsts = flags.get("RST", 0)
            fins = flags.get("FIN", 0)

            if rsts > 0:
                fl.state_summary = "RESET"
            elif fins > 0:
                fl.state_summary = "CLOSED"
            elif syns > 0 and acks == 0:
                fl.state_summary = "SYN_SENT"
            elif syns >= 1 and acks >= 1:
                fl.state_summary = "ESTABLISHED"
            else:
                fl.state_summary = "ACTIVE"
        else:
            if fl.packets_a_to_b > 0 and fl.packets_b_to_a > 0:
                fl.state_summary = "BIDIRECTIONAL"
            else:
                fl.state_summary = "UNIDIRECTIONAL"

    return flows
