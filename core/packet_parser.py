"""
Packet parsing and field extraction layer.
Decouples PyShark/TShark decoding from the rest of the application.
Transforms raw packets into immutable PacketRecord objects.
"""

from __future__ import annotations

import datetime
import logging
from typing import Callable, Iterator

from core.config import AppConfig, DEFAULT_CONFIG
from core.models import PacketRecord

logger = logging.getLogger(__name__)

# Apply nest_asyncio to avoid conflicts in Streamlit threads when PyShark uses asyncio
try:
    import nest_asyncio
    nest_asyncio.apply()
except Exception:
    pass


def _safe_int(val: Any) -> int | None:
    if val is None:
        return None
    try:
        if isinstance(val, str) and val.startswith(("0x", "0X")):
            return int(val, 16)
        return int(val)
    except (ValueError, TypeError):
        return None


def _safe_float(val: Any) -> float | None:
    if val is None:
        return None
    try:
        return float(val)
    except (ValueError, TypeError):
        return None


def _parse_tcp_flags(tcp_layer: Any) -> dict[str, bool]:
    """
    Extracts standard TCP flags from a PyShark TCP layer using bitmask.
    """
    flags_dict = {
        "FIN": False,
        "SYN": False,
        "RST": False,
        "PSH": False,
        "ACK": False,
        "URG": False,
        "ECE": False,
        "CWR": False,
    }

    try:
        raw_val = getattr(tcp_layer, "flags", None)
        flags_int = _safe_int(raw_val)
        if flags_int is not None:
            flags_dict["FIN"] = bool(flags_int & 0x01)
            flags_dict["SYN"] = bool(flags_int & 0x02)
            flags_dict["RST"] = bool(flags_int & 0x04)
            flags_dict["PSH"] = bool(flags_int & 0x08)
            flags_dict["ACK"] = bool(flags_int & 0x10)
            flags_dict["URG"] = bool(flags_int & 0x20)
            flags_dict["ECE"] = bool(flags_int & 0x40)
            flags_dict["CWR"] = bool(flags_int & 0x80)
            return flags_dict

        # Fallback to direct field attributes
        flags_dict["FIN"] = getattr(tcp_layer, "flags_fin", "0") == "1"
        flags_dict["SYN"] = getattr(tcp_layer, "flags_syn", "0") == "1"
        flags_dict["RST"] = getattr(tcp_layer, "flags_reset", "0") == "1"
        flags_dict["PSH"] = getattr(tcp_layer, "flags_push", "0") == "1"
        flags_dict["ACK"] = getattr(tcp_layer, "flags_ack", "0") == "1"
        flags_dict["URG"] = getattr(tcp_layer, "flags_urg", "0") == "1"
    except Exception as exc:
        logger.debug("Error parsing TCP flags: %s", exc)

    return flags_dict


def _normalise_pyshark_packet(packet: Any, packet_idx: int) -> PacketRecord:
    """
    Converts a single PyShark packet object into a normalised PacketRecord.
    Never raises an uncaught exception; captures parsing issues in parse_warnings.
    """
    warnings: list[str] = []

    # Timestamp
    try:
        ts = float(packet.sniff_time.timestamp())
        ts_iso = packet.sniff_time.isoformat()
    except Exception:
        ts = 0.0
        ts_iso = datetime.datetime.fromtimestamp(0, tz=datetime.timezone.utc).isoformat()
        warnings.append("Invalid or missing packet timestamp.")

    captured_len = _safe_int(getattr(packet, "captured_length", None)) or _safe_int(getattr(packet, "length", 0)) or 0
    reported_len = _safe_int(getattr(packet, "length", None)) or captured_len
    highest_layer = getattr(packet, "highest_layer", "UNKNOWN")

    try:
        layers = tuple(l.layer_name.upper() for l in packet.layers)
    except Exception:
        layers = ()

    # Layer 2 (Ethernet)
    src_mac = None
    dst_mac = None
    if hasattr(packet, "eth"):
        src_mac = getattr(packet.eth, "src", None)
        dst_mac = getattr(packet.eth, "dst", None)

    # Layer 3 (IP / IPv6)
    src_ip = None
    dst_ip = None
    ip_version = None
    ttl = None
    ip_id = None
    frag_offset = None
    more_frags = None

    if hasattr(packet, "ip"):
        ip_layer = packet.ip
        ip_version = 4
        src_ip = getattr(ip_layer, "src", None)
        dst_ip = getattr(ip_layer, "dst", None)
        ttl = _safe_int(getattr(ip_layer, "ttl", None))
        ip_id = _safe_int(getattr(ip_layer, "id", None))
        frag_offset = _safe_int(getattr(ip_layer, "frag_offset", None))
        flags_mf = getattr(ip_layer, "flags_mf", "0")
        more_frags = (flags_mf == "1")
    elif hasattr(packet, "ipv6"):
        ip_layer = packet.ipv6
        ip_version = 6
        src_ip = getattr(ip_layer, "src", None)
        dst_ip = getattr(ip_layer, "dst", None)
        ttl = _safe_int(getattr(ip_layer, "hlim", None))

    # Layer 4 (Transport: TCP / UDP / ICMP)
    transport_protocol = None
    src_port = None
    dst_port = None
    tcp_flags = None
    tcp_seq = None
    tcp_ack = None
    tcp_payload_len = None

    if hasattr(packet, "tcp"):
        transport_protocol = "TCP"
        tcp_layer = packet.tcp
        src_port = _safe_int(getattr(tcp_layer, "srcport", None))
        dst_port = _safe_int(getattr(tcp_layer, "dstport", None))
        tcp_seq = _safe_int(getattr(tcp_layer, "seq", None))
        tcp_ack = _safe_int(getattr(tcp_layer, "ack", None))
        tcp_payload_len = _safe_int(getattr(tcp_layer, "len", None))
        tcp_flags = _parse_tcp_flags(tcp_layer)
    elif hasattr(packet, "udp"):
        transport_protocol = "UDP"
        udp_layer = packet.udp
        src_port = _safe_int(getattr(udp_layer, "srcport", None))
        dst_port = _safe_int(getattr(udp_layer, "dstport", None))
    elif hasattr(packet, "icmp"):
        transport_protocol = "ICMP"

    # DNS Layer
    dns_id = None
    dns_is_response = None
    dns_query_name = None
    dns_query_type = None
    dns_response_code = None
    dns_answers: list[str] = []

    if hasattr(packet, "dns"):
        dns_layer = packet.dns
        dns_id = _safe_int(getattr(dns_layer, "id", None))
        flags_resp = getattr(dns_layer, "flags_response", None)
        if flags_resp in ("1", "True", True, 1):
            dns_is_response = True
        elif flags_resp in ("0", "False", False, 0):
            dns_is_response = False

        dns_query_name = getattr(dns_layer, "qry_name", None) or getattr(dns_layer, "dns_qry_name", None)
        dns_query_type = getattr(dns_layer, "qry_type", None)
        dns_response_code = _safe_int(getattr(dns_layer, "flags_rcode", None))

        flags_int = _safe_int(getattr(dns_layer, "flags", None))
        if flags_int is not None:
            if dns_is_response is None:
                dns_is_response = bool(flags_int & 0x8000)
            if dns_response_code is None and dns_is_response:
                dns_response_code = flags_int & 0x000F

        # Collect response answers if available
        for attr in ("a", "cname", "resp_name"):
            val = getattr(dns_layer, attr, None)
            if val:
                if isinstance(val, (list, tuple)):
                    dns_answers.extend(str(v) for v in val)
                else:
                    dns_answers.append(str(val))

    # ARP Layer
    arp_op = None
    arp_sender_ip = None
    arp_sender_mac = None
    arp_target_ip = None
    arp_target_mac = None

    if hasattr(packet, "arp"):
        arp_layer = packet.arp
        raw_op = getattr(arp_layer, "opcode", None)
        if raw_op == "1":
            arp_op = "REQUEST"
        elif raw_op == "2":
            arp_op = "REPLY"
        else:
            arp_op = str(raw_op) if raw_op else None
        arp_sender_ip = getattr(arp_layer, "src_proto_ipv4", None) or getattr(arp_layer, "src.proto_ipv4", None)
        arp_sender_mac = getattr(arp_layer, "src_hw_mac", None) or getattr(arp_layer, "src.hw_mac", None)
        arp_target_ip = getattr(arp_layer, "dst_proto_ipv4", None) or getattr(arp_layer, "dst.proto_ipv4", None)
        arp_target_mac = getattr(arp_layer, "dst_hw_mac", None) or getattr(arp_layer, "dst.hw_mac", None)
        transport_protocol = "ARP"
        if not src_ip and arp_sender_ip:
            src_ip = arp_sender_ip
        if not dst_ip and arp_target_ip:
            dst_ip = arp_target_ip

    # DHCP / BOOTP Layer
    dhcp_type = None
    dhcp_server_id = None
    dhcp_client_mac = None
    dhcp_offered_ip = None

    if hasattr(packet, "dhcp") or hasattr(packet, "bootp"):
        bootp_layer = getattr(packet, "dhcp", None) or getattr(packet, "bootp", None)
        dhcp_type = getattr(bootp_layer, "option_dhcp_message_type", None) or getattr(bootp_layer, "type", None)
        dhcp_server_id = getattr(bootp_layer, "option_dhcp_server_id", None) or getattr(bootp_layer, "server_id", None)
        dhcp_client_mac = getattr(bootp_layer, "hw_mac_addr", None) or getattr(bootp_layer, "client_hardware_address", None)
        dhcp_offered_ip = getattr(bootp_layer, "your_client_ip_address", None) or getattr(bootp_layer, "ip_your", None)

    # ICMP Layer Details
    icmp_type = None
    icmp_code = None
    icmp_mtu = None

    if hasattr(packet, "icmp"):
        icmp_layer = packet.icmp
        icmp_type = _safe_int(getattr(icmp_layer, "type", None))
        icmp_code = _safe_int(getattr(icmp_layer, "code", None))
        icmp_mtu = _safe_int(getattr(icmp_layer, "mtu", None)) or _safe_int(getattr(icmp_layer, "nexthopmtu", None))

    return PacketRecord(
        packet_number=packet_idx,
        timestamp=ts,
        timestamp_iso=ts_iso,
        captured_length=captured_len,
        reported_length=reported_len,
        highest_layer=highest_layer,
        protocol_stack=layers,
        src_mac=src_mac,
        dst_mac=dst_mac,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ip_version=ip_version,
        ttl=ttl,
        ip_id=ip_id,
        fragment_offset=frag_offset,
        more_fragments=more_frags,
        transport_protocol=transport_protocol,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        tcp_seq=tcp_seq,
        tcp_ack=tcp_ack,
        tcp_payload_length=tcp_payload_len,
        dns_id=dns_id,
        dns_is_response=dns_is_response,
        dns_query_name=dns_query_name,
        dns_query_type=dns_query_type,
        dns_response_code=dns_response_code,
        dns_answers=tuple(dns_answers),
        arp_operation=arp_op,
        arp_sender_ip=arp_sender_ip,
        arp_sender_mac=arp_sender_mac,
        arp_target_ip=arp_target_ip,
        arp_target_mac=arp_target_mac,
        dhcp_message_type=str(dhcp_type) if dhcp_type else None,
        dhcp_server_id=str(dhcp_server_id) if dhcp_server_id else None,
        dhcp_client_mac=str(dhcp_client_mac) if dhcp_client_mac else None,
        dhcp_offered_ip=str(dhcp_offered_ip) if dhcp_offered_ip else None,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
        icmp_mtu=icmp_mtu,
        parse_warnings=tuple(warnings),
    )


def parse_pcap_file(
    file_path: str,
    config: AppConfig = DEFAULT_CONFIG,
    progress_callback: Callable[[int, str], None] | None = None
) -> list[PacketRecord]:
    """
    Parses a PCAP/PCAPNG file using PyShark with streaming iteration.
    Guarantees cleanup of capture resources.
    """
    import pyshark
    import asyncio
    import os

    # Ensure an active Proactor event loop exists for PyShark on Windows
    try:
        loop = asyncio.get_event_loop()
        if os.name == "nt" and not isinstance(loop, asyncio.ProactorEventLoop):
            loop = asyncio.ProactorEventLoop()
            asyncio.set_event_loop(loop)
    except Exception:
        loop = asyncio.ProactorEventLoop() if os.name == "nt" else asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    try:
        import nest_asyncio
        nest_asyncio.apply(loop)
    except Exception:
        pass

    from core.pcap_loader import resolve_tshark_path
    tshark_exec = resolve_tshark_path(config.tshark_path) or config.tshark_path
    records: list[PacketRecord] = []
    packet_idx = 1

    capture = None
    try:
        logger.info("Opening capture with PyShark: %s (tshark: %s)", file_path, tshark_exec)
        capture = pyshark.FileCapture(
            file_path,
            tshark_path=tshark_exec,
            eventloop=loop,
            keep_packets=False,
            use_json=False,
            include_raw=False
        )

        for raw_packet in capture:
            if packet_idx > config.max_packets_limit:
                logger.warning("Reached maximum packet budget limit (%d). Stopping parse.", config.max_packets_limit)
                break

            try:
                rec = _normalise_pyshark_packet(raw_packet, packet_idx)
                records.append(rec)
            except Exception as exc:
                logger.warning("Failed to parse packet #%d: %s", packet_idx, exc)

            if progress_callback and packet_idx % 100 == 0:
                progress_callback(packet_idx, f"Parsed {packet_idx} packets...")

            packet_idx += 1

    finally:
        if capture is not None:
            try:
                capture.close()
            except Exception:
                pass

    logger.info("Parsing complete. Total packets converted: %d", len(records))
    return records
