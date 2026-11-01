"""
Core data contracts and shared models for NetSleuth.
All layers communicate via these strongly typed, normalized records.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PacketRecord:
    """
    Normalized representation of a single captured packet.
    Missing fields must be None (never exceptions).
    """
    packet_number: int                 # 1-based sequential capture index
    timestamp: float                   # Epoch seconds (float)
    timestamp_iso: str                 # Formatted ISO timestamp (UTC or local)
    captured_length: int
    reported_length: int
    highest_layer: str
    protocol_stack: tuple[str, ...]

    # Layer 2 (Data Link)
    src_mac: str | None = None
    dst_mac: str | None = None

    # Layer 3 (Network)
    src_ip: str | None = None
    dst_ip: str | None = None
    ip_version: int | None = None
    ttl: int | None = None
    ip_id: int | None = None
    fragment_offset: int | None = None
    more_fragments: bool | None = None

    # Layer 4 (Transport)
    transport_protocol: str | None = None  # "TCP", "UDP", "ICMP", "ARP", etc.
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: dict[str, bool] | None = None  # {"SYN": True, "ACK": False, ...}
    tcp_seq: int | None = None
    tcp_ack: int | None = None
    tcp_payload_length: int | None = None

    # DNS
    dns_id: int | None = None
    dns_is_response: bool | None = None
    dns_query_name: str | None = None
    dns_query_type: str | None = None
    dns_response_code: int | None = None
    dns_answers: tuple[str, ...] = ()

    # ARP
    arp_operation: str | None = None  # "REQUEST", "REPLY"
    arp_sender_ip: str | None = None
    arp_sender_mac: str | None = None
    arp_target_ip: str | None = None
    arp_target_mac: str | None = None

    # DHCP / BOOTP
    dhcp_message_type: str | None = None
    dhcp_server_id: str | None = None
    dhcp_client_mac: str | None = None
    dhcp_offered_ip: str | None = None

    # ICMP
    icmp_type: int | None = None
    icmp_code: int | None = None
    icmp_mtu: int | None = None

    # Warnings / anomalies encountered during decode
    parse_warnings: tuple[str, ...] = ()


@dataclass
class FlowRecord:
    """
    Bidirectional flow record representing a conversation between two endpoints.
    """
    flow_id: str                       # Canonical key: "TCP:10.0.0.1:80<->10.0.0.2:50000"
    protocol: str                      # "TCP", "UDP"
    endpoint_a: tuple[str, int]        # (ip, port) canonically sorted
    endpoint_b: tuple[str, int]        # (ip, port) canonically sorted
    start_time: float
    end_time: float
    packet_count: int = 0
    byte_count: int = 0
    packets_a_to_b: int = 0
    packets_b_to_a: int = 0
    bytes_a_to_b: int = 0
    bytes_b_to_a: int = 0
    tcp_flags_summary: dict[str, int] = field(default_factory=dict)
    evidence_packets: list[int] = field(default_factory=list)
    state_summary: str = "ESTABLISHED"


@dataclass
class HostProfile:
    """
    Observed host-level summary.
    """
    ip_address: str
    mac_addresses: set[str] = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0
    packet_count: int = 0
    byte_count: int = 0
    protocols_used: set[str] = field(default_factory=set)
    ports_contacted: set[int] = field(default_factory=set)
    peers: set[str] = field(default_factory=set)
    associated_flow_ids: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """
    Unified output format returned by every detector module.
    """
    finding_id: str                    # Unique ID (e.g. "F-TCP-001")
    category: str                      # "NETWORK_FAULT" | "SECURITY" | "OBSERVATION"
    type: str                          # "TCP_RETRANSMISSION", "PORT_SCAN", etc.
    title: str
    classification: str                # "OBSERVATION", "SUSPICIOUS_ACTIVITY", "POSSIBLE_ATTACK_INDICATOR", etc.
    severity: str                      # "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    confidence: float                  # Heuristic evidence strength (0.0 to 1.0)
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    affected_hosts: list[str]
    flow_ids: list[str]
    start_time: float
    end_time: float
    metrics: dict[str, Any]            # Measured values triggering the detector
    evidence_packets: list[int]        # Real packet numbers in PCAP
    reason: str                        # Factual statement of condition met
    likely_cause: str                  # Cautiously phrased likely explanation
    alternative_explanations: list[str]# Benign or alternative causes
    recommendation: str                # Actionable next steps
    limitations: list[str]             # What PCAP cannot prove


@dataclass
class TimelineEvent:
    """
    Chronological event record for timeline visualization.
    """
    event_id: str
    timestamp: float
    timestamp_iso: str
    packet_number: int | None
    event_type: str                    # "DNS_QUERY", "TCP_SYN", "TCP_RST", "FAULT", etc.
    category: str                      # "FAULT", "SECURITY", "PROTOCOL"
    source: str
    destination: str
    protocol: str
    severity: str
    description: str
    finding_id: str | None = None
    evidence_packets: list[int] = field(default_factory=list)


@dataclass
class IncidentRecord:
    """
    Correlated multi-signal incident linking several findings.
    """
    incident_id: str                   # E.g. "INC-01"
    title: str
    category: str
    classification: str
    start_time: float
    end_time: float
    affected_hosts: list[str]
    contributing_finding_ids: list[str]
    contributing_event_ids: list[str]
    narrative: str                     # Step-by-step description of sequence
    correlation_reasons: list[str]     # Why grouped (e.g., shared IP, temporal correlation)
    severity: str
    confidence: float
    likely_cause: str
    alternative_explanations: list[str]
    recommendations: list[str]
    limitations: list[str]


@dataclass
class ValidationResult:
    """
    Result of uploaded file validation.
    """
    is_valid: bool
    error_message: str | None = None
    file_path: str | None = None
    file_size_bytes: int = 0
    file_type: str = "unknown"         # "pcap", "pcapng"


@dataclass
class AnalysisResult:
    """
    Complete container returned by analysis pipeline.
    """
    filename: str
    file_size_bytes: int
    capture_start_time: float
    capture_end_time: float
    duration_seconds: float
    total_packets_read: int
    packets: list[PacketRecord]
    flows: dict[str, FlowRecord]
    hosts: dict[str, HostProfile]
    findings: list[Finding]
    events: list[TimelineEvent]
    incidents: list[IncidentRecord]
    protocol_counts: dict[str, int]
    warnings: list[str]
