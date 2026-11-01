"""
Configuration settings and detection thresholds for NetSleuth.
All thresholds are centralized and documented here.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AppConfig:
    """
    Application-wide configuration parameters and detection thresholds.
    """
    # Environment & Paths
    tshark_path: str = field(
        default_factory=lambda: os.environ.get(
            "NETSLEUTH_TSHARK_PATH",
            r"C:\Program Files\Wireshark\tshark.exe" if os.name == "nt" else "tshark"
        )
    )

    # Ingestion & Resource Limits
    max_upload_size_bytes: int = 50 * 1024 * 1024  # 50 MB
    max_packets_limit: int = 100_000               # Bounded safety limit for interactive performance
    supported_extensions: tuple[str, ...] = (".pcap", ".pcapng")

    # TCP Detection Thresholds
    tcp_handshake_timeout_seconds: float = 3.0     # Time to wait for SYN-ACK and final ACK
    tcp_rst_burst_threshold: int = 3               # Resets in a flow/endpoint to consider a burst
    tcp_rst_burst_window_seconds: float = 5.0      # Window to count RST burst
    tcp_retransmission_min_ratio: float = 0.05     # 5% retransmission ratio in flow to flag
    tcp_retransmission_min_count: int = 3          # Minimum retransmissions to flag

    # DNS Detection Thresholds
    dns_timeout_seconds: float = 3.0               # Unanswered DNS timeout window
    dns_slow_response_threshold_ms: float = 500.0  # 500ms indicates slow DNS

    # Port Scan Detection Thresholds
    port_scan_window_seconds: float = 10.0         # Sliding window for scan detection
    vertical_scan_min_ports: int = 15              # Distinct ports on 1 target
    horizontal_scan_min_hosts: int = 8             # Same port on distinct targets

    # ARP & DHCP Thresholds
    arp_conflict_window_seconds: float = 60.0      # Window to correlate multiple MACs for single IP
    arp_gratuitous_burst_threshold: int = 5        # Unsolicited ARP announcements in window

    # Incident Correlation Thresholds
    correlation_window_seconds: float = 30.0       # Max time distance to group related findings

    # UI Pagination & Rendering
    packet_explorer_page_size: int = 100
    timeline_max_events_display: int = 1000


# Default global singleton config instance
DEFAULT_CONFIG = AppConfig()
