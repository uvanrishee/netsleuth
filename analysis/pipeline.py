"""
End-to-end analysis pipeline orchestration.
Coordinates parsing, flow aggregation, host profiling, detection, timeline building, and correlation.
"""

from __future__ import annotations

import logging
import os
from collections import Counter
from typing import Callable

from analysis.event_builder import build_timeline_events
from analysis.incident_correlator import correlate_incidents
from core.config import AppConfig, DEFAULT_CONFIG
from core.flow_tracker import build_flows
from core.host_profiler import build_host_profiles
from core.models import AnalysisResult, PacketRecord
from core.packet_parser import parse_pcap_file
from detectors.runner import DetectorRegistry

logger = logging.getLogger(__name__)


def run_pipeline(
    file_path: str,
    original_filename: str | None = None,
    config: AppConfig = DEFAULT_CONFIG,
    progress_callback: Callable[[float, str], None] | None = None
) -> AnalysisResult:
    """
    Executes the complete NetSleuth analysis chain:
    PCAP -> Normalisation -> Flow/Host Aggregation -> Detectors -> Events -> Correlation.
    """
    display_name = original_filename or os.path.basename(file_path)
    file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

    if progress_callback:
        progress_callback(0.1, "Initializing packet decoder...")

    # Step 1: Decode & Normalise Packets
    def _parser_progress(count: int, msg: str) -> None:
        if progress_callback:
            # 10% to 50% for parsing
            progress_callback(min(0.5, 0.1 + (count / 2000.0) * 0.4), msg)

    packets: list[PacketRecord] = parse_pcap_file(
        file_path, config, progress_callback=_parser_progress
    )

    if not packets:
        return AnalysisResult(
            filename=display_name,
            file_size_bytes=file_size,
            capture_start_time=0.0,
            capture_end_time=0.0,
            duration_seconds=0.0,
            total_packets_read=0,
            packets=[],
            flows={},
            hosts={},
            findings=[],
            events=[],
            incidents=[],
            protocol_counts={},
            warnings=["No packets could be parsed or capture file is empty."]
        )

    if progress_callback:
        progress_callback(0.55, "Aggregating flows and profiling endpoints...")

    # Step 2: Flow & Host Aggregation
    flows = build_flows(packets)
    hosts = build_host_profiles(packets, flows)

    if progress_callback:
        progress_callback(0.70, "Executing original detection engine...")

    # Step 3: Run Detection Engine
    registry = DetectorRegistry(config)
    findings = registry.run_all(packets, flows, hosts)

    if progress_callback:
        progress_callback(0.85, "Building chronological event timeline...")

    # Step 4: Event Timeline Generation
    events = build_timeline_events(packets, findings)

    if progress_callback:
        progress_callback(0.92, "Correlating multi-signal incidents...")

    # Step 5: Incident Correlation
    incidents = correlate_incidents(findings, events, config)

    # Step 6: Protocol Distribution & Metadata
    proto_counter: Counter[str] = Counter()
    for p in packets:
        proto = p.transport_protocol or p.highest_layer or "Other"
        proto_counter[proto] += 1

    start_ts = min(p.timestamp for p in packets)
    end_ts = max(p.timestamp for p in packets)
    duration = max(0.0, end_ts - start_ts)

    if progress_callback:
        progress_callback(1.0, "Analysis complete!")

    logger.info(
        "Pipeline finished: %d packets, %d flows, %d hosts, %d findings, %d incidents",
        len(packets), len(flows), len(hosts), len(findings), len(incidents)
    )

    return AnalysisResult(
        filename=display_name,
        file_size_bytes=file_size,
        capture_start_time=start_ts,
        capture_end_time=end_ts,
        duration_seconds=round(duration, 3),
        total_packets_read=len(packets),
        packets=packets,
        flows=flows,
        hosts=hosts,
        findings=findings,
        events=events,
        incidents=incidents,
        protocol_counts=dict(proto_counter.most_common()),
        warnings=[]
    )
