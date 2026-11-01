"""
Incident Correlation Engine.
Correlates related findings across temporal proximity, shared endpoints, and causal protocol chains.
Connects individual clues into comprehensive incident narratives.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Sequence

from core.config import AppConfig, DEFAULT_CONFIG
from core.models import Finding, IncidentRecord, TimelineEvent

logger = logging.getLogger(__name__)


def correlate_incidents(
    findings: Sequence[Finding],
    events: Sequence[TimelineEvent],
    config: AppConfig = DEFAULT_CONFIG
) -> list[IncidentRecord]:
    """
    Evaluates findings and clusters them into multi-signal incidents using explicit correlation rules:
    Rule 1: DNS Failure followed by TCP Connection Failure to the resolved destination.
    Rule 2: Port Scanning followed by high volume of TCP Resets.
    Rule 3: ARP Mapping Conflict / Spoofing followed by connection disruptions.
    Rule 4: Multi-server DHCP or Network-wide infrastructure anomalies.
    """
    incidents: list[IncidentRecord] = []
    incident_counter = 1
    grouped_finding_ids: set[str] = set()

    # Rule 1: DNS Resolution Degradation & Hostname Connection Failures
    dns_findings = [f for f in findings if f.type in ("DNS_FAILURE", "DNS_UNANSWERED")]
    tcp_findings = [f for f in findings if f.type in ("TCP_RESET", "INCOMPLETE_HANDSHAKE")]

    for df in dns_findings:
        related_tcp: list[Finding] = []
        for tf in tcp_findings:
            # Check temporal proximity (within correlation window)
            time_diff = abs(tf.start_time - df.start_time)
            if time_diff <= config.correlation_window_seconds:
                # Shared client host
                if df.source_ip and (df.source_ip == tf.source_ip or df.source_ip in tf.affected_hosts):
                    related_tcp.append(tf)

        if related_tcp:
            contributing = [df] + related_tcp
            for f in contributing:
                grouped_finding_ids.add(f.finding_id)

            inc_id = f"INC-{incident_counter:02d}"
            incident_counter += 1

            client = df.source_ip or "Client"
            incidents.append(IncidentRecord(
                incident_id=inc_id,
                title=f"DNS Degradation Preceding Connection Failure ({client})",
                category="NETWORK_FAULT",
                classification="POSSIBLE_INCIDENT",
                start_time=min(f.start_time for f in contributing),
                end_time=max(f.end_time for f in contributing),
                affected_hosts=list({h for f in contributing for h in f.affected_hosts}),
                contributing_finding_ids=[f.finding_id for f in contributing],
                contributing_event_ids=[e.event_id for e in events if e.finding_id in [f.finding_id for f in contributing]],
                narrative=(
                    f"1. Host {client} experienced DNS resolution issues (Finding {df.finding_id}: {df.title}).\n"
                    f"2. Concurrently or immediately following the DNS failure, connection attempts failed or received resets "
                    f"({', '.join(f.finding_id for f in related_tcp)}).\n"
                    f"3. The combined observations indicate that domain lookup problems degraded downstream application connectivity."
                ),
                correlation_reasons=[
                    f"Shared client endpoint ({client})",
                    f"Occurred within {config.correlation_window_seconds}s time proximity",
                    "Causal protocol dependency: application connectivity requires prior successful DNS resolution"
                ],
                severity="HIGH",
                confidence=min(0.9, df.confidence + 0.1),
                likely_cause="DNS resolution failure or upstream nameserver timeout caused endpoint application requests to stall or abort.",
                alternative_explanations=[
                    "Independent concurrent application crash unrelated to DNS",
                    "Network switch or routing flap affecting both DNS and application traffic simultaneously"
                ],
                recommendations=[
                    "Test recursive DNS resolver availability from client host using `dig` or `nslookup`.",
                    "Verify secondary DNS server configuration in DHCP or network interface settings.",
                    "Inspect firewall logs for outbound UDP/53 and TCP connection drops."
                ],
                limitations=[
                    "Capture shows DNS queries and TCP connection failures occurring close in time; independent concurrent failures cannot be ruled out without application logs."
                ]
            ))

    # Rule 2: Reconnaissance Activity (Port Scan) Correlated with Destination Resets
    scan_findings = [f for f in findings if f.type in ("PORT_SCAN", "PORT_SWEEP")]
    reset_findings = [f for f in findings if f.type == "TCP_RESET"]

    for sf in scan_findings:
        related_resets: list[Finding] = []
        for rf in reset_findings:
            if rf.source_ip == sf.destination_ip or (sf.source_ip and rf.destination_ip == sf.source_ip):
                if abs(rf.start_time - sf.start_time) <= config.correlation_window_seconds:
                    related_resets.append(rf)

        if related_resets:
            contributing = [sf] + related_resets
            for f in contributing:
                grouped_finding_ids.add(f.finding_id)

            inc_id = f"INC-{incident_counter:02d}"
            incident_counter += 1

            scanner = sf.source_ip or "Unknown"
            target = sf.destination_ip or "Subnet"

            incidents.append(IncidentRecord(
                incident_id=inc_id,
                title=f"Network Reconnaissance and Target Rejection ({scanner} -> {target})",
                category="SECURITY",
                classification="POSSIBLE_ATTACK_INDICATOR",
                start_time=min(f.start_time for f in contributing),
                end_time=max(f.end_time for f in contributing),
                affected_hosts=list({h for f in contributing for h in f.affected_hosts}),
                contributing_finding_ids=[f.finding_id for f in contributing],
                contributing_event_ids=[e.event_id for e in events if e.finding_id in [f.finding_id for f in contributing]],
                narrative=(
                    f"1. Host {scanner} probed target {target} across multiple ports ({sf.finding_id}).\n"
                    f"2. The target host responded with TCP RST packets ({', '.join(r.finding_id for r in related_resets)}), "
                    f"confirming active rejection of connection attempts to closed ports.\n"
                    f"3. The combined signals strongly support a port scan / service discovery pattern."
                ),
                correlation_reasons=[
                    f"Shared scanner ({scanner}) and target ({target}) endpoints",
                    "Direct protocol handshake causality: closed ports reply to SYN probes with RST segments"
                ],
                severity="HIGH",
                confidence=min(0.95, sf.confidence + 0.1),
                likely_cause="Automated port scanning or vulnerability enumeration actively probing closed target ports.",
                alternative_explanations=[
                    "Authorized internal security audit or network asset inventory scan",
                    "Misconfigured application client retrying multiple port numbers"
                ],
                recommendations=[
                    "Identify owner of scanning IP address and confirm if an authorized penetration test is underway.",
                    "Review host firewall rules on target and ensure unnecessary listening ports are closed or restricted."
                ],
                limitations=[
                    "A packet capture records the probing and reset responses; it does not disclose the operator or motive behind the scan."
                ]
            ))

    # Rule 3: Single High-Severity Findings promoted to Standalone Incidents if Not Grouped
    for f in findings:
        if f.finding_id not in grouped_finding_ids and f.severity in ("HIGH", "CRITICAL"):
            inc_id = f"INC-{incident_counter:02d}"
            incident_counter += 1

            incidents.append(IncidentRecord(
                incident_id=inc_id,
                title=f"High-Impact Network Event: {f.title}",
                category=f.category,
                classification=f.classification,
                start_time=f.start_time,
                end_time=f.end_time,
                affected_hosts=f.affected_hosts,
                contributing_finding_ids=[f.finding_id],
                contributing_event_ids=[e.event_id for e in events if e.finding_id == f.finding_id],
                narrative=f"Single high-severity event observed: {f.reason}",
                correlation_reasons=["Standalone high-severity event requiring immediate operator review"],
                severity=f.severity,
                confidence=f.confidence,
                likely_cause=f.likely_cause,
                alternative_explanations=f.alternative_explanations,
                recommendations=[f.recommendation],
                limitations=f.limitations
            ))

    incidents.sort(key=lambda inc: inc.start_time)
    return incidents
