"""
DNS Fault & Anomaly Detectors:
1. DNS Failure Codes (NXDOMAIN, SERVFAIL, REFUSED)
2. Unanswered DNS Queries (with observation window caveat)
3. DNS Response Latency (> 500ms)
4. DNS Response Inconsistencies (manipulation/hijack clues)
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Mapping, Sequence

from core.config import AppConfig, DEFAULT_CONFIG
from core.models import Finding, FlowRecord, HostProfile, PacketRecord
from detectors.base import BaseDetector

logger = logging.getLogger(__name__)

RCODE_NAMES = {
    1: "FORMERR (Format Error)",
    2: "SERVFAIL (Server Failure)",
    3: "NXDOMAIN (Non-Existent Domain)",
    4: "NOTIMP (Not Implemented)",
    5: "REFUSED (Query Refused)"
}


class DNSFaultDetector(BaseDetector):
    """
    Detects DNS resolution errors, unanswered queries, excessive latency, and answer discrepancies.
    """

    @property
    def detector_name(self) -> str:
        return "DNS Fault & Anomaly Detector"

    def analyze(
        self,
        packets: Sequence[PacketRecord],
        flows: Mapping[str, FlowRecord],
        hosts: Mapping[str, HostProfile]
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Collect DNS packets
        queries: dict[tuple[int, str, str, str], list[PacketRecord]] = defaultdict(list)
        responses: dict[tuple[int, str, str, str], list[PacketRecord]] = defaultdict(list)
        all_dns_packets: list[PacketRecord] = []

        for pkt in packets:
            if pkt.dns_id is not None and pkt.src_ip and pkt.dst_ip:
                all_dns_packets.append(pkt)
                qname = (pkt.dns_query_name or "").lower().rstrip(".")
                if pkt.dns_is_response is False:
                    # Key: (dns_id, client_ip, server_ip, query_name)
                    queries[(pkt.dns_id, pkt.src_ip, pkt.dst_ip, qname)].append(pkt)
                elif pkt.dns_is_response is True:
                    # Key reversed: (dns_id, client_ip, server_ip, query_name)
                    responses[(pkt.dns_id, pkt.dst_ip, pkt.src_ip, qname)].append(pkt)

        # 1. Match queries with responses
        unanswered_queries: list[PacketRecord] = []
        slow_responses: list[tuple[PacketRecord, PacketRecord, float]] = []
        error_responses: list[tuple[PacketRecord, PacketRecord | None, int]] = []
        name_to_answers: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

        for key, q_list in queries.items():
            dns_id, client_ip, server_ip, qname = key
            q_pkt = q_list[0]

            if key in responses:
                resp_pkts = responses[key]
                r_pkt = resp_pkts[0]
                latency_ms = (r_pkt.timestamp - q_pkt.timestamp) * 1000.0

                if latency_ms >= self.config.dns_slow_response_threshold_ms:
                    slow_responses.append((q_pkt, r_pkt, latency_ms))

                # Check response code
                rcode = r_pkt.dns_response_code
                if rcode and rcode in RCODE_NAMES:
                    error_responses.append((r_pkt, q_pkt, rcode))

                # Track answers for discrepancy check
                if r_pkt.dns_answers:
                    for ans in r_pkt.dns_answers:
                        name_to_answers[qname][server_ip].add(ans)
            else:
                unanswered_queries.extend(q_list)

        # Also catch standalone error responses without captured query
        for key, r_list in responses.items():
            if key not in queries:
                for r_pkt in r_list:
                    rcode = r_pkt.dns_response_code
                    if rcode and rcode in RCODE_NAMES:
                        error_responses.append((r_pkt, None, rcode))

        # Generate Findings
        finding_counter = 1

        # A. DNS Errors (NXDOMAIN, SERVFAIL, etc.)
        errors_by_domain: dict[tuple[str, int], list[tuple[PacketRecord, PacketRecord | None]]] = defaultdict(list)
        for r_pkt, q_pkt, rcode in error_responses:
            qname = (r_pkt.dns_query_name or "unknown").lower()
            errors_by_domain[(qname, rcode)].append((r_pkt, q_pkt))

        for (domain, rcode), pair_list in errors_by_domain.items():
            rcode_desc = RCODE_NAMES.get(rcode, f"Code {rcode}")
            evidence = []
            for r_p, q_p in pair_list:
                if q_p:
                    evidence.append(q_p.packet_number)
                evidence.append(r_p.packet_number)

            client = pair_list[0][0].dst_ip
            resolver = pair_list[0][0].src_ip
            f_id = f"F-DNS-ERR-{finding_counter:03d}"
            finding_counter += 1

            findings.append(Finding(
                finding_id=f_id,
                category="NETWORK_FAULT",
                type="DNS_FAILURE",
                title=f"DNS {rcode_desc} for domain '{domain}'",
                classification="OBSERVATION",
                severity="HIGH" if rcode == 2 else "MEDIUM",  # SERVFAIL is severe, NXDOMAIN medium
                confidence=0.95,
                source_ip=client,
                destination_ip=resolver,
                source_port=pair_list[0][0].dst_port,
                destination_port=pair_list[0][0].src_port,
                affected_hosts=[h for h in (client, resolver) if h],
                flow_ids=[],
                start_time=pair_list[0][0].timestamp,
                end_time=pair_list[-1][0].timestamp,
                metrics={
                    "domain": domain,
                    "response_code": rcode,
                    "response_name": rcode_desc,
                    "occurrences": len(pair_list)
                },
                evidence_packets=evidence[:10],
                reason=f"Resolver {resolver} returned {rcode_desc} for query '{domain}' across {len(pair_list)} request(s).",
                likely_cause="Domain does not exist or authorative nameserver failed to resolve recursive records (SERVFAIL).",
                alternative_explanations=[
                    "Client mistyped the domain name (typo in configuration)",
                    "Temporary upstream nameserver synchronization delay",
                    "DNS filtering / sinkhole policy enforced by upstream network resolver"
                ],
                recommendation=f"Verify domain name spelling in application config, check resolver connectivity, and query authorative nameservers directly with `dig` or `nslookup`.",
                limitations=[
                    "PCAP reveals the resolver's response code but cannot inspect upstream authoritative nameserver state."
                ]
            ))

        # B. Unanswered DNS Queries
        if unanswered_queries:
            unanswered_by_client: dict[tuple[str, str], list[PacketRecord]] = defaultdict(list)
            for q in unanswered_queries:
                unanswered_by_client[(q.src_ip or "unknown", q.dst_ip or "unknown")].append(q)

            for (client, resolver), q_list in unanswered_by_client.items():
                evidence = [q.packet_number for q in q_list]
                domains = list({q.dns_query_name for q in q_list if q.dns_query_name})
                f_id = f"F-DNS-UNANS-{finding_counter:03d}"
                finding_counter += 1

                findings.append(Finding(
                    finding_id=f_id,
                    category="NETWORK_FAULT",
                    type="DNS_UNANSWERED",
                    title=f"Unanswered DNS Queries ({client} -> {resolver})",
                    classification="OBSERVATION",
                    severity="MEDIUM",
                    confidence=0.8,
                    source_ip=client,
                    destination_ip=resolver,
                    source_port=q_list[0].src_port,
                    destination_port=q_list[0].dst_port,
                    affected_hosts=[client, resolver],
                    flow_ids=[],
                    start_time=q_list[0].timestamp,
                    end_time=q_list[-1].timestamp,
                    metrics={
                        "unanswered_query_count": len(q_list),
                        "queried_domains": domains[:5]
                    },
                    evidence_packets=evidence[:10],
                    reason=f"Observed {len(q_list)} DNS query requests from {client} to {resolver} with no matching response in capture window.",
                    likely_cause="DNS resolver is unreachable, UDP packets dropped by firewall, or DNS service inactive.",
                    alternative_explanations=[
                        "Capture ended before resolver response arrived",
                        "Asymmetric network routing where response bypassed the monitoring capture point",
                        "High UDP packet drop on congested local interface"
                    ],
                    recommendation="Verify resolver IP configuration on the client host, test UDP/53 reachability, and check server logs.",
                    limitations=[
                        "No matching response was observed within the capture window; this does not prove the resolver was permanently down."
                    ]
                ))

        # C. Slow DNS Responses
        for q_p, r_p, latency in slow_responses:
            f_id = f"F-DNS-LAT-{finding_counter:03d}"
            finding_counter += 1

            findings.append(Finding(
                finding_id=f_id,
                category="NETWORK_FAULT",
                type="DNS_HIGH_LATENCY",
                title=f"Slow DNS Response ({latency:.0f} ms for '{q_p.dns_query_name}')",
                classification="OBSERVATION",
                severity="LOW",
                confidence=0.9,
                source_ip=q_p.src_ip,
                destination_ip=q_p.dst_ip,
                source_port=q_p.src_port,
                destination_port=q_p.dst_port,
                affected_hosts=[h for h in (q_p.src_ip, q_p.dst_ip) if h],
                flow_ids=[],
                start_time=q_p.timestamp,
                end_time=r_p.timestamp,
                metrics={
                    "latency_ms": round(latency, 2),
                    "threshold_ms": self.config.dns_slow_response_threshold_ms,
                    "domain": q_p.dns_query_name
                },
                evidence_packets=[q_p.packet_number, r_p.packet_number],
                reason=f"DNS query took {latency:.0f} ms to receive a response, exceeding the {self.config.dns_slow_response_threshold_ms:.0f} ms threshold.",
                likely_cause="Resolver recursing through slow or distant authoritative servers, or resolver CPU overload.",
                alternative_explanations=[
                    "Cold cache miss requiring root-to-TLD recursive lookups",
                    "WAN/satellite link latency"
                ],
                recommendation="Investigate recursive resolver caching policies and test internal cache hit ratios.",
                limitations=[
                    "Measured round-trip time includes capture delay and network propagation."
                ]
            ))

        # D. DNS Response Inconsistencies / Manipulation Indicators
        for qname, resolver_answers in name_to_answers.items():
            if len(resolver_answers) > 1:
                # Compare answers from multiple resolvers
                all_sets = list(resolver_answers.values())
                if len(all_sets) >= 2 and all_sets[0] != all_sets[1]:
                    f_id = f"F-DNS-ANOM-{finding_counter:03d}"
                    finding_counter += 1

                    resolvers = list(resolver_answers.keys())
                    findings.append(Finding(
                        finding_id=f_id,
                        category="SECURITY",
                        type="DNS_RESPONSE_ANOMALY",
                        title=f"Inconsistent DNS Answers for '{qname}' Across Resolvers",
                        classification="SUSPICIOUS_ACTIVITY",
                        severity="MEDIUM",
                        confidence=0.7,
                        source_ip=resolvers[0],
                        destination_ip=resolvers[1] if len(resolvers) > 1 else None,
                        source_port=None,
                        destination_port=None,
                        affected_hosts=resolvers,
                        flow_ids=[],
                        start_time=all_dns_packets[0].timestamp if all_dns_packets else 0.0,
                        end_time=all_dns_packets[-1].timestamp if all_dns_packets else 0.0,
                        metrics={
                            "domain": qname,
                            "resolver_answers": {r: list(ans) for r, ans in resolver_answers.items()}
                        },
                        evidence_packets=[p.packet_number for p in all_dns_packets if p.dns_query_name == qname][:10],
                        reason=f"Different resolvers provided conflicting IP addresses for '{qname}'.",
                        likely_cause="Different DNS resolvers returning geographically localized CDN IPs or split-horizon DNS.",
                        alternative_explanations=[
                            "Content Delivery Network (CDN) GeoDNS routing",
                            "Round-robin DNS rotation",
                            "Split-horizon DNS (internal vs external view)",
                            "Possible rogue resolver or DNS poisoning/manipulation attempt"
                        ],
                        recommendation="Compare resolver configurations and verify whether the resolved IP addresses belong to authorized CDNs or hosting providers.",
                        limitations=[
                            "Differing DNS answers do not prove malicious DNS hijacking without baseline validation."
                        ]
                    ))

        return findings
