"""
Central detector runner and orchestration registry.
Runs all enabled detectors against normalized data with exception isolation.
"""

from __future__ import annotations

import logging
from typing import Mapping, Sequence

from core.config import AppConfig, DEFAULT_CONFIG
from core.models import Finding, FlowRecord, HostProfile, PacketRecord
from detectors.arp_analysis import ARPAnalysisDetector
from detectors.base import BaseDetector
from detectors.dhcp_analysis import DHCPAnalysisDetector
from detectors.dns_faults import DNSFaultDetector
from detectors.mtu_icmp import MTUICMPDetector
from detectors.port_scan import PortScanDetector
from detectors.tcp_faults import TCPFaultDetector

logger = logging.getLogger(__name__)


class DetectorRegistry:
    """
    Registry and runner for all NetSleuth detectors.
    """

    def __init__(self, config: AppConfig = DEFAULT_CONFIG) -> None:
        self.config = config
        self.detectors: list[BaseDetector] = [
            TCPFaultDetector(config),
            DNSFaultDetector(config),
            ARPAnalysisDetector(config),
            PortScanDetector(config),
            MTUICMPDetector(config),
            DHCPAnalysisDetector(config),
        ]

    def register_detector(self, detector: BaseDetector) -> None:
        self.detectors.append(detector)

    def run_all(
        self,
        packets: Sequence[PacketRecord],
        flows: Mapping[str, FlowRecord],
        hosts: Mapping[str, HostProfile]
    ) -> list[Finding]:
        all_findings: list[Finding] = []

        for detector in self.detectors:
            try:
                logger.info("Running detector: %s", detector.detector_name)
                res = detector.analyze(packets, flows, hosts)
                logger.info("Detector %s produced %d finding(s)", detector.detector_name, len(res))
                all_findings.extend(res)
            except Exception as exc:
                logger.error("Detector %s raised unexpected exception: %s", detector.detector_name, exc, exc_info=True)

        # Sort findings by start_time
        all_findings.sort(key=lambda f: f.start_time)
        return all_findings
