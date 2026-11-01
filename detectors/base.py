"""
Base detector interface for NetSleuth.
All detectors must inherit or follow this contract and return list[Finding].
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Mapping, Sequence

from core.config import AppConfig, DEFAULT_CONFIG
from core.models import Finding, FlowRecord, HostProfile, PacketRecord


class BaseDetector(ABC):
    """
    Abstract Base Class for all NetSleuth detectors.
    Detectors MUST NOT depend on Streamlit or presentation logic.
    """

    def __init__(self, config: AppConfig = DEFAULT_CONFIG) -> None:
        self.config = config

    @property
    @abstractmethod
    def detector_name(self) -> str:
        """Name of the detector for logging and reporting."""
        pass

    @abstractmethod
    def analyze(
        self,
        packets: Sequence[PacketRecord],
        flows: Mapping[str, FlowRecord],
        hosts: Mapping[str, HostProfile]
    ) -> list[Finding]:
        """
        Executes detection logic and returns findings following the unified schema.
        """
        pass
