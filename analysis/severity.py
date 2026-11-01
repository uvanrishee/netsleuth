"""
Severity calculation engine for NetSleuth.
Estimates potential operational or security impact using explicit, transparent rules.
Severity is strictly separated from evidence confidence.
"""

from __future__ import annotations

from typing import Literal

SeverityLevel = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

SEVERITY_ORDER: dict[SeverityLevel, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def compare_severity(s1: str, s2: str) -> int:
    """Returns positive if s1 > s2, negative if s1 < s2, 0 if equal."""
    v1 = SEVERITY_ORDER.get(s1.upper(), 0)  # type: ignore[arg-type]
    v2 = SEVERITY_ORDER.get(s2.upper(), 0)  # type: ignore[arg-type]
    return v1 - v2


def get_severity_badge_color(severity: str) -> str:
    """Returns Hex color code for UI badges."""
    s = severity.upper()
    if s == "CRITICAL":
        return "#d32f2f"  # Red
    if s == "HIGH":
        return "#f57c00"  # Orange
    if s == "MEDIUM":
        return "#fbc02d"  # Amber/Yellow
    if s == "LOW":
        return "#1976d2"  # Blue
    return "#757575"       # Grey
