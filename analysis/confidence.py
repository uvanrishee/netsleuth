"""
Confidence scoring engine for NetSleuth.
Estimates heuristic evidence strength (0.0 to 1.0).
Strictly decoupled from severity.
"""

from __future__ import annotations


def calculate_evidence_confidence(
    evidence_packet_count: int,
    has_bidirectional_context: bool,
    has_repeated_observations: bool,
    boundary_ambiguity: bool = False
) -> float:
    """
    Computes a heuristic confidence score based on observable capture evidence.
    """
    score = 0.5

    # More packets increase confidence
    if evidence_packet_count >= 10:
        score += 0.2
    elif evidence_packet_count >= 3:
        score += 0.1

    # Bidirectional confirmation
    if has_bidirectional_context:
        score += 0.15

    # Repetition / recurrence
    if has_repeated_observations:
        score += 0.1

    # Boundary penalties (e.g. capture truncated mid-flow)
    if boundary_ambiguity:
        score -= 0.2

    return max(0.1, min(0.99, round(score, 2)))


def format_confidence_label(score: float) -> str:
    """Returns human-friendly confidence category."""
    if score >= 0.85:
        return f"High Confidence ({score:.0%})"
    if score >= 0.60:
        return f"Moderate Confidence ({score:.0%})"
    return f"Low / Tentative ({score:.0%})"
