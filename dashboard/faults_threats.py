"""
Network Faults & Security Threats deep-dive views.
Displays findings with evidence packets, cautious diagnostic explanations, and limitations.
"""

from __future__ import annotations

import streamlit as st

from analysis.confidence import format_confidence_label
from analysis.severity import get_severity_badge_color
from dashboard.session import get_current_analysis, set_selected_packet


def render_faults_threats_page() -> None:
    st.title("Diagnostic Findings: Faults & Security Threats")
    st.caption("Evidence-backed detections categorized by operational faults and suspicious patterns.")

    res = get_current_analysis()
    if not res:
        st.info("No active capture analysis found. Please upload or select a capture on the Overview page first.")
        return

    tab_faults, tab_threats = st.tabs(["Network Faults", "Security & Suspicious Threats"])

    # 1. Network Faults
    with tab_faults:
        faults = [f for f in res.findings if f.category == "NETWORK_FAULT"]
        st.markdown(f"**Identified {len(faults)} Network Fault Finding(s)**")

        if not faults:
            st.success("No operational network faults detected in this capture window.")
        else:
            for f in faults:
                _render_finding_card(f)

    # 2. Security Threats
    with tab_threats:
        threats = [f for f in res.findings if f.category == "SECURITY"]
        st.markdown(f"**Identified {len(threats)} Security / Suspicious Threat Finding(s)**")

        if not threats:
            st.success("No suspicious attack patterns or reconnaissance sweeps detected in this capture.")
        else:
            for f in threats:
                _render_finding_card(f)


def _render_finding_card(f) -> None:
    badge_color = get_severity_badge_color(f.severity)
    conf_label = format_confidence_label(f.confidence)

    with st.container(border=True):
        col1, col2, col3 = st.columns([3, 1, 1])
        with col1:
            st.markdown(f"### {f.title}")
            st.caption(f"ID: `{f.finding_id}` | Type: `{f.type}` | Classification: `{f.classification}`")
        with col2:
            st.markdown(
                f"<div style='background-color:{badge_color};color:white;padding:4px 8px;border-radius:4px;text-align:center;font-weight:bold;'>{f.severity}</div>",
                unsafe_allow_html=True
            )
        with col3:
            st.markdown(
                f"<div style='background-color:#eceff1;color:#37474f;padding:4px 8px;border-radius:4px;text-align:center;font-size:0.85em;'>{conf_label}</div>",
                unsafe_allow_html=True
            )

        st.markdown(f"**Observed Facts / Condition:**  \n{f.reason}")
        st.markdown(f"**Likely Cause:**  \n{f.likely_cause}")

        st.markdown("**Alternative Benign Explanations:**")
        for alt in f.alternative_explanations:
            st.markdown(f"- {alt}")

        st.markdown(f"**Recommended Actionable Steps:**  \n{f.recommendation}")

        with st.expander("Technical Evidence & PCAP Limitations"):
            st.markdown(f"**Endpoints:** `{f.source_ip or 'Any'}` → `{f.destination_ip or 'Any'}`")
            st.markdown(f"**Measured Metrics:** `{f.metrics}`")
            st.markdown(f"**Supporting Packet Numbers:** `{', '.join(map(str, f.evidence_packets))}`")

            # Jump-to-evidence button for primary packet
            if f.evidence_packets:
                primary_pkt = f.evidence_packets[0]
                if st.button(f"Inspect Packet #{primary_pkt} in Packet Explorer", key=f"btn_{f.finding_id}"):
                    set_selected_packet(primary_pkt)
                    st.info(
                        f"Packet **#{primary_pkt}** selected as the inspection target. "
                        "Navigate to **Packet Explorer** in the left sidebar to view the full field breakdown."
                    )

            st.markdown("**Explicit PCAP Limitations:**")
            for lim in f.limitations:
                st.markdown(f"- *{lim}*")
