"""
Streamlit session state management for NetSleuth.
Ensures session isolation and preserves analysis state across navigation transitions.
"""

from __future__ import annotations

import streamlit as st
from core.models import AnalysisResult


def init_session() -> None:
    """Initializes session state defaults."""
    if "analysis_result" not in st.session_state:
        st.session_state["analysis_result"] = None
    if "selected_packet_number" not in st.session_state:
        st.session_state["selected_packet_number"] = None
    if "packet_filter_ip" not in st.session_state:
        st.session_state["packet_filter_ip"] = ""
    if "packet_filter_protocol" not in st.session_state:
        st.session_state["packet_filter_protocol"] = "All"


def get_current_analysis() -> AnalysisResult | None:
    return st.session_state.get("analysis_result")


def set_current_analysis(res: AnalysisResult | None) -> None:
    st.session_state["analysis_result"] = res


def set_selected_packet(pkt_num: int | None) -> None:
    st.session_state["selected_packet_number"] = pkt_num
