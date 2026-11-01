"""
NetSleuth — Network Diagnosis & Incident Intelligence.
Main Streamlit application entry point using modern st.navigation.
"""

import streamlit as st

from core.pcap_loader import check_tshark_available
from dashboard.faults_threats import render_faults_threats_page
from dashboard.overview import render_overview_page
from dashboard.packet_explorer import render_packet_explorer_page
from dashboard.session import init_session
from dashboard.timeline import render_timeline_page
from dashboard.topology_reports import render_topology_reports_page

st.set_page_config(
    page_title="NetSleuth — Network Diagnosis",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize Session
init_session()

# Check TShark Runtime Status
tshark_ok, tshark_info = check_tshark_available()

# Define Pages with st.Page
p_overview = st.Page(
    render_overview_page,
    title="Overview",
    default=True,
    url_path="overview"
)
p_timeline = st.Page(
    render_timeline_page,
    title="Timeline & Incidents",
    url_path="timeline"
)
p_faults = st.Page(
    render_faults_threats_page,
    title="Faults & Threats",
    icon="⚠️",
    url_path="faults"
)
p_packets = st.Page(
    render_packet_explorer_page,
    title="Packet Explorer",
    url_path="packets"
)
p_topology = st.Page(
    render_topology_reports_page,
    title="Topology & Reports",
    url_path="topology"
)

# Modern Multipage Navigation
pg = st.navigation({
    "Diagnosis & Intelligence": [p_overview, p_timeline, p_faults],
    "Deep Inspection & Evidence": [p_packets, p_topology]
})

# Sidebar Info
st.sidebar.markdown("### **NetSleuth**")
st.sidebar.caption("v1.0 • Network Diagnosis & Intelligence")

if tshark_ok:
    st.sidebar.success("TShark Decoder Active")
else:
    st.sidebar.warning(f"TShark Missing: {tshark_info}")

st.sidebar.divider()
st.sidebar.markdown("""
**Core Principles:**
- Evidence-First (Exact packet citations)
- 100% Original Detection Logic
- Separated Severity & Confidence
- Explainable Incident Correlation
""")

# Run Active Page
pg.run()

