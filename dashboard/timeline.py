"""
Timeline & Incident Sequences Page.
Interactive Plotly timeline visualization and filterable chronological event log.
Spec §8.2: filter by category, severity, protocol, IP, and time range.
Spec §8.3: incident sequences panel with contributing findings and correlation narrative.
"""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from analysis.severity import get_severity_badge_color
from dashboard.session import get_current_analysis, set_selected_packet


def render_timeline_page() -> None:
    st.title("Network Event & Incident Timeline")
    st.caption(
        "Chronological reconstruction of packet observations, protocol handshakes, "
        "and diagnostic detections. Evidence references are preserved for every event."
    )

    res = get_current_analysis()
    if not res or not res.events:
        st.info("No active capture analysis found. Please upload or select a capture on the Overview page first.")
        return

    # ── Timeline Filters ────────────────────────────────────────────────────────
    with st.expander("Timeline Filters", expanded=True):
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            all_categories = ["All"] + sorted({e.category for e in res.events})
            sel_cat = st.selectbox("Category:", options=all_categories, key="tl_cat")
        with col2:
            all_severities = ["All"] + ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            sel_sev = st.selectbox("Min Severity:", options=all_severities, key="tl_sev")
        with col3:
            all_protocols = ["All"] + sorted({e.protocol for e in res.events if e.protocol})
            sel_proto = st.selectbox("Protocol:", options=all_protocols, key="tl_proto")
        with col4:
            ip_filter = st.text_input(
                "Filter by IP / Endpoint:",
                placeholder="e.g. 192.168.1.1",
                key="tl_ip"
            ).strip()

        # Time range slider (relative seconds from capture start)
        if res.duration_seconds > 0:
            t_min, t_max = st.slider(
                "Time Range (seconds from capture start):",
                min_value=0.0,
                max_value=float(res.duration_seconds),
                value=(0.0, float(res.duration_seconds)),
                step=max(0.001, res.duration_seconds / 1000),
                key="tl_timerange"
            )
        else:
            t_min, t_max = 0.0, 0.0

    # ── Apply filters ─────────────────────────────────────────────────────────
    sev_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    min_sev_rank = sev_rank.get(sel_sev, 0)

    filtered_events = res.events
    if sel_cat != "All":
        filtered_events = [e for e in filtered_events if e.category == sel_cat]
    if sel_sev != "All":
        filtered_events = [e for e in filtered_events if sev_rank.get(e.severity, 0) >= min_sev_rank]
    if sel_proto != "All":
        filtered_events = [e for e in filtered_events if e.protocol == sel_proto]
    if ip_filter:
        filtered_events = [
            e for e in filtered_events
            if ip_filter in (e.source or "") or ip_filter in (e.destination or "")
        ]
    if res.duration_seconds > 0:
        filtered_events = [
            e for e in filtered_events
            if t_min <= (e.timestamp - res.capture_start_time) <= t_max
        ]

    st.markdown(f"**Showing {len(filtered_events)} of {len(res.events)} total events.**")

    # ── Tabs: Event Stream + Incident Sequences ────────────────────────────────
    tab_timeline, tab_incidents = st.tabs(["Event Stream", "Incident Sequences"])

    with tab_timeline:
        if filtered_events:
            df_events = pd.DataFrame([
                {
                    "Time (s)": round(e.timestamp - res.capture_start_time, 3),
                    "Event Type": e.event_type,
                    "Category": e.category,
                    "Protocol": e.protocol,
                    "Severity": e.severity,
                    "Description": e.description,
                    "Packet #": e.packet_number if e.packet_number else "—",
                    "Source": e.source or "—",
                    "Destination": e.destination or "—",
                }
                for e in filtered_events[:500]
            ])

            color_map = {
                "CRITICAL": "#d32f2f",
                "HIGH": "#f57c00",
                "MEDIUM": "#fbc02d",
                "LOW": "#1976d2",
                "INFO": "#757575",
            }

            chart_height = max(350, min(600, len(df_events["Event Type"].unique()) * 30 + 100))
            fig = px.scatter(
                df_events,
                x="Time (s)",
                y="Event Type",
                color="Severity",
                color_discrete_map=color_map,
                hover_data=["Packet #", "Source", "Destination", "Protocol", "Description"],
                title=f"Chronological Event Stream ({len(filtered_events)} events)",
                height=chart_height,
            )
            fig.update_layout(margin=dict(l=20, r=20, t=40, b=20))
            fig.update_traces(marker=dict(size=8, opacity=0.85))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No events match the selected filters.")

        # Detailed Event Table
        st.subheader("Event Ledger")
        st.caption("Up to 200 rows shown — use filters to narrow results.")

        table_data = []
        for e in filtered_events[:200]:
            time_rel = f"{e.timestamp - res.capture_start_time:+.3f}s"
            table_data.append({
                "Rel Time": time_rel,
                "Packet #": e.packet_number or "—",
                "Severity": e.severity,
                "Category": e.category,
                "Protocol": e.protocol,
                "Source": e.source,
                "Destination": e.destination,
                "Description": e.description,
            })

        if table_data:
            st.dataframe(pd.DataFrame(table_data), use_container_width=True, height=380)

            # Jump-to-packet widget
            st.divider()
            pkt_nums = [e.packet_number for e in filtered_events[:200] if e.packet_number]
            if pkt_nums:
                col_sel, col_btn = st.columns([3, 1])
                with col_sel:
                    selected_pkt = st.selectbox(
                        "Select evidence packet to inspect:",
                        options=pkt_nums,
                        format_func=lambda n: f"Packet #{n}",
                        key="tl_pkt_select"
                    )
                with col_btn:
                    if st.button("Open in Packet Explorer", key="tl_open_pkt", use_container_width=True):
                        set_selected_packet(selected_pkt)
                        st.info(
                            f"Packet #{selected_pkt} selected — switch to "
                            "**Packet Explorer** in the sidebar to inspect it."
                        )
        else:
            st.write("No events match the selected filter criteria.")

    # ── Incident Sequences Panel (spec §8.3) ──────────────────────────────────
    with tab_incidents:
        st.subheader("Correlated Incident Sequences")
        st.caption(
            "Incidents group related findings by shared endpoints, time proximity, "
            "and causal protocol dependencies. Confidence and severity are kept separate."
        )

        if not res.incidents:
            st.info("No multi-signal incidents were correlated for this capture.")
            return

        for inc in res.incidents:
            badge_color = get_severity_badge_color(inc.severity)
            with st.container(border=True):
                hdr_col, badge_col, conf_col = st.columns([4, 1, 1])
                with hdr_col:
                    st.markdown(f"#### {inc.title}")
                    st.caption(
                        f"Incident: `{inc.incident_id}` | Category: `{inc.category}` | "
                        f"Classification: `{inc.classification}`"
                    )
                with badge_col:
                    st.markdown(
                        f"<div style='background-color:{badge_color};color:white;"
                        f"padding:4px 8px;border-radius:4px;text-align:center;"
                        f"font-weight:bold;'>{inc.severity}</div>",
                        unsafe_allow_html=True
                    )
                with conf_col:
                    st.markdown(
                        f"<div style='background-color:#eceff1;color:#37474f;"
                        f"padding:4px 8px;border-radius:4px;text-align:center;"
                        f"font-size:0.85em;'>Conf: {inc.confidence:.0%}</div>",
                        unsafe_allow_html=True
                    )

                t_start_rel = round(inc.start_time - res.capture_start_time, 3)
                t_end_rel = round(inc.end_time - res.capture_start_time, 3)
                st.caption(
                    f"+{t_start_rel}s → +{t_end_rel}s from capture start | "
                    f"Hosts: `{', '.join(inc.affected_hosts) or 'Multiple'}`"
                )

                st.markdown("**Observed Sequence:**")
                for line in inc.narrative.split("\n"):
                    if line.strip():
                        st.markdown(f"  {line.strip()}")

                st.markdown(f"**Likely Cause:** {inc.likely_cause}")

                st.markdown("**Why these findings were grouped (Correlation Reasons):**")
                for reason in inc.correlation_reasons:
                    st.markdown(f"- {reason}")

                with st.expander("Alternative Explanations, Recommendations & PCAP Limitations"):
                    if inc.alternative_explanations:
                        st.markdown("**Alternative Explanations:**")
                        for alt in inc.alternative_explanations:
                            st.markdown(f"- {alt}")

                    if inc.recommendations:
                        st.markdown("**Recommended Checks:**")
                        for rec in inc.recommendations:
                            st.markdown(f"- {rec}")

                    if inc.limitations:
                        st.markdown("**PCAP Limitations:**")
                        for lim in inc.limitations:
                            st.markdown(f"- *{lim}*")

                    st.markdown(
                        f"**Contributing Findings:** `{', '.join(inc.contributing_finding_ids)}`"
                    )
