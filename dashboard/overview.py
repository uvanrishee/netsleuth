"""
Overview & Executive Dashboard page.
Provides high-level capture health assessment, KPIs, protocol distribution, and top incidents.
"""

from __future__ import annotations

import os
import plotly.express as px
import streamlit as st

from analysis.pipeline import run_pipeline
from analysis.severity import get_severity_badge_color
from core.pcap_loader import (
    cleanup_temporary_capture,
    save_upload_to_temp,
    validate_capture_bytes,
)
from dashboard.session import get_current_analysis, set_current_analysis


def render_overview_page() -> None:
    st.title("NetSleuth — Executive Overview")
    st.caption("Network Diagnosis & Incident Intelligence from Packet Captures")

    # ── Ingestion Section ──────────────────────────────────────────────────────
    with st.expander("Capture Ingestion & Sample Scenarios", expanded=True):

        col_upload, col_sample = st.columns(2, gap="large")

        with col_upload:
            st.markdown("##### Upload a Capture File")
            uploaded_file = st.file_uploader(
                "upload_area",
                type=["pcap", "pcapng"],
                help="Maximum upload limit: 50 MB. Magic-byte header is verified before analysis.",
                label_visibility="collapsed",
            )
            st.caption("Accepted formats: `.pcap` · `.pcapng` &nbsp;|&nbsp; Max size: 50 MB")

        with col_sample:
            st.markdown("##### Or Load a Pre-built Sample Scenario")
            sample_dir = "sample_pcaps"
            sample_files = (
                sorted(f for f in os.listdir(sample_dir) if f.endswith((".pcap", ".pcapng")))
                if os.path.exists(sample_dir)
                else []
            )
            selected_sample = st.selectbox(
                "sample_selector",
                options=["-- Select a sample --"] + sample_files,
                help="Run analysis on a synthetic scenario — no upload needed.",
                label_visibility="collapsed",
            )
            st.caption(f"{len(sample_files)} pre-built scenario(s) available in `sample_pcaps/`")

        st.divider()

        # Full-width Analyze button centred below both columns
        analyze_clicked = st.button(
            "Analyze Capture",
            type="primary",
            use_container_width=True,
        )

        if analyze_clicked:
            target_path = None
            is_temp = False
            display_name = ""

            if uploaded_file is not None:
                bytes_data = uploaded_file.getvalue()
                val_res = validate_capture_bytes(bytes_data, uploaded_file.name)
                if not val_res.is_valid:
                    st.error(val_res.error_message)
                    return
                target_path = save_upload_to_temp(bytes_data, f".{val_res.file_type}")
                is_temp = True
                display_name = uploaded_file.name

            elif selected_sample and selected_sample != "-- Select a sample --":
                target_path = os.path.join(sample_dir, selected_sample)
                display_name = selected_sample

            if target_path:
                progress_bar = st.progress(0, text="Starting packet analysis...")

                def update_prog(ratio: float, msg: str) -> None:
                    progress_bar.progress(min(1.0, max(0.0, ratio)), text=msg)

                try:
                    result = run_pipeline(
                        target_path,
                        original_filename=display_name,
                        progress_callback=update_prog,
                    )
                    set_current_analysis(result)
                    st.success(f"Analysis completed for **{display_name}**!")
                except Exception as exc:
                    st.error(f"Analysis failed: {exc}")
                finally:
                    if is_temp and target_path:
                        cleanup_temporary_capture(target_path)
                    progress_bar.empty()
            else:
                st.warning("⚠️ Please upload a file or choose a sample scenario above to begin.")

    res = get_current_analysis()
    if not res:
        st.info("Upload a capture or pick a pre-built sample scenario above to see results.")
        return

    # ── Assessment Banner ──────────────────────────────────────────────────────
    st.divider()
    crit_high = [f for f in res.findings if f.severity in ("CRITICAL", "HIGH")]
    med = [f for f in res.findings if f.severity == "MEDIUM"]

    if crit_high:
        st.error(
            f"**ASSESSMENT: Suspicious Activity / Severe Faults Observed**  \n"
            f"NetSleuth identified {len(crit_high)} high-priority finding(s) and "
            f"{len(res.incidents)} correlated incident(s) requiring immediate investigation."
        )
    elif med:
        st.warning(
            f"**ASSESSMENT: Needs Investigation**  \n"
            f"NetSleuth detected {len(med)} network anomaly/anomalies (e.g. resets, timeouts, "
            "or retransmissions). Recommended checks are detailed below."
        )
    else:
        st.info(
            "**ASSESSMENT: No Major Issue Observed**  \n"
            "Traffic appears consistent with normal operation within the observed capture window. "
            "(Absence of findings does not guarantee full network security)."
        )

    # ── Metric Cards ───────────────────────────────────────────────────────────
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.metric("Total Packets", f"{res.total_packets_read:,}")
    with m2:
        st.metric("Observed Flows", f"{len(res.flows):,}")
    with m3:
        st.metric("Active Hosts", f"{len(res.hosts):,}")
    with m4:
        st.metric("Correlated Incidents", f"{len(res.incidents):,}")
    with m5:
        st.metric("Total Findings", f"{len(res.findings):,}")

    st.divider()

    # ── Protocol Distribution & Capture Metadata ───────────────────────────────
    c_left, c_right = st.columns([1.2, 1], gap="large")

    with c_left:
        st.subheader("Traffic Protocol Distribution")
        if res.protocol_counts:
            fig = px.pie(
                names=list(res.protocol_counts.keys()),
                values=list(res.protocol_counts.values()),
                hole=0.45,
                color_discrete_sequence=px.colors.qualitative.Plotly,
            )
            fig.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=300)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.write("No protocols observed.")

    with c_right:
        st.subheader("Capture Metadata")
        size_kb = res.file_size_bytes / 1024.0
        size_str = f"{size_kb / 1024.0:.2f} MB" if size_kb > 1024 else f"{size_kb:.1f} KB"
        st.markdown(f"""
        | Field | Value |
        |---|---|
        | **Filename** | `{res.filename}` |
        | **File Size** | `{size_str}` |
        | **Duration** | `{res.duration_seconds:.2f} seconds` |
        | **Start (Epoch)** | `{res.capture_start_time:.3f}` |
        | **End (Epoch)** | `{res.capture_end_time:.3f}` |
        | **Capture Scope** | Single vantage point |
        """)

    # ── Prioritized Incidents ──────────────────────────────────────────────────
    st.subheader("Prioritized Incidents & Findings")
    if res.incidents:
        for inc in res.incidents:
            badge_color = get_severity_badge_color(inc.severity)
            with st.container(border=True):
                col_title, col_badge = st.columns([5, 1])
                with col_title:
                    st.markdown(f"#### {inc.title}")
                    st.caption(
                        f"Incident ID: `{inc.incident_id}` | "
                        f"Classification: `{inc.classification}`"
                    )
                with col_badge:
                    st.markdown(
                        f"<div style='background-color:{badge_color};color:white;"
                        f"padding:4px 8px;border-radius:4px;text-align:center;"
                        f"font-weight:bold;margin-top:8px;'>{inc.severity}</div>",
                        unsafe_allow_html=True,
                    )

                st.markdown(f"**Narrative:**\n{inc.narrative}")
                st.markdown(f"**Likely Cause:** {inc.likely_cause}")

                st.markdown("**Recommended Investigation Next Steps:**")
                for r in inc.recommendations:
                    st.markdown(f"- {r}")

                with st.expander("Technical Evidence & Limitations"):
                    st.markdown(f"**Contributing Findings:** `{', '.join(inc.contributing_finding_ids)}`")
                    st.markdown(f"**Affected Hosts:** `{', '.join(inc.affected_hosts)}`")
                    st.markdown("**Limitations:**")
                    for lim in inc.limitations:
                        st.markdown(f"- {lim}")
    else:
        st.info("No multi-signal incidents correlated for this capture.")

    # ── Recommended Investigation Order ───────────────────────────────────────
    if res.findings:
        st.divider()
        st.subheader("Recommended Investigation Order")
        st.caption("Prioritized by potential operational impact and evidence confidence.")

        sev_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        sorted_findings = sorted(
            res.findings,
            key=lambda x: (sev_rank.get(x.severity, 0), x.confidence),
            reverse=True,
        )

        for i, f in enumerate(sorted_findings[:6], 1):
            badge = get_severity_badge_color(f.severity)
            with st.container(border=True):
                col_t, col_b = st.columns([5, 1])
                with col_t:
                    st.markdown(
                        f"**#{i} — [{f.category.replace('_', ' ')}] {f.title}**"
                    )
                    st.caption(
                        f"ID: `{f.finding_id}` | "
                        f"Classification: `{f.classification}` | "
                        f"Confidence: `{f.confidence:.0%}`"
                    )
                with col_b:
                    st.markdown(
                        f"<div style='background-color:{badge};color:white;"
                        f"padding:3px 6px;border-radius:4px;text-align:center;"
                        f"font-size:0.85em;font-weight:bold;margin-top:8px;'>"
                        f"{f.severity}</div>",
                        unsafe_allow_html=True,
                    )
                st.markdown(f"**Likely Cause:** {f.likely_cause}")
                st.markdown(f"**Immediate Next Step:** {f.recommendation}")
                if f.evidence_packets:
                    st.caption(f"Evidence Packet(s): {', '.join(map(str, f.evidence_packets))}")
    else:
        st.divider()
        st.info("No network faults or security threats identified in this capture.")
