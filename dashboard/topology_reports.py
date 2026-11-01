"""
Topology & Exportable Reports Page.
Observed communication topology (§8.7) and downloadable diagnostic reports (§8.8).
Topology shows host-level detail on selection; wording avoids physical topology claims.
"""

from __future__ import annotations

import json
import math
import networkx as nx
import plotly.graph_objects as go
import streamlit as st

from analysis.severity import get_severity_badge_color
from dashboard.session import get_current_analysis


def render_topology_reports_page() -> None:
    st.title("Network Topology & Diagnostic Reports")
    st.caption(
        "Visual graph of observed host communications and exportable executive diagnostic reports."
    )

    res = get_current_analysis()
    if not res:
        st.info("No active capture analysis found. Please upload or select a capture on the Overview page first.")
        return

    tab_topo, tab_reports = st.tabs(["Observed Communication Topology", "Exportable Diagnostic Reports"])

    # ── Topology (spec §8.7) ───────────────────────────────────────────────────
    with tab_topo:
        st.info(
            "**Observed Communication Topology:** This graph represents IP endpoints and flows "
            "directly observed in the capture. It does **not** imply physical switch/router cabling, "
            "VLANs, or any unobserved segments.",
            icon="ℹ️"
        )

        if not res.flows:
            st.write("No flow relationships to display.")
        else:
            G = nx.Graph()

            # Add nodes
            for host_ip, host_prof in res.hosts.items():
                G.add_node(host_ip, packet_count=host_prof.packet_count, byte_count=host_prof.byte_count)

            # Add edges
            for flow_id, fl in res.flows.items():
                ip_a = fl.endpoint_a[0]
                ip_b = fl.endpoint_b[0]
                if ip_a not in G:
                    G.add_node(ip_a, packet_count=0, byte_count=0)
                if ip_b not in G:
                    G.add_node(ip_b, packet_count=0, byte_count=0)
                if G.has_edge(ip_a, ip_b):
                    G[ip_a][ip_b]["weight"] += fl.packet_count
                else:
                    G.add_edge(ip_a, ip_b, weight=fl.packet_count, protocol=fl.protocol)

            pos = nx.spring_layout(G, seed=42, k=1.0)

            # Build edge traces
            edge_traces = []
            for edge in G.edges(data=True):
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]
                weight = edge[2].get("weight", 1)
                proto = edge[2].get("protocol", "")
                edge_traces.append(
                    go.Scatter(
                        x=[x0, x1, None],
                        y=[y0, y1, None],
                        line=dict(width=max(1, min(6, math.log(weight + 1))), color="#546e7a"),
                        hoverinfo="text",
                        text=f"{edge[0]} ↔ {edge[1]}<br>{weight} packets | {proto}",
                        mode="lines",
                    )
                )

            # Build node trace
            node_x, node_y, node_text, node_hover, node_size, node_color = [], [], [], [], [], []
            nodes_list = list(G.nodes())

            # Determine which hosts have findings
            hosts_with_findings: dict[str, list[str]] = {}
            for f in res.findings:
                for h in f.affected_hosts:
                    hosts_with_findings.setdefault(h, []).append(f.finding_id)

            for node in nodes_list:
                x, y = pos[node]
                node_x.append(x)
                node_y.append(y)
                cnt = G.nodes[node].get("packet_count", 1)
                finding_ids = hosts_with_findings.get(node, [])
                badge = f" ⚠️ {len(finding_ids)} finding(s)" if finding_ids else ""
                node_text.append(node)
                node_hover.append(
                    f"<b>{node}</b>{badge}<br>"
                    f"Packets: {cnt}<br>"
                    f"Peers: {G.degree(node)}"
                )
                node_size.append(min(38, max(14, int(math.log(cnt + 1) * 7))))
                node_color.append("#d32f2f" if finding_ids else "#1976d2")

            node_trace = go.Scatter(
                x=node_x,
                y=node_y,
                mode="markers+text",
                hoverinfo="text",
                text=node_text,
                textposition="bottom center",
                hovertext=node_hover,
                customdata=nodes_list,
                marker=dict(
                    color=node_color,
                    size=node_size,
                    line=dict(width=2, color="#0d47a1"),
                    symbol="circle",
                ),
            )

            fig = go.Figure(
                data=edge_traces + [node_trace],
                layout=go.Layout(
                    title="Observed Host Communication Network (red = hosts with findings)",
                    showlegend=False,
                    hovermode="closest",
                    margin=dict(b=20, l=10, r=10, t=50),
                    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    height=520,
                )
            )
            st.plotly_chart(fig, use_container_width=True)

            # ── Host Detail Panel ──────────────────────────────────────────────
            st.subheader("Host Detail Inspector")
            st.caption("Select a host to see observed traffic, peers, protocols, and related findings.")

            all_hosts = sorted(res.hosts.keys())
            selected_host = st.selectbox(
                "Select host IP:",
                options=all_hosts,
                key="topo_host_select",
                format_func=lambda h: (
                    f"⚠️ {h}  ({len(hosts_with_findings.get(h, []))} findings)"
                    if h in hosts_with_findings else h
                )
            )

            if selected_host and selected_host in res.hosts:
                hp = res.hosts[selected_host]
                col_a, col_b = st.columns(2)

                with col_a:
                    st.markdown(f"##### Host: `{selected_host}`")
                    st.markdown(f"- **MACs observed:** `{', '.join(hp.mac_addresses) or '—'}`")
                    st.markdown(f"- **First seen:** `{hp.first_seen:.3f}`")
                    st.markdown(f"- **Last seen:** `{hp.last_seen:.3f}`")
                    st.markdown(f"- **Packet count:** `{hp.packet_count:,}`")
                    st.markdown(f"- **Byte count:** `{hp.byte_count:,}`")
                    st.markdown(f"- **Protocols:** `{', '.join(sorted(hp.protocols_used)) or '—'}`")
                    st.markdown(f"- **Destination ports contacted:** `{', '.join(str(p) for p in sorted(hp.ports_contacted)) or '—'}`")

                with col_b:
                    st.markdown(f"- **Unique peers ({len(hp.peers)}):**")
                    for peer in sorted(hp.peers):
                        st.markdown(f"  - `{peer}`")

                # Related findings for this host
                host_findings = [f for f in res.findings if selected_host in f.affected_hosts]
                if host_findings:
                    st.markdown(f"**Related Findings ({len(host_findings)}):**")
                    for hf in host_findings:
                        badge = get_severity_badge_color(hf.severity)
                        with st.container(border=True):
                            c1, c2 = st.columns([4, 1])
                            with c1:
                                st.markdown(f"**{hf.title}**")
                                st.caption(
                                    f"`{hf.finding_id}` | {hf.type} | "
                                    f"Evidence packets: `{', '.join(str(p) for p in hf.evidence_packets[:5])}`"
                                )
                            with c2:
                                st.markdown(
                                    f"<div style='background:{badge};color:white;"
                                    f"padding:3px 6px;border-radius:4px;text-align:center;"
                                    f"font-size:0.8em;font-weight:bold;'>{hf.severity}</div>",
                                    unsafe_allow_html=True
                                )
                else:
                    st.info("No findings directly associated with this host.")

    # ── Exportable Reports (spec §8.8) ────────────────────────────────────────
    with tab_reports:
        st.subheader("Generate Diagnostic Incident Report")
        st.write(
            "Download evidence-backed diagnostic summaries. Reports use the same analysis "
            "results as the dashboard — no separate detection path."
        )

        # Build JSON report
        json_report = {
            "metadata": {
                "filename": res.filename,
                "file_size_bytes": res.file_size_bytes,
                "duration_seconds": res.duration_seconds,
                "total_packets": res.total_packets_read,
                "total_flows": len(res.flows),
                "total_hosts": len(res.hosts),
                "analysis_limitations": (
                    "Conclusions generated solely from observable traffic metadata "
                    "at a single capture point."
                ),
            },
            "incidents": [
                {
                    "id": inc.incident_id,
                    "title": inc.title,
                    "category": inc.category,
                    "classification": inc.classification,
                    "severity": inc.severity,
                    "confidence": inc.confidence,
                    "narrative": inc.narrative,
                    "correlation_reasons": inc.correlation_reasons,
                    "likely_cause": inc.likely_cause,
                    "alternative_explanations": inc.alternative_explanations,
                    "recommendations": inc.recommendations,
                    "limitations": inc.limitations,
                    "contributing_finding_ids": inc.contributing_finding_ids,
                    "affected_hosts": inc.affected_hosts,
                }
                for inc in res.incidents
            ],
            "findings": [
                {
                    "id": f.finding_id,
                    "category": f.category,
                    "type": f.type,
                    "title": f.title,
                    "classification": f.classification,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "reason": f.reason,
                    "likely_cause": f.likely_cause,
                    "alternative_explanations": f.alternative_explanations,
                    "recommendation": f.recommendation,
                    "limitations": f.limitations,
                    "evidence_packets": f.evidence_packets,
                    "metrics": f.metrics,
                    "affected_hosts": f.affected_hosts,
                }
                for f in res.findings
            ],
        }

        # Build Markdown report
        md_lines = [
            "# NetSleuth Incident & Network Diagnostic Report",
            "",
            f"**Capture File:** `{res.filename}`  ",
            f"**File Size:** `{res.file_size_bytes / 1024:.1f} KB`  ",
            f"**Duration:** `{res.duration_seconds:.2f}s`  ",
            f"**Total Packets:** `{res.total_packets_read:,}`  ",
            f"**Analysis Scope:** Single network capture point observation.",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            f"- **Observed Flows:** {len(res.flows)}",
            f"- **Active Hosts:** {len(res.hosts)}",
            f"- **Correlated Incidents:** {len(res.incidents)}",
            f"- **Total Diagnostic Findings:** {len(res.findings)}",
            "",
        ]

        if res.incidents:
            md_lines += ["## 2. Correlated Incidents", ""]
            for inc in res.incidents:
                md_lines.append(f"### {inc.incident_id}: {inc.title}")
                md_lines.append(f"- **Severity:** {inc.severity} | **Confidence:** {inc.confidence:.0%}")
                md_lines.append(f"- **Classification:** {inc.classification}")
                md_lines.append(f"- **Affected Hosts:** {', '.join(inc.affected_hosts)}")
                md_lines.append(f"\n**Narrative:**\n{inc.narrative}")
                md_lines.append(f"\n**Likely Cause:** {inc.likely_cause}")
                md_lines.append("\n**Recommended Actions:**")
                for r in inc.recommendations:
                    md_lines.append(f"  - {r}")
                md_lines.append("\n**Limitations:**")
                for lim in inc.limitations:
                    md_lines.append(f"  - {lim}")
                md_lines.append("")

        if res.findings:
            md_lines += ["## 3. Individual Findings", ""]
            for f in res.findings:
                md_lines.append(f"### [{f.severity}] {f.title} (`{f.finding_id}`)")
                md_lines.append(f"- **Category:** {f.category} | **Type:** {f.type}")
                md_lines.append(f"- **Classification:** {f.classification}")
                md_lines.append(f"- **Confidence:** {f.confidence:.0%}")
                md_lines.append(f"- **Evidence Packets:** `{', '.join(str(p) for p in f.evidence_packets)}`")
                md_lines.append(f"\n**Observed Facts:** {f.reason}")
                md_lines.append(f"\n**Likely Cause:** {f.likely_cause}")
                md_lines.append(f"\n**Recommendation:** {f.recommendation}")
                md_lines.append("")

        md_lines += [
            "---",
            "",
            "## 4. Scope & Limitations Notice",
            "",
            "This diagnosis is based strictly on packet metadata captured at one network interface "
            "at a single vantage point. Packets dropped before capture, traffic on alternate paths, "
            "and encrypted payload contents are not observable. All conclusions are qualified "
            "hypotheses, not confirmed attributions.",
        ]

        md_report_text = "\n".join(md_lines)

        col_dl1, col_dl2 = st.columns(2)
        with col_dl1:
            st.download_button(
                label="Download Structured Report (JSON)",
                data=json.dumps(json_report, indent=2),
                file_name=f"netsleuth_report_{res.filename}.json",
                mime="application/json",
                use_container_width=True,
            )
        with col_dl2:
            st.download_button(
                label="Download Executive Report (Markdown)",
                data=md_report_text,
                file_name=f"netsleuth_report_{res.filename}.md",
                mime="text/markdown",
                use_container_width=True,
            )

        st.markdown("---")
        st.markdown("### Report Preview")
        st.markdown(md_report_text)
