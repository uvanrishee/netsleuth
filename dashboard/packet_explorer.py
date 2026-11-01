"""
Packet Explorer & Evidence Deep-Dive Page.
Provides paginated packet browsing, search by packet number, and layer-by-layer field inspection.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from dashboard.session import get_current_analysis, set_selected_packet


def render_packet_explorer_page() -> None:
    st.title("Packet Explorer & Evidence Inspector")
    st.caption("Verify raw packet metadata, inspect protocol headers, and analyze surrounding packet context.")

    res = get_current_analysis()
    if not res or not res.packets:
        st.info("No active capture analysis found. Please upload or select a capture on the Overview page first.")
        return

    # Filter Controls
    with st.expander("Search & Filters", expanded=True):
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            pkt_search = st.number_input(
                "Jump to Packet #:",
                min_value=1,
                max_value=len(res.packets),
                value=st.session_state.get("selected_packet_number") or 1,
                step=1
            )
            if pkt_search:
                set_selected_packet(pkt_search)

        with col2:
            ip_query = st.text_input("Filter by IP:", value="").strip()

        with col3:
            proto_opts = ["All"] + sorted(list({p.transport_protocol or p.highest_layer for p in res.packets if p.transport_protocol or p.highest_layer}))
            selected_proto = st.selectbox("Protocol:", options=proto_opts)

        with col4:
            page_size = st.selectbox("Page Size:", options=[50, 100, 200], index=1)

    # Filter packet list
    filtered_packets = res.packets
    if ip_query:
        filtered_packets = [p for p in filtered_packets if ip_query in (p.src_ip or "") or ip_query in (p.dst_ip or "")]
    if selected_proto != "All":
        filtered_packets = [p for p in filtered_packets if (p.transport_protocol or p.highest_layer) == selected_proto]

    st.markdown(f"**Showing {len(filtered_packets)} of {len(res.packets)} packets.**")

    # Pagination
    total_pages = max(1, (len(filtered_packets) + page_size - 1) // page_size)
    curr_page = st.number_input("Page:", min_value=1, max_value=total_pages, value=1, step=1)

    start_idx = (curr_page - 1) * page_size
    end_idx = min(start_idx + page_size, len(filtered_packets))
    page_packets = filtered_packets[start_idx:end_idx]

    # Render tabular overview
    table_rows = []
    for p in page_packets:
        rel_time = f"{p.timestamp - res.capture_start_time:+.3f}s"
        proto = p.transport_protocol or p.highest_layer
        src = f"{p.src_ip}:{p.src_port}" if p.src_port else (p.src_ip or p.src_mac or "—")
        dst = f"{p.dst_ip}:{p.dst_port}" if p.dst_port else (p.dst_ip or p.dst_mac or "—")

        flag_str = ""
        if p.tcp_flags:
            flag_str = ",".join([k for k, v in p.tcp_flags.items() if v])

        table_rows.append({
            "No.": p.packet_number,
            "Rel Time": rel_time,
            "Source": src,
            "Destination": dst,
            "Protocol": proto,
            "Length": p.captured_length,
            "Flags / Info": flag_str or p.dns_query_name or p.arp_operation or "—"
        })

    if table_rows:
        st.dataframe(pd.DataFrame(table_rows), use_container_width=True, height=350)

    # Selected Packet Deep-Dive Inspector
    selected_num = st.session_state.get("selected_packet_number") or 1
    selected_pkt = next((p for p in res.packets if p.packet_number == selected_num), None)

    st.divider()
    st.subheader(f"Inspection Drawer — Packet #{selected_num}")

    if selected_pkt:
        col_l, col_r = st.columns(2)

        with col_l:
            st.markdown("##### Layer 2 & 3 (Network / Link)")
            st.markdown(f"- **Frame Length:** `{selected_pkt.captured_length} bytes`")
            st.markdown(f"- **Epoch Timestamp:** `{selected_pkt.timestamp:.6f}`")
            st.markdown(f"- **ISO Time:** `{selected_pkt.timestamp_iso}`")
            st.markdown(f"- **Source MAC:** `{selected_pkt.src_mac or '—'}`")
            st.markdown(f"- **Destination MAC:** `{selected_pkt.dst_mac or '—'}`")
            st.markdown(f"- **Source IP:** `{selected_pkt.src_ip or '—'}`")
            st.markdown(f"- **Destination IP:** `{selected_pkt.dst_ip or '—'}`")
            st.markdown(f"- **IP Version / TTL:** `IPv{selected_pkt.ip_version or '—'} / TTL {selected_pkt.ttl or '—'}`")

        with col_r:
            st.markdown("##### Layer 4 & Application")
            st.markdown(f"- **Transport Protocol:** `{selected_pkt.transport_protocol or '—'}`")
            st.markdown(f"- **Ports:** `{selected_pkt.src_port or '—'} → {selected_pkt.dst_port or '—'}`")
            st.markdown(f"- **TCP Flags:** `{selected_pkt.tcp_flags or '—'}`")
            st.markdown(f"- **TCP Seq / Ack:** `{selected_pkt.tcp_seq or '—'} / {selected_pkt.tcp_ack or '—'}`")

            if selected_pkt.dns_id is not None:
                st.markdown("##### DNS Details")
                st.markdown(f"- **Transaction ID:** `0x{selected_pkt.dns_id:04x}`")
                st.markdown(f"- **Query Name:** `{selected_pkt.dns_query_name or '—'}`")
                st.markdown(f"- **Is Response:** `{selected_pkt.dns_is_response}`")
                st.markdown(f"- **Response Code (RCODE):** `{selected_pkt.dns_response_code or '—'}`")
                st.markdown(f"- **Answers:** `{selected_pkt.dns_answers or '—'}`")

            if selected_pkt.arp_operation:
                st.markdown("##### ARP Details")
                st.markdown(f"- **Operation:** `{selected_pkt.arp_operation}`")
                st.markdown(f"- **Sender IP / MAC:** `{selected_pkt.arp_sender_ip} ({selected_pkt.arp_sender_mac})`")
                st.markdown(f"- **Target IP / MAC:** `{selected_pkt.arp_target_ip} ({selected_pkt.arp_target_mac})`")

            if selected_pkt.icmp_type is not None:
                st.markdown("##### ICMP Details")
                st.markdown(f"- **Type / Code:** `{selected_pkt.icmp_type} / {selected_pkt.icmp_code}`")
                st.markdown(f"- **Next-Hop MTU:** `{selected_pkt.icmp_mtu or '—'}`")

        # Surrounding Packet Context (± 5 packets)
        with st.expander("Surrounding Packet Context (±5 Packets)"):
            ctx_start = max(1, selected_num - 5)
            ctx_end = min(len(res.packets), selected_num + 5)
            ctx_packets = [p for p in res.packets if ctx_start <= p.packet_number <= ctx_end]

            ctx_rows = []
            for cp in ctx_packets:
                is_sel = "[Focus]" if cp.packet_number == selected_num else ""
                ctx_rows.append({
                    "Focus": is_sel,
                    "No.": cp.packet_number,
                    "Rel Time": f"{cp.timestamp - res.capture_start_time:+.3f}s",
                    "Protocol": cp.transport_protocol or cp.highest_layer,
                    "Source": f"{cp.src_ip}:{cp.src_port}" if cp.src_port else cp.src_ip or cp.src_mac,
                    "Destination": f"{cp.dst_ip}:{cp.dst_port}" if cp.dst_port else cp.dst_ip or cp.dst_mac,
                })
            st.dataframe(pd.DataFrame(ctx_rows), use_container_width=True)
    else:
        st.write("Packet not found.")
