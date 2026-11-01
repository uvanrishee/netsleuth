# NetSleuth — Network Diagnosis & Incident Intelligence

> **Transforming raw packet captures into explainable, evidence-backed network incident intelligence.**  
> Built for the **24-Hour Cybersecurity Hackathon | IIITDM Kancheepuram**.

---

## 1. Problem & Solution Overview

Small offices, university campus labs, and departmental networks rely on their connections every day, but rarely have dedicated round-the-clock network engineers or Tier-3 SOC analysts. When network disruptions occur (sluggish throughput, connection timeouts, or strange endpoint behaviors), the standard diagnostic approach requires manually sifting through thousands of raw packets in Wireshark.

This process is error-prone, demands deep protocol knowledge, and makes it virtually impossible for beginners to distinguish a benign operational fault (e.g. buffer congestion or router failover) from an active attack hiding in the same traffic (e.g. ARP cache poisoning or port reconnaissance).

**NetSleuth** automates the entire network investigation chain:
$$\text{PCAP Upload} \longrightarrow \text{TShark Decoding} \longrightarrow \text{Field Normalisation} \longrightarrow \text{Flow Tracking} \longrightarrow \text{10 Original Detectors} \longrightarrow \text{Incident Correlation} \longrightarrow \text{Interactive Dashboard}$$

Every conclusion is tied to **exact packet indices and timestamps**—delivering plain-language explanations, benign alternatives, and actionable remediation steps without fabricated certainty.

---

## 2. Key Architecture & Differentiators

NetSleuth is designed with clean architectural boundaries. UI code never contains detection heuristics, and detection modules are 100% decoupled from Streamlit.

```text
┌────────────────────────────────────────────────────────┐
│                   Streamlit Web UI                     │
│  (Modern st.navigation: Overview, Timeline, Faults,    │
│       Threats, Packet Explorer, Topology, Reports)     │
└───────────────────────────▲────────────────────────────┘
                            │
┌───────────────────────────┴────────────────────────────┐
│                    Diagnosis Layer                     │
│  (Explanations, Recommendations, PCAP Boundary Limits) │
└───────────────────────────▲────────────────────────────┘
                            │
┌───────────────────────────┴────────────────────────────┐
│             Correlation & Scoring Layer                │
│    (Incident Correlator, Severity, Heuristic Conf)     │
└───────────────────────────▲────────────────────────────┘
                            │
┌───────────────────────────┴────────────────────────────┐
│                    Detection Layer                     │
│  (10 Original Python Detectors for Faults & Threats)   │
└───────────────────────────▲────────────────────────────┘
                            │
┌───────────────────────────┴────────────────────────────┐
│             Aggregation & Normalisation Layer          │
│   (Packet Normalisation, Bidirectional Flow Tracker,   │
│                 Host Profiler, Events)                 │
└───────────────────────────▲────────────────────────────┘
                            │
┌───────────────────────────┴────────────────────────────┐
│             Ingestion & Decoding Layer                 │
│      (Safe Header Validation, PyShark / TShark)        │
└────────────────────────────────────────────────────────┘
```

---

## 3. Original Detection Logic (No Wireshark Wrapper)

In strict compliance with hackathon originality rules, **PyShark/TShark is utilized strictly as a decoder interface**. All feature extraction, sequence tracking, aggregation, detection, and correlation logic was written from scratch:

| Detector | Category | What NetSleuth Analyzes | Cautious Language Standard |
|---|---|---|---|
| **TCP Retransmissions** | `NETWORK_FAULT` | Byte sequence range overlaps in same stream and direction | Reports measurable retransmission ratio; caveats capture offload artifacts. |
| **TCP Resets** | `NETWORK_FAULT` | Connection reset context, sender direction, and burst rates | Acknowledges resets as normal protocol signals, not immediate proof of attack. |
| **Incomplete Handshakes** | `NETWORK_FAULT` | Unanswered SYNs within configurable timeouts | Cautiously notes possible asymmetric routing or capture boundaries. |
| **DNS Failures** | `NETWORK_FAULT` | Request/response transaction pairing, NXDOMAIN, SERVFAIL | Identifies explicit server error codes vs. unanswered queries. |
| **DNS Latency** | `NETWORK_FAULT` | Query-to-response round-trip time exceeding threshold (>500ms) | Identifies potential resolver recursions or cache misses. |
| **ARP Conflict** | `NETWORK_FAULT` / `SECURITY` | Multiple distinct MAC addresses claiming a single IP in time window | Distinguishes benign failover (VRRP/HSRP) from ARP poisoning indicators. |
| **Vertical Port Scan** | `SECURITY` | Single source probing $\ge 15$ distinct ports on one destination | Notes that authorized vulnerability scanners are a valid alternative. |
| **Horizontal Port Sweep**| `SECURITY` | Single source probing a common port across $\ge 8$ destination hosts | Notes automated inventory discovery as a benign alternative. |
| **MTU / ICMP Clues** | `NETWORK_FAULT` | ICMP Type 3 Code 4 (Fragmentation Needed) and next-hop MTU hints | Suggests Path MTU Discovery checks and MSS clamping. |
| **DHCP Multi-Server** | `SECURITY` | Multiple distinct DHCP servers offering IP leases on the same subnet | Identifies multiple server identities without falsely declaring rogue server without allowlist. |

---

## 4. Multi-Signal Incident Correlation

Instead of inundating operators with isolated alerts, NetSleuth's **Incident Correlation Engine** clusters related observations using explainable heuristics:
1. **DNS Degradation Preceding Connection Failures:** Links client DNS lookup timeouts to subsequent connection resets or aborted handshakes.
2. **Reconnaissance with Target Rejection:** Links vertical/horizontal port scans with corresponding closed-port TCP RST replies.
3. **ARP Conflicts & Disruption:** Links competing MAC assertions with transport-layer stalls.

---

## 5. Quickstart & Local Setup

### Prerequisites
- Python 3.10+ (tested on Python 3.14)
- **Wireshark / TShark** installed:
  - **Windows:** Default installer installs TShark at `C:\Program Files\Wireshark\tshark.exe` (automatically detected).
  - **Linux / Ubuntu:** `sudo apt-get update && sudo apt-get install -y tshark`
  - **macOS:** `brew install wireshark`

### 1. Clone the repository
```bash
git clone https://github.com/<your-username>/netsleuth.git
cd netsleuth
```

### 2. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 3. Launch NetSleuth
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## 6. Pre-Packaged Sample Captures (For Judges & Demos)

NetSleuth includes controlled, reproducible `.pcap` files in `sample_pcaps/`. Judges can immediately evaluate the tool by selecting any scenario from the dropdown on the **Overview** page:

| Sample PCAP | Scenario Demonstrated | Key Findings |
|---|---|---|
| `sample_pcaps/normal_traffic.pcap` | Baseline HTTP/DNS traffic, complete handshakes, normal ARP | No major issues observed; clean health baseline. |
| `sample_pcaps/tcp_retransmission.pcap` | Repeated TCP byte sequence ranges | Flags TCP Retransmission with exact packet numbers. |
| `sample_pcaps/tcp_reset_burst.pcap` | Host repeatedly rejecting connection attempts | Flags TCP Reset Burst and affected endpoints. |
| `sample_pcaps/incomplete_handshake.pcap` | SYN packets sent without matching SYN-ACK | Flags unanswered handshake requests with timeouts. |
| `sample_pcaps/dns_failures.pcap` | NXDOMAIN, SERVFAIL, and unanswered queries | Identifies domain failure codes and resolver latencies. |
| `sample_pcaps/arp_conflict.pcap` | Two MACs claiming the same IP address | Flags IP-to-MAC mapping conflict and ARP burst. |
| `sample_pcaps/port_scan_recon.pcap` | Vertical scan (25 ports) and horizontal sweep (12 hosts) | Correlates scan probes and target RST rejections into an Incident. |
| `sample_pcaps/dhcp_multi_server.pcap` | Two distinct DHCP servers offering subnet leases | Flags multi-server DHCP observation. |

*(To re-generate all sample files from source at any time, run: `python scripts/generate_sample_pcaps.py`)*

---

## 7. Running the Automated Test Suite

NetSleuth comes with a comprehensive test suite (unit tests and integration tests executing real TShark parsing):

```bash
python -m pytest -v
```

Expected output:
```text
======================= 26 passed in 2.0s =======================
```

---

## 8. Deployment Target (Streamlit Community Cloud)

NetSleuth is fully prepared for one-click deployment to **Streamlit Community Cloud**:
- `packages.txt`: Specifies `tshark` so Streamlit Cloud's Debian runtime installs the system packet decoder.
- `requirements.txt`: Pins all application dependencies.
- Ingestion limits: 50 MB bounded safety budget to prevent out-of-memory container eviction.

---

## 9. Security, Privacy & Responsible Use

1. **Untrusted Input Handling:** Uploaded filenames are sanitized; files are stored using random UUID paths in temporary directories and guaranteed deleted in `finally` blocks.
2. **Data Minimization:** NetSleuth extracts protocol metadata only; raw packet payload content is not stored or displayed by default.
3. **No External Leakage:** Captures are analyzed 100% locally on the host server; no packet data is transmitted to third-party APIs.
4. **Responsible Disclosure:** All sample packet captures are synthetically generated from simulated lab environments with no sensitive personal or corporate data.
