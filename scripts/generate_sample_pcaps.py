"""
Synthetic PCAP Generator for NetSleuth.
Generates controlled, reproducible .pcap files demonstrating each diagnostic scenario.
Uses Scapy to construct clean Ethernet, IP, TCP, UDP, DNS, ARP, and DHCP packets.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path


def generate_all_samples(output_dir: str = "sample_pcaps") -> dict[str, str]:
    """
    Generates all test PCAP scenarios into the output directory.
    """
    from scapy.all import (
        Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, ARP, BOOTP, DHCP, wrpcap
    )

    os.makedirs(output_dir, exist_ok=True)
    generated_files: dict[str, str] = {}

    base_time = 1700000000.0  # Stable deterministic reference time

    # =========================================================================
    # 1. Normal Mixed Traffic
    # =========================================================================
    pkts = []
    # ARP query & reply
    pkts.append(Ether(src="00:11:22:33:44:01", dst="ff:ff:ff:ff:ff:ff") /
                ARP(op=1, hwsrc="00:11:22:33:44:01", psrc="192.168.1.50", hwdst="00:00:00:00:00:00", pdst="192.168.1.1"))
    pkts.append(Ether(src="00:11:22:33:44:fe", dst="00:11:22:33:44:01") /
                ARP(op=2, hwsrc="00:11:22:33:44:fe", psrc="192.168.1.1", hwdst="00:11:22:33:44:01", pdst="192.168.1.50"))

    # DNS Request & Successful Response
    pkts.append(Ether(src="00:11:22:33:44:01", dst="00:11:22:33:44:fe") /
                IP(src="192.168.1.50", dst="192.168.1.1") /
                UDP(sport=53210, dport=53) /
                DNS(id=0x1234, qr=0, qd=DNSQR(qname="example.com", qtype="A")))
    pkts.append(Ether(src="00:11:22:33:44:fe", dst="00:11:22:33:44:01") /
                IP(src="192.168.1.1", dst="192.168.1.50") /
                UDP(sport=53, dport=53210) /
                DNS(id=0x1234, qr=1, rcode=0, qd=DNSQR(qname="example.com", qtype="A"),
                    an=DNSRR(rrname="example.com", rdata="93.184.216.34")))

    # Successful TCP 3-way handshake & teardown
    pkts.append(Ether(src="00:11:22:33:44:01", dst="00:11:22:33:44:fe") /
                IP(src="192.168.1.50", dst="93.184.216.34") /
                TCP(sport=49152, dport=80, flags="S", seq=1000))
    pkts.append(Ether(src="00:11:22:33:44:fe", dst="00:11:22:33:44:01") /
                IP(src="93.184.216.34", dst="192.168.1.50") /
                TCP(sport=80, dport=49152, flags="SA", seq=5000, ack=1001))
    pkts.append(Ether(src="00:11:22:33:44:01", dst="00:11:22:33:44:fe") /
                IP(src="192.168.1.50", dst="93.184.216.34") /
                TCP(sport=49152, dport=80, flags="A", seq=1001, ack=5001))
    pkts.append(Ether(src="00:11:22:33:44:01", dst="00:11:22:33:44:fe") /
                IP(src="192.168.1.50", dst="93.184.216.34") /
                TCP(sport=49152, dport=80, flags="FA", seq=1001, ack=5001))
    pkts.append(Ether(src="00:11:22:33:44:fe", dst="00:11:22:33:44:01") /
                IP(src="93.184.216.34", dst="192.168.1.50") /
                TCP(sport=80, dport=49152, flags="FA", seq=5001, ack=1002))
    pkts.append(Ether(src="00:11:22:33:44:01", dst="00:11:22:33:44:fe") /
                IP(src="192.168.1.50", dst="93.184.216.34") /
                TCP(sport=49152, dport=80, flags="A", seq=1002, ack=5002))

    # Apply timestamps
    for i, p in enumerate(pkts):
        p.time = base_time + (i * 0.05)

    path = os.path.join(output_dir, "normal_traffic.pcap")
    wrpcap(path, pkts)
    generated_files["normal_traffic"] = path

    # =========================================================================
    # 2. TCP Retransmission Scenario
    # =========================================================================
    pkts = []
    # Handshake
    pkts.append(Ether() / IP(src="10.0.0.5", dst="10.0.0.100") / TCP(sport=50001, dport=443, flags="S", seq=100))
    pkts.append(Ether() / IP(src="10.0.0.100", dst="10.0.0.5") / TCP(sport=443, dport=50001, flags="SA", seq=500, ack=101))
    pkts.append(Ether() / IP(src="10.0.0.5", dst="10.0.0.100") / TCP(sport=50001, dport=443, flags="A", seq=101, ack=501))

    # Data Segment 1 (Seq 101 to 601, len 500)
    payload_chunk = b"X" * 500
    pkts.append(Ether() / IP(src="10.0.0.5", dst="10.0.0.100") / TCP(sport=50001, dport=443, flags="PA", seq=101, ack=501) / payload_chunk)

    # Retransmission 1 of Data Segment 1
    pkts.append(Ether() / IP(src="10.0.0.5", dst="10.0.0.100") / TCP(sport=50001, dport=443, flags="PA", seq=101, ack=501) / payload_chunk)

    # Retransmission 2 of Data Segment 1
    pkts.append(Ether() / IP(src="10.0.0.5", dst="10.0.0.100") / TCP(sport=50001, dport=443, flags="PA", seq=101, ack=501) / payload_chunk)

    # Data Segment 2 (Seq 601 to 1101)
    pkts.append(Ether() / IP(src="10.0.0.5", dst="10.0.0.100") / TCP(sport=50001, dport=443, flags="PA", seq=601, ack=501) / payload_chunk)
    # Retransmission of Data Segment 2
    pkts.append(Ether() / IP(src="10.0.0.5", dst="10.0.0.100") / TCP(sport=50001, dport=443, flags="PA", seq=601, ack=501) / payload_chunk)

    for i, p in enumerate(pkts):
        p.time = base_time + (i * 0.1)

    path = os.path.join(output_dir, "tcp_retransmission.pcap")
    wrpcap(path, pkts)
    generated_files["tcp_retransmission"] = path

    # =========================================================================
    # 3. TCP Reset (RST) Scenario
    # =========================================================================
    pkts = []
    # Connection attempts receiving RST
    for p_offset in range(5):
        client_port = 40000 + p_offset
        pkts.append(Ether() / IP(src="192.168.10.15", dst="192.168.10.80") / TCP(sport=client_port, dport=8080, flags="S", seq=1000 + p_offset))
        pkts.append(Ether() / IP(src="192.168.10.80", dst="192.168.10.15") / TCP(sport=8080, dport=client_port, flags="R", seq=0, ack=1001 + p_offset))

    for i, p in enumerate(pkts):
        p.time = base_time + (i * 0.08)

    path = os.path.join(output_dir, "tcp_reset_burst.pcap")
    wrpcap(path, pkts)
    generated_files["tcp_reset_burst"] = path

    # =========================================================================
    # 4. Incomplete TCP Handshake (SYN Timeout)
    # =========================================================================
    pkts = []
    for retry in range(4):
        pkts.append(Ether() / IP(src="10.1.1.20", dst="10.1.1.99") / TCP(sport=55100, dport=443, flags="S", seq=2000 + (retry * 10)))

    for i, p in enumerate(pkts):
        p.time = base_time + (i * 1.5)

    path = os.path.join(output_dir, "incomplete_handshake.pcap")
    wrpcap(path, pkts)
    generated_files["incomplete_handshake"] = path

    # =========================================================================
    # 5. DNS Failures (NXDOMAIN, SERVFAIL, Unanswered)
    # =========================================================================
    pkts = []
    # Query 1: NXDOMAIN
    pkts.append(Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=61001, dport=53) /
                DNS(id=0xAA01, qr=0, qd=DNSQR(qname="this-domain-does-not-exist-xyz123.com", qtype="A")))
    pkts.append(Ether() / IP(src="8.8.8.8", dst="192.168.1.10") / UDP(sport=53, dport=61001) /
                DNS(id=0xAA01, qr=1, rcode=3, qd=DNSQR(qname="this-domain-does-not-exist-xyz123.com", qtype="A")))

    # Query 2: SERVFAIL
    pkts.append(Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=61002, dport=53) /
                DNS(id=0xAA02, qr=0, qd=DNSQR(qname="broken-internal-zone.corp.local", qtype="A")))
    pkts.append(Ether() / IP(src="8.8.8.8", dst="192.168.1.10") / UDP(sport=53, dport=61002) /
                DNS(id=0xAA02, qr=1, rcode=2, qd=DNSQR(qname="broken-internal-zone.corp.local", qtype="A")))

    # Query 3: Unanswered query
    pkts.append(Ether() / IP(src="192.168.1.10", dst="10.99.99.99") / UDP(sport=61003, dport=53) /
                DNS(id=0xAA03, qr=0, qd=DNSQR(qname="unreachable-resolver.org", qtype="A")))

    for i, p in enumerate(pkts):
        p.time = base_time + (i * 0.2)

    path = os.path.join(output_dir, "dns_failures.pcap")
    wrpcap(path, pkts)
    generated_files["dns_failures"] = path

    # =========================================================================
    # 6. ARP Conflict / Spoofing Scenario
    # =========================================================================
    pkts = []
    # Legitimate owner of 192.168.1.1 has MAC 00:aa:bb:cc:dd:01
    pkts.append(Ether(src="00:aa:bb:cc:dd:01", dst="ff:ff:ff:ff:ff:ff") /
                ARP(op=2, hwsrc="00:aa:bb:cc:dd:01", psrc="192.168.1.1", hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.1.1"))

    # Conflicting / Rogue MAC claiming 192.168.1.1 (MAC 00:de:ad:be:ef:99)
    for i in range(6):
        pkts.append(Ether(src="00:de:ad:be:ef:99", dst="ff:ff:ff:ff:ff:ff") /
                    ARP(op=2, hwsrc="00:de:ad:be:ef:99", psrc="192.168.1.1", hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.1.1"))

    for i, p in enumerate(pkts):
        p.time = base_time + (i * 0.5)

    path = os.path.join(output_dir, "arp_conflict.pcap")
    wrpcap(path, pkts)
    generated_files["arp_conflict"] = path

    # =========================================================================
    # 7. Vertical & Horizontal Port Scan Scenario
    # =========================================================================
    pkts = []
    scanner_ip = "192.168.50.200"
    target_ip = "192.168.50.10"

    # Vertical scan: 25 distinct ports on target_ip
    for target_port in range(20, 45):
        pkts.append(Ether() / IP(src=scanner_ip, dst=target_ip) / TCP(sport=54321, dport=target_port, flags="S", seq=100))
        # Closed ports reply with RST
        if target_port not in (22, 80):
            pkts.append(Ether() / IP(src=target_ip, dst=scanner_ip) / TCP(sport=target_port, dport=54321, flags="R", seq=0, ack=101))

    # Horizontal sweep: Sweeping port 445 across 12 distinct hosts
    for host_suffix in range(10, 22):
        sweep_dst = f"192.168.50.{host_suffix}"
        pkts.append(Ether() / IP(src=scanner_ip, dst=sweep_dst) / TCP(sport=55000, dport=445, flags="S", seq=500))

    for i, p in enumerate(pkts):
        p.time = base_time + (i * 0.05)

    path = os.path.join(output_dir, "port_scan_recon.pcap")
    wrpcap(path, pkts)
    generated_files["port_scan_recon"] = path

    # =========================================================================
    # 8. Multi-Server DHCP Scenario
    # =========================================================================
    pkts = []
    # DHCP Discover from client
    client_mac = "00:1a:2b:3c:4d:5e"
    pkts.append(Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=client_mac.encode(), xid=0x112233) /
                DHCP(options=[("message-type", "discover"), "end"]))

    # Server 1 Offer
    pkts.append(Ether(src="00:50:56:00:01:01", dst=client_mac) /
                IP(src="192.168.1.1", dst="192.168.1.150") /
                UDP(sport=67, dport=68) /
                BOOTP(yiaddr="192.168.1.150", chaddr=client_mac.encode(), xid=0x112233) /
                DHCP(options=[("message-type", "offer"), ("server_id", "192.168.1.1"), "end"]))

    # Server 2 (Rogue / Secondary) Offer
    pkts.append(Ether(src="00:50:56:99:99:99", dst=client_mac) /
                IP(src="192.168.1.254", dst="192.168.1.200") /
                UDP(sport=67, dport=68) /
                BOOTP(yiaddr="192.168.1.200", chaddr=client_mac.encode(), xid=0x112233) /
                DHCP(options=[("message-type", "offer"), ("server_id", "192.168.1.254"), "end"]))

    for i, p in enumerate(pkts):
        p.time = base_time + (i * 0.1)

    path = os.path.join(output_dir, "dhcp_multi_server.pcap")
    wrpcap(path, pkts)
    generated_files["dhcp_multi_server"] = path

    print(f"Successfully generated {len(generated_files)} sample PCAPs in '{output_dir}'.")
    return generated_files


if __name__ == "__main__":
    generate_all_samples()
