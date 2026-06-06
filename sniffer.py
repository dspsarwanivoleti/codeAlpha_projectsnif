from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import time
import signal
import sys

# ==============================
# CONFIGURATION
# ==============================

INTERFACE = "wlan0"       # Change if needed (check with ip a)
FLOW_TIMEOUT = 30         # Seconds before flow expires
SUMMARY_INTERVAL = 5      # Summary refresh interval
PRINT_THRESHOLD = 30      # Max packets printed per flow

# ==============================
# GLOBAL DATA
# ==============================

flows = defaultdict(lambda: {
    "packets": 0,
    "bytes": 0,
    "start_time": 0,
    "last_seen": 0
})

protocol_counter = defaultdict(int)
ip_stats = defaultdict(int)

total_packets = 0
total_bytes = 0

last_summary_time = time.time()
last_rate_time = time.time()
packets_this_interval = 0
bytes_this_interval = 0

# ==============================
# CLEANUP OLD FLOWS
# ==============================

def cleanup_flows():
    now = time.time()
    expired = []

    for key, data in flows.items():
        if now - data["last_seen"] > FLOW_TIMEOUT:
            expired.append(key)

    for key in expired:
        del flows[key]

# ==============================
# PRINT SUMMARY
# ==============================

def print_summary():
    global last_summary_time
    global packets_this_interval
    global bytes_this_interval
    global last_rate_time

    now = time.time()

    if now - last_summary_time < SUMMARY_INTERVAL:
        return

    cleanup_flows()

    time_diff = now - last_rate_time
    pps = packets_this_interval / time_diff if time_diff > 0 else 0
    bps = bytes_this_interval / time_diff if time_diff > 0 else 0

    print("\n" + "=" * 70)
    print("         ADVANCED FLOW-BASED NETWORK SNIFFER")
    print("=" * 70)

    print(f"Active Flows        : {len(flows)}")
    print(f"Total Packets       : {total_packets}")
    print(f"Total Bytes         : {total_bytes}")
    print(f"Packets/sec (PPS)   : {pps:.2f}")
    print(f"Bytes/sec (BPS)     : {bps:.2f}")

    print("\nProtocol Breakdown:")
    for proto in ["TCP", "UDP", "ICMP", "OTHER"]:
        count = protocol_counter[proto]
        percent = (count / total_packets * 100) if total_packets else 0
        print(f"  {proto:<6}: {count:<6} ({percent:.2f}%)")

    print("\nTop 5 Talkers:")
    sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1], reverse=True)
    for ip, count in sorted_ips[:5]:
        print(f"  {ip:<15} {count} packets")

    print("=" * 70 + "\n")

    packets_this_interval = 0
    bytes_this_interval = 0
    last_rate_time = now
    last_summary_time = now

# ==============================
# PACKET PROCESSOR
# ==============================

def process_packet(packet):
    global total_packets
    global total_bytes
    global packets_this_interval
    global bytes_this_interval

    if not packet.haslayer(IP):
        return

    total_packets += 1
    total_bytes += len(packet)
    packets_this_interval += 1
    bytes_this_interval += len(packet)

    src = packet[IP].src
    dst = packet[IP].dst
    proto = "OTHER"
    sport = "-"
    dport = "-"

    if packet.haslayer(TCP):
        proto = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport
    elif packet.haslayer(UDP):
        proto = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport
    elif packet.haslayer(ICMP):
        proto = "ICMP"
        sport = 0
        dport = 0

    protocol_counter[proto] += 1
    ip_stats[src] += 1

    flow_key = (src, dst, proto, sport, dport)
    now = time.time()

    flows[flow_key]["packets"] += 1
    flows[flow_key]["bytes"] += len(packet)
    flows[flow_key]["last_seen"] = now

    if flows[flow_key]["start_time"] == 0:
        flows[flow_key]["start_time"] = now

    duration = now - flows[flow_key]["start_time"]
    avg_size = flows[flow_key]["bytes"] / flows[flow_key]["packets"]

    if flows[flow_key]["packets"] <= PRINT_THRESHOLD:
        print(
            f"[{proto:<4}] "
            f"{src}:{sport:<5} → {dst}:{dport:<5} "
            f"| Size: {len(packet):<4}B "
            f"| FlowPkts: {flows[flow_key]['packets']:<3} "
            f"| Duration: {duration:.1f}s "
            f"| AvgSize: {int(avg_size)}B"
        )

    print_summary()

# ==============================
# GRACEFUL EXIT
# ==============================

def signal_handler(sig, frame):
    print("\n\n[+] Sniffer stopped by user.")
    print("[+] Final Statistics:")
    print_summary()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# ==============================
# START
# ==============================

print("🔥 Advanced Professional Network Sniffer Running...\n")

sniff(
    iface=INTERFACE,
    filter="ip",
    prn=process_packet,
    store=False
)
