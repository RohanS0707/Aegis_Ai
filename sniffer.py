# sniffer.py - Real Network Packet Capture (Scapy)
# Run as Administrator on Windows!

import threading
import time
from collections import defaultdict
from packet_engine import process_connection, blocked_ips

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    print("⚠️ Scapy not installed. Run: pip install scapy")

# Connection flow tracker
flows = defaultdict(lambda: {
    "start": time.time(), "spkts": 0, "dpkts": 0,
    "sbytes": 0, "dbytes": 0, "last_seen": time.time(),
    "proto": "tcp",
})
flows_lock = threading.Lock()
FLOW_TIMEOUT = 5  # seconds — analyze flow after 5s of inactivity

def get_proto(pkt):
    if pkt.haslayer(TCP): return "tcp"
    if pkt.haslayer(UDP): return "udp"
    if pkt.haslayer(ICMP): return "icmp"
    return "other"

def packet_callback(pkt):
    if not pkt.haslayer(IP):
        return
    
    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = get_proto(pkt)
    size = len(pkt)

    # Skip localhost
    if src.startswith("127.") or dst.startswith("127."):
        return

    # If already blocked — drop silently
    if src in blocked_ips:
        return

    sport = dport = 0
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

    flow_key = (src, dst, sport, dport, proto)
    rev_key  = (dst, src, dport, sport, proto)

    with flows_lock:
        now = time.time()
        # Forward direction
        flows[flow_key]["spkts"] += 1
        flows[flow_key]["sbytes"] += size
        flows[flow_key]["last_seen"] = now
        flows[flow_key]["proto"] = proto
        # Reverse direction bytes
        if rev_key in flows:
            flows[rev_key]["dpkts"] += 1
            flows[rev_key]["dbytes"] += size


def flow_analyzer():
    """Periodically flush timed-out flows to ML engine"""
    while True:
        time.sleep(2)
        now = time.time()
        to_analyze = []

        with flows_lock:
            expired = [k for k, v in flows.items()
                       if now - v["last_seen"] > FLOW_TIMEOUT]
            for key in expired:
                flow = flows.pop(key)
                to_analyze.append((key, flow))

        for (src, dst, sport, dport, proto), flow in to_analyze:
            if flow["spkts"] < 2:  # Skip single-packet flows
                continue
            result = process_connection(
                src_ip=src, dst_ip=dst,
                sport=sport, dport=dport,
                proto=proto,
                sbytes=flow["sbytes"],
                dbytes=flow["dbytes"],
                spkts=flow["spkts"],
                dpkts=flow["dpkts"],
            )
            if result["is_attack"]:
                print(f"🚨 ATTACK: {src}→{dst}:{dport} | "
                      f"Conf: {result['confidence']:.1f}% | BLOCKED: {result['blocked']}")


def start_sniffer(interface=None):
    """Start packet capture"""
    if not SCAPY_OK:
        print("❌ Scapy not available")
        return

    # Start flow analyzer thread
    threading.Thread(target=flow_analyzer, daemon=True).start()
    print(f"🔍 Starting packet capture on {'all interfaces' if not interface else interface}")
    print("   (Run as Administrator for full access)")
    print("   Press Ctrl+C to stop\n")

    try:
        sniff(
            iface=interface,
            prn=packet_callback,
            store=False,
            filter="ip",  # Only IP packets
        )
    except PermissionError:
        print("❌ Permission denied — Run VS Code / terminal as Administrator!")
    except Exception as e:
        print(f"Sniffer error: {e}")


if __name__ == "__main__":
    # List available interfaces
    if SCAPY_OK:
        print("Available interfaces:")
        for i, iface in enumerate(get_if_list()):
            print(f"  [{i}] {iface}")
        print()
    start_sniffer()  # None = all interfaces
