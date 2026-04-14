
# ── Imports ──────────────────────────────────────────────
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
import os
import sys

# ── Configuration ─────────────────────────────────────────
MAX_PACKETS   = 50          # How many packets to capture (change as needed)
LOG_FILE      = "captured_packets.log"   # Output log file name
SHOW_PAYLOAD  = True        # Set False to hide raw payload bytes

# ── Protocol map: number → human-readable name ───────────
PROTOCOL_MAP = {
    1:  "ICMP",   # Ping
    6:  "TCP",    # Web, SSH, FTP …
    17: "UDP",    # DNS, video streams …
}

# ── Packet counter (shared across calls) ──────────────────
packet_count = 0

# ─────────────────────────────────────────────────────────
def format_payload(raw_bytes: bytes, max_chars: int = 80) -> str:
    """
    Try to decode payload as UTF-8 text.
    If that fails, show it as hex bytes instead.
    Only show the first `max_chars` characters to keep output tidy.
    """
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
        # Remove newlines so the log stays on one readable line
        text = text.replace("\n", "\\n").replace("\r", "\\r")
        return text[:max_chars] + ("…" if len(text) > max_chars else "")
    except Exception:
        return raw_bytes.hex()[:max_chars]


# ─────────────────────────────────────────────────────────
def process_packet(packet):
    """
    Called automatically by scapy for EVERY captured packet.
    We pull out the fields we care about and print / log them.
    """
    global packet_count
    packet_count += 1

    timestamp  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip     = "N/A"
    dst_ip     = "N/A"
    protocol   = "Unknown"
    src_port   = ""
    dst_port   = ""
    payload    = ""

    # ── Layer 3: IP header ─────────────────────────────
    if packet.haslayer(IP):
        src_ip   = packet[IP].src
        dst_ip   = packet[IP].dst
        proto_no = packet[IP].proto
        protocol = PROTOCOL_MAP.get(proto_no, f"Proto#{proto_no}")

    # ── Layer 4: TCP ───────────────────────────────────
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags    = packet[TCP].flags   # SYN, ACK, FIN …
        protocol = f"TCP (flags={flags})"

    # ── Layer 4: UDP ───────────────────────────────────
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        protocol = "UDP"

    # ── Application payload (raw bytes) ───────────────
    if SHOW_PAYLOAD and packet.haslayer(Raw):
        payload = format_payload(packet[Raw].load)

    # ── Build the display line ─────────────────────────
    port_info = f"  Ports : {src_port} → {dst_port}" if src_port else ""
    pay_info  = f"\n  Payload: {payload}"             if payload  else ""

    line = (
        f"\n{'─'*60}\n"
        f"  Packet #{packet_count:03d}  [{timestamp}]\n"
        f"  From   : {src_ip}\n"
        f"  To     : {dst_ip}\n"
        f"  Proto  : {protocol}"
        f"{port_info}"
        f"{pay_info}"
    )

    print(line)

    # ── Write same info to the log file ───────────────
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


# ─────────────────────────────────────────────────────────
def main():
    # Friendly banner
    print("=" * 60)
    print("       CodeAlpha — Basic Network Sniffer")
    print("=" * 60)
    print(f"  Capturing up to {MAX_PACKETS} packets …")
    print(f"  Log file : {LOG_FILE}")
    print(f"  Press Ctrl+C to stop early.\n")

    # Write a header to the log file
    with open(LOG_FILE, "w") as f:
        f.write(f"Network Sniffer Log — {datetime.now()}\n")
        f.write("=" * 60 + "\n")

    try:
        # scapy's sniff() does all the heavy lifting:
        #   filter  = BPF filter string (same syntax as tcpdump)
        #             "ip" means capture only IP packets
        #   prn     = function to call for each packet
        #   count   = stop after this many packets (0 = forever)
        #   store   = False means don't keep packets in RAM
        sniff(
            filter="ip",
            prn=process_packet,
            count=MAX_PACKETS,
            store=False,
        )
    except KeyboardInterrupt:
        pass   # Ctrl+C is a normal way to stop

    print(f"\n{'='*60}")
    print(f"  Done! Captured {packet_count} packet(s).")
    print(f"  Full log saved to: {LOG_FILE}")
    print("=" * 60)


# ── Entry point ───────────────────────────────────────────
if __name__ == "__main__":
    # Warn if not running as Administrator (Windows) or root (Linux/Mac)
    import platform
    if platform.system() == "Windows":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[WARNING] Not running as Administrator. Packet capture may fail.")
            print("          Right-click CMD → 'Run as Administrator'\n")
    else:
        if os.geteuid() != 0:
            print("[WARNING] Not running as root. Packet capture may fail.")
            print("          Try: sudo python3 task1_network_sniffer.py\n")
    main()
