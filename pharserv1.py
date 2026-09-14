from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, sniff


def identify_traffic(packet):
    """Callback function to analyze and classify captured packets."""
    # Ensure the packet contains an IP layer
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = "UNKNOWN"
    info = ""

    # 1. Identify Transport Layer Protocol & Ports
    if packet.haslayer(TCP):
        proto = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # Check for HTTP payload
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            if (
                b"GET" in payload
                or b"POST" in payload
                or b"HTTP/" in payload
            ):
                proto = "HTTP"
                # Extract host/request line if available
                first_line = payload.split(b"\r\n")[0]
                info = f"Request: {first_line.decode(errors='ignore')}"

        # Standard Web Traffic heuristic
        elif dst_port == 443 or src_port == 443:
            proto = "HTTPS (TLS)"

    elif packet.haslayer(UDP):
        proto = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

        # Check for DNS traffic
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            proto = "DNS"
            query_name = packet[DNSQR].qname.decode(errors="ignore")
            info = f"Query: {query_name}"

    # Print parsed network traffic summary
    if proto in ["TCP", "UDP"]:
        print(
            f"[{proto}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} {info}".strip()
        )
    else:
        print(f"[{proto}] {src_ip} -> {dst_ip} {info}".strip())


def start_parser(interface=None, packet_count=0):
    """Starts sniffing and parsing network traffic.

    - interface: Network interface (e.g., 'eth0', 'wlan0', 'Wi-Fi'). Uses default if None.
    - packet_count: Number of packets to capture (0 = continuous).
    """
    print(
        f"[*] Starting traffic parser on {interface or 'default interface'}..."
    )
    sniff(iface=interface, prn=identify_traffic, store=False, count=packet_count)


if __name__ == "__main__":
    # Run continuous parser (Press Ctrl+C to stop)
    start_parser()