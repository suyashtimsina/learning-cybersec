import argparse
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, conf, sniff, load_layer
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import TLS_Ext_ServerName

# Force Scapy to use Windows native Layer 3 sockets
conf.L3socket = conf.L3socket

# Load the TLS module to parse HTTPS handshakes natively
load_layer("tls")

def identify_traffic(packet):
    # [Keep your existing identify_traffic logic exactly the same here!]
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # 1. DNS Queries
    if packet.haslayer(UDP) and packet.haslayer(DNS) and packet.haslayer(DNSQR):
        query_name = packet[DNSQR].qname.decode(errors="ignore").strip('.')
        print(f"[DNS Lookup] {src_ip} requested IP for -> {query_name}")
        return

    # 2. HTTPS SNI
    if packet.haslayer(TCP) and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
        if packet.haslayer(TLSClientHello):
            for ext in packet[TLSClientHello].ext:
                if isinstance(ext, TLS_Ext_ServerName) and len(ext.servernames) > 0:
                    domain = ext.servernames[0].servername.decode('utf-8', errors='ignore')
                    print(f"[HTTPS Connection] {src_ip} is visiting -> {domain}")
                    return

def parse_arguments():
    """Sets up the command line arguments for the tool."""
    # 1. Initialize the ArgumentParser
    parser = argparse.ArgumentParser(
        description="DomainTracker: A lightweight network traffic and website tracker.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # 2. Define the expected arguments
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (e.g., 'Wi-Fi' or 'eth0')")
    parser.add_argument("-p", "--pcap", help="Path to an offline PCAP file to analyze")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (default: 0 = infinite)")

    # 3. Parse and return the arguments provided by the user
    return parser.parse_args()

def start_parser(args):
    """Starts the sniffing process based on user arguments."""
    
    # Check if the user provided a PCAP file
    if args.pcap:
        print(f"[*] Analyzing offline PCAP file: {args.pcap}...")
        # Scapy's 'offline' parameter reads from a file instead of a live network adapter
        sniff(offline=args.pcap, prn=identify_traffic, store=False)
        print("[*] PCAP analysis complete.")
        
    # Otherwise, do live network sniffing
    else:
        iface_text = args.interface if args.interface else "default interface"
        print(f"[*] Starting live Website Tracker on {iface_text}...")
        print(f"[*] Capturing {args.count if args.count > 0 else 'infinite'} packets. Press Ctrl+C to stop.")
        
        # Scapy's 'iface' and 'count' parameters handle the live logic perfectly
        sniff(iface=args.interface, count=args.count, prn=identify_traffic, store=False)

if __name__ == "__main__":
    # Get the arguments from the terminal, then pass them to the parser
    user_args = parse_arguments()
    start_parser(user_args)