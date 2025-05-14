# DISCLAIMER: Use this tool ONLY on networks you own or have explicit permission to monitor.

from scapy.all import sniff, IP, TCP, UDP

def packet_handler(packet):
    # Extract basic packet details
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        # Get protocol name (6=TCP, 17=UDP)
        if protocol == 6:
            proto_name = "TCP"
            payload = str(packet[TCP].payload) if packet.haslayer(TCP) else ""
        elif protocol == 17:
            proto_name = "UDP"
            payload = str(packet[UDP].payload) if packet.haslayer(UDP) else ""
        else:
            proto_name = "Other"
            payload = ""
        
        # Print packet info
        print(f"Source: {src_ip} → Destination: {dst_ip} | Protocol: {proto_name}")
        print(f"Payload (snippet): {payload[:50]}...\n")

# Start sniffing (capture 10 packets as an example)
print("Starting packet sniffer... Press Ctrl+C to stop.")
sniff(prn=packet_handler, count=10)