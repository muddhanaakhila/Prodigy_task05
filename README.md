from scapy.all import sniff, TCP, IP, Raw, UDP, ICMP

# Define a function to process each packet
def process_packet(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"IP Packet: {src_ip} -> {dst_ip}")

        # Check if the packet has a TCP layer
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

            # Check if the packet has a Raw layer (payload data)
            if Raw in packet:
                payload = packet[Raw].load
                print(f"Payload: {payload}")

        # Check if the packet has a UDP layer
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"UDP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        # Check if the packet has an ICMP layer
        elif ICMP in packet:
            print(f"ICMP Packet: {src_ip} -> {dst_ip}")

# Start sniffing packets
sniff(prn=process_packet)
