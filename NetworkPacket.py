from scapy.all import *

def packet_handler(packet):
    print("IN")
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        print(f"Source IP: {src_ip} -> Destination IP: {dst_ip}")
    if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
    elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
    else:
            src_port, dst_port = None, None
            print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}")
            print(f"Source Port: {src_port}, Destination Port: {dst_port}")

        # Print payload data (if present)
    if packet.payload:
            print(f"Payload: {packet.payload}")
# Sniff IP packets (you can adjust the filter as needed)
sniff(filter="ip", prn=packet_handler)
print("I am running...!")
