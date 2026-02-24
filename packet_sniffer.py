
# packet_sniffer.py
# A simple network packet sniffer using Scapy

from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(packet):
    print("="*60)
    
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")
        print(f"Protocol       : {ip_layer.proto}")
        
        # Identify protocol type
        if TCP in packet:
            print("Protocol Name  : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
        elif UDP in packet:
            print("Protocol Name  : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
        elif ICMP in packet:
            print("Protocol Name  : ICMP")
        
        # Display payload (if available)
        if packet.payload:
            print(f"Payload        : {bytes(packet.payload)}")

def main():
    print("Starting Packet Sniffer... Press Ctrl+C to stop.")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    main()
