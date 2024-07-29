from scapy.all import sniff, wrpcap

packets = []

def packet_callback(packet):
    packets.append(packet)
    print(packet.show())

def main():
    print("Starting network sniffer...")
    sniff(prn=packet_callback, store=0)
    wrpcap('captured_packets.pcap', packets)

if __name__ == "__main__":
    main()
