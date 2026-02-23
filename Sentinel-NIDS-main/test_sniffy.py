from scapy.all import sniff, IP, TCP

def handle_packet(pkt):
    if IP in pkt:
        print(f"{pkt[IP].src} → {pkt[IP].dst}")

print("Starting sniffing...")
sniff(prn=handle_packet, store=False)