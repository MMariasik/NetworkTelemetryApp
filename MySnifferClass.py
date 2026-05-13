from scapy.all import sniff, IP, TCP, UDP, ICMP, AsyncSniffer

class MySniffer:
    def __init__(self, interface):
        self.sniffer = AsyncSniffer(
            iface=interface, 
            prn=self.detailed_callback, 
            store=0
        )
        self.sniffer.start()
        print(f"Sniffing on \"{interface}\"... Press Ctrl+C to stop.")
    
    def __del__(self):
        self.sniffer.stop()

    def detailed_callback(self, packet):
        PODSLUCH = False  # Set to False to disable detailed output (for cleaner console)
        if PODSLUCH:
            print("-" * 50)
            # 1. Print the high-level summary (e.g., "Ether / IP / TCP 1.1.1.1:80 > 2.2.2.2:54321 S")
            print(f"SUMMARY: {packet.summary()}")

            # 2. Check for specific layers and extract data
            if packet.haslayer(IP):
                ip_layer = packet.getlayer(IP)
                print(f"SRC IP: {ip_layer.src} | DST IP: {ip_layer.dst} | TTL: {ip_layer.ttl}")

            if packet.haslayer(TCP):
                tcp_layer = packet.getlayer(TCP)
                print(f"Type: TCP | Port: {tcp_layer.sport} -> {tcp_layer.dport} | Flags: {tcp_layer.flags}")

            if packet.haslayer(UDP):
                udp_layer = packet.getlayer(UDP)
                print(f"Type: UDP | Port: {udp_layer.sport} -> {udp_layer.dport} | Len: {udp_layer.len}")

            if packet.haslayer(ICMP):
                print("Type: ICMP (Ping)")

            # 3. UNCOMMENT the line below if you want to see EVERYTHING (huge output)
            packet.show() 
