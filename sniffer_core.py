from scapy.all import sniff, IP, TCP, UDP, ICMP

def start_sniffing(callback_func, stop_event, filter_proto):
    """Fungsi inti untuk menangkap paket di jaringan secara real-time"""
    
    def packet_handler(pkt):
        # Memastikan paket memiliki layer IP (Layer 3)
        if pkt.haslayer(IP):
            protocol = "OTH"
            if pkt.haslayer(TCP): protocol = "TCP"
            elif pkt.haslayer(UDP): protocol = "UDP"
            elif pkt.haslayer(ICMP): protocol = "ICMP"
            
            # Filter protokol sesuai pilihan di GUI
            if filter_proto == "ALL" or protocol == filter_proto:
                # Mengirim data ringkasan DAN objek paket asli (pkt) ke GUI
                data = {
                    "src": pkt[IP].src,
                    "dst": pkt[IP].dst,
                    "proto": protocol,
                    "len": len(pkt),
                    "raw_pkt": pkt  # Objek asli untuk fitur double-click
                }
                callback_func(data)

    # Sniffing berjalan hingga stop_event diset True
    sniff(
        prn=packet_handler, 
        stop_filter=lambda x: stop_event.is_set(), 
        store=0
    )