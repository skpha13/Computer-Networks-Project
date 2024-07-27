import socket
from scapy.all import *
import math
import base64
import concurrent.futures as thread_mod
simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
simple_udp.bind(('0.0.0.0', 53))

logging_file = open("logging.txt",'w')

cache  = dict()





def process_req(request,adresa_sursa):
    packet = DNS(request)
    dns = packet.getlayer(DNS)
    
    if dns is not None and dns.opcode == 0: # dns QUERY
            
        logging_file.write("got "+str(dns.qd.qname)+'\n')
        
        query =  str(dns.qd.qname).split("@")
        
        if query[-1]=="size.nota10.rosualbastru.live.'": # get the number of 255 segments 
            file_name  = str(query[0])[2:]
            file_name = file_name.replace("-",'.')
            with  open(file_name,'rb') as f:
                contents = base64.b64encode(f.read())
                cache[file_name] = contents
                size = len(contents)
                nr_segments = math.ceil(size/255)
                
                dns_answer = DNSRR(      # DNS Reply
                rrname=dns.qd.qname, # for question
                ttl=330,             # DNS entry Time to Live
                type="TXT",            
                rclass="IN",
                rdata=str(nr_segments))    
                dns_response = DNS(
                                id = packet[DNS].id, # DNS replies must have the same ID as requests
                                qr = 1,              # 1 for response, 0 for query 
                                aa = 0,              # Authoritative Answer
                                rcode = 0,           # 0, nicio eroare http://www.networksorcery.com/enp/protocol/dns.htm#Rcode,%20Return%20code
                                qd = packet.qd,      # request-ul original
                                an = dns_answer)     # obiectul de reply
        
                simple_udp.sendto(bytes(dns_response), adresa_sursa)
        elif len(query)==2:
            logging_file.write("got "+str(dns.qd.qname)+'\n')
            segment_number = int(query[-1][:-27])
            file_name  = str(query[0])[2:]
            file_name = file_name.replace('-','.')
            content_file_Nsegment = cache[file_name][segment_number*255:(segment_number+1)*255] # assume the first segment is 0, so 0 based indexing 
            
            dns_answer = DNSRR(      # DNS Reply
                rrname=dns.qd.qname, # for question
                ttl=330,             # DNS entry Time to Live
                type="TXT",               
                rclass="IN",
                rdata=content_file_Nsegment)    
            dns_response = DNS(
                            id = packet[DNS].id, # DNS replies must have the same ID as requests
                            qr = 1,              # 1 for response, 0 for query 
                            aa = 0,              # Authoritative Answer
                            rcode = 0,           # 0, nicio eroare http://www.networksorcery.com/enp/protocol/dns.htm#Rcode,%20Return%20code
                            qd = packet.qd,      # request-ul original
                            an = dns_answer)     # obiectul de reply
    
            simple_udp.sendto(bytes(dns_response), adresa_sursa)


while True:
    with thread_mod.ThreadPoolExecutor(1000) as pool_ex:
        request, adresa_sursa = simple_udp.recvfrom(1025)
        pool_ex.submit(process_req,request,adresa_sursa)
