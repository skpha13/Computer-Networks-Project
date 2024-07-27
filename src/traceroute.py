'''
    Resurse:

- https://www.nslookup.io/domains/google.com/webservers/
- https://stackoverflow.com/questions/11865685/handling-a-timeout-error-in-python-sockets
- https://resrequest.helpspot.com/index.php?pg=kb.page&id=437
- https://www.liveaction.com/glossary/internet-control-message-protocol-icmp/
- https://www.rfc-editor.org/rfc/rfc792
- https://medium.com/@MonlesYen/python-for-cybersecurity-29-sniffer-vi-decode-icmp-47a917d6ab42
- https://gist.github.com/pklaus/856268#file-ping-py-L124
'''

import socket
import struct
import random 
import requests
import json
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from mpl_toolkits.basemap import Basemap

class NetworkPlot:
    df_list = []
    df = pd.DataFrame(columns=['lat', 'lon'])
    colorList = ['orange', 'yellow', 'lawngreen', 'darkgreen', 'aquamarine', 'darkslategrey', \
                  'deepskyblue', 'royalblue', 'mediumslateblue', 'violet', 'indigo']

    @staticmethod
    def insertCoordinates(lat, lon):
        if NetworkPlot.df.empty:
            NetworkPlot.df = pd.DataFrame({'lat': [lat], 'lon': [lon]})
        else:
            NetworkPlot.df = pd.concat([NetworkPlot.df, pd.DataFrame({'lat': [lat], 'lon': [lon]})], ignore_index=True)

    @staticmethod
    def resetDataFrame():
        NetworkPlot.df = pd.DataFrame(columns=['lat', 'lon'])

    @staticmethod
    def appendDataFrame():
        if not NetworkPlot.df.empty:
            NetworkPlot.df_list.append(NetworkPlot.df)

    @staticmethod
    def resetPlot():
        NetworkPlot.df_list = []
        NetworkPlot.df = pd.DataFrame(columns=['lat', 'lon'])

    @staticmethod
    def plot():
        plt.figure(figsize=(16, 9))
        map = Basemap(projection='mill', llcrnrlat=-90, urcrnrlat=90, llcrnrlon=-180, urcrnrlon=180, resolution='c') 
        map.drawcoastlines()

        for (index, dataFrame) in enumerate(NetworkPlot.df_list):
            x, y = map(dataFrame['lon'].values, dataFrame['lat'].values)
            map.plot(x, y, marker='o', markersize=5, color='red')

            color = NetworkPlot.colorList[index % len(NetworkPlot.colorList)]
            map.plot(x, y, marker=None, color=color)

        plt.title('Network')
        plt.show()

class IPInfo:
    fake_HTTP_header = {
        'referer': 'https://ipinfo.io/',
        'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36'
    }

    lastVisitedCountry = ""
    
    @staticmethod
    def getLocation(ipAddress="", useIPinfo=False):
        if not useIPinfo:
            response = requests.get(f'http://ip-api.com/json/{ipAddress}?fields=lat,lon,country,city,region', headers=IPInfo.fake_HTTP_header)
        else:
            response = requests.get(f'https://ipinfo.io/widget/{ipAddress}', headers=IPInfo.fake_HTTP_header)

        try:
            response = json.loads(response.text)
        except Exception as e:
            # it means we got 429 http error code
            return "{:<18} {:<8} {:<18}".format(f'HTTP Error Code: {response.status_code}', "", "")

        try:
            try:
                if not IPInfo.lastVisitedCountry == response['country']:
                    NetworkPlot.insertCoordinates(response['lat'], response['lon'])

                IPInfo.lastVisitedCountry = response['country']
            except AttributeError as atr:
                pass

            return "{:<18} {:<8} {:<18}".format(response["country"], response["region"], response["city"])
        except KeyError as err:
            return 'Private IP'


# socket de UDP
udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)

# socket RAW de citire a răspunsurilor ICMP
icmp_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
# setam timout in cazul in care socketul ICMP la apelul recvfrom nu primeste nimic in buffer
icmp_recv_socket.settimeout(3)

def getRandomPort():
    return random.randint(33434, 33534)

def traceroute(ip, port):
    # setam TTL in headerul de IP pentru socketul de UDP
    # TTL = 64
    print("{:<8} {:<20} {:<18} {:<8} {:<18}".format('TTL', 'IP', 'COUNTRY', 'REGION', 'CITY'))
    IPInfo.getLocation()

    for ttl in range(1, 33):
        udp_send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

        # trimite un mesaj UDP catre un tuplu (IP, port)
        udp_send_sock.sendto(b'salut', (ip, port))

        # asteapta un mesaj ICMP de tipul ICMP TTL exceeded messages
        # in cazul nostru nu verificăm tipul de mesaj ICMP
        # puteti verifica daca primul byte are valoarea Type == 11
        # https://tools.ietf.org/html/rfc792#page-5
        # https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Header
        addr = 'done!'
        hasThrownError = False
        try:
            data, addr = icmp_recv_socket.recvfrom(63535)
            ipAddress = addr[0]

        except Exception as e:
            # print("Socket timeout ", str(e))
            # print(traceback.format_exc())
            print("{:<8} {:<20} {:<20} {:<8} {:<18}".format(ttl, 'Request Timed Out', "", "", ""))
            hasThrownError = True
            # return 

        if hasThrownError == False:
            print("{:<8} {:<20}".format(ttl, ipAddress), end=" ")
            print(IPInfo.getLocation(ipAddress))

            # header-ul unui pachet ICMP incepe de la 20 si merge pana la 28
            icmp_header = data[20:28]
            # in ordinea asta se afla type, code, checksum si alte 2 chestii de care nu avem nevoie
            type, code, _, _, _ = struct.unpack('bbHHh', icmp_header)

            # daca type-ul e 3 => am avut un Destination Unreachable Message
            # daca codul e 1 => host unreachable
            # daca codul e 3 => port unreachable
            # daca aceste conditii sunt indeplinite ne oprim, inseamna ca s-a raspuns cu destination/port
            # unreachable => am ajuns la destinatie
            if type == 3 and (code == 1 or code == 3):
                break

    NetworkPlot.appendDataFrame()
    NetworkPlot.resetDataFrame()
    print('Trace Complete')
    return ipAddress

# google IPv4 address
traceroute('142.251.32.46', getRandomPort())

# pcauto.com.cn        Asia
# traceroute('14.29.101.168', getRandomPort())

# NetworkPlot.plot()

# bidvestbank.co.za    Africa
# traceroute('20.87.217.143', getRandomPort())

# nzstadium.com.au     Australia
# traceroute('52.64.132.90', getRandomPort())