import scapy.all as scapy
from netfilterqueue import NetfilterQueue as NFQ
import os

global forSeq, forAck   #stocam valorile seq si ack ale pachetelor pentru a permite comunicarea corespunzatoare dupa manipulare
forSeq = dict()                                        #(nu e de ajuns sa schimbam doar load-ul)
forAck = dict()

def alter_packet(pachet): #ne cream un nou pachet aproximativ identic cu cel dat ca parametru si pe acela il vom trimite
    pachetNou = pachet
    if pachet.haslayer(scapy.IP) and pachet.haslayer(scapy.TCP):
        currentSeq = pachet[scapy.TCP].seq
        currentAck = pachet[scapy.TCP].ack
        nextSeq = currentSeq
        if currentSeq in forSeq.keys():
            nextSeq = forSeq[currentSeq]
        nextAck = currentAck
        if currentAck in forAck.keys():
            nextAck = forAck[currentAck]


        msg = pachet[scapy.TCP].payload
        if "P" in pachet[scapy.TCP].flags: #nu are sens sa modificam pachetul daca nu are flag-ul PSH, ce inseamna ca se trimite un mesaj
            msg = pachet[scapy.Raw].load + b'---Alterat'

        pachetNou = (scapy.IP(src = pachet[scapy.IP].src, dst = pachet[scapy.IP].dst)/
                     scapy.TCP(sport = pachet[scapy.TCP].sport, dport = pachet[scapy.TCP].dport, seq = nextSeq, ack = nextAck, flags = pachet[scapy.TCP].flags)/
                     msg)
        pachetNou = scapy.IP(pachetNou.build())
        forSeq[currentSeq + len(pachet[scapy.TCP].payload)] = nextSeq + len(msg)
        forAck[nextSeq + len(msg)] = currentSeq + len(pachet[scapy.TCP].payload)

        print("Pachet dupa: ")
        pachetNou[scapy.IP].show()
    scapy.send(pachetNou)

def proceseaza(pachet):
    octeti = pachet.get_payload()
    scapy_packet = scapy.IP(octeti)
    print("Pachet inainte: ")
    scapy_packet.show()
    alter_packet(scapy_packet)

queue = NFQ()
try:
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 5") #toate pachetele ce vin, vor fi redirectionate intr-o coada pentru a le prelucra
    queue.bind(5, proceseaza)
    queue.run()
except KeyboardInterrupt:
    os.system("iptables --flush")  #stergem toate regulile
    print("Stopping")
    queue.unbind()




