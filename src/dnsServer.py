import os
import base64
import socket
from scapy.all import *
from scapy.layers.dns import DNS, DNSRR

listenIpAddress = '0.0.0.0'
listenPort = 54
upStreamDNS = '8.8.8.8'

# split the file into multile chuncks having a given size
# and encode it in Base32
def splitFile(filePath, chunkSize=255):
    with open(filePath, 'rb') as file:
        while chunk := file.read(chunkSize):
            yield base64.b32encode(chunk)


# Forward DNS request to upstream DNS server
def forwardDNSReq(packetDNS):
    try:
        sendSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sendSocket.settimeout(2)
        sendSocket.sendto(bytes(packetDNS), (upStreamDNS, 53))
        response, _ = sendSocket.recvfrom(65535)

        if DNS(response).rcode == 3:
            print('NXDOMAIN\nDomain name does not exist')
            return None
        return DNS(response)[DNSRR].rdata
    except Exception as e:
        print(f'Forward DNS: {e}')
        return None


# Send NXDOMAIN response
def domainNameNonExistent(packetDNS, adresa_sursa):
    dns_response = DNS(
        id=packetDNS[DNS].id,
        qr=1,
        aa=0,
        rcode=3,
        qd=packetDNS.qd)
    print('NXDOMAIN error response')
    print()
    simple_udp.sendto(bytes(dns_response), adresa_sursa)


# Send nameserver response
def sendNSResponse(packetDNS, adresa_sursa):
    dns_response = DNS(
        id=packetDNS[DNS].id,
        qr=1,
        aa=1,
        rcode=0,
        qd=packetDNS.qd,
        ns=DNSRR(
            rrname=packetDNS.qd.qname,
            type='NS',
            ttl=330,
            rdata='ns-cloud-a1.googledomains.com'
        )
    )
    print('NS response')
    print()
    simple_udp.sendto(bytes(dns_response), adresa_sursa)


# domain lookup in depth (delegation permited)
def resolveFinalIPAddress(domain):
    visited = set()
    while domain in knownHosts:
        if domain in visited:
            print(f"Circular reference detected for {domain}")
            return None
        visited.add(domain)
        next_hop = knownHosts[domain]
        if next_hop.replace('.', '').isdigit():  # verify if current domain is an IP
            return next_hop
        print(f"{domain} delegated to {next_hop}")
        domain = next_hop
    return None


with open('dnsKnownHosts', 'r') as file:
    knownHosts = file.read().strip().split('\n')
    knownHosts = {host.split(';')[0]: host.split(';')[1] for host in knownHosts}

simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
simple_udp.bind((listenIpAddress, listenPort))

# spliting the transferable file into chunks
filePath = "fisierTest.tunel.live"
fileChunks = list(splitFile(filePath))

while True:
    request, adresa_sursa = simple_udp.recvfrom(65535)
    # convertim payload-ul in pachet scapy
    packet = DNS(request)
    dns = packet.getlayer(DNS)
    if dns is not None and dns.opcode == 0:  # dns QUERY
        print("got: ")
        print(packet.summary())
        print(f"name: {dns.qd.qname}")

        # nameserver response
        if len(dns.qd.qname.decode()) < 2:  # dig @localhost
            sendNSResponse(packet, adresa_sursa)
            continue

        # check if request is file transfer
        if "fisierTest.tunel.live" in dns.qd.qname.decode():
                dnsResponse = DNS(
                    id = packet[DNS].id,
                    qr = 1,
                    aa = 0,
                    rcode = 0,
                    qd = packet.qd,
                    an = []
                )
                for chunckIndex in range(len(fileChunks)):
                    encodedChunk = fileChunks[chunckIndex].decode('utf-8')
                    dnsResponse.an.append(DNSRR(
                        rrname = dns.qd.qname,
                        ttl = 330,
                        type = 'TXT',
                        # rrclass = 'IN',
                        rdata = encodedChunk
                    ))
                    print(f'Sent chunk {chunckIndex} from fisierTest.tunel.live')
                simple_udp.sendto(bytes(dnsResponse), adresa_sursa)
        # normal DNS
        else:
            final_ip = resolveFinalIPAddress(dns.qd.qname.decode())
            if final_ip:        # known hosts response  
                dns_answer = DNSRR(  	    # DNS Reply
                    rrname=dns.qd.qname,  	# for question
                    ttl=330,  		        # DNS entry Time to Live
                    type="A",
                    rclass="IN",
                    rdata=final_ip)
            # forward DNS response
            else:               # dig @localhost google.com
                print("Forwarding DNS to google.com")
                ipAddress = forwardDNSReq(packet)
                if ipAddress is None:
                    # domain name does not exist
                    domainNameNonExistent(packet, adresa_sursa) 
                    continue
                dns_answer = DNSRR(         # DNS Reply
                    rrname=dns.qd.qname,    # for question
                    ttl=330,                # DNS entry Time to Live
                    type="A",
                    rclass="IN",
                    rdata=ipAddress)
            dns_response = DNS(
                id=packet[DNS].id,  # DNS replies must have the same ID as requests
                qr=1,  		        # 1 for response, 0 for query
                aa=0,  		        # Authoritative Answer
                rcode=0,  		    # 0, nicio eroare http://www.networksorcery.com/enp/protocol/dns.htm#Rcode,%20Return%20code
                qd=packet.qd,  	    # request-ul original
                an=dns_answer)  	# obiectul de reply
            simple_udp.sendto(bytes(dns_response), adresa_sursa)
            print('response:')
            print(dns_response.summary())
            print()

simple_udp.close()
