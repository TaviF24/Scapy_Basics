import base64
import socket
from scapy.all import *
from scapy.layers.dns import DNS, DNSRR, DNSQR

listenIpAddress = '0.0.0.0'
listenPort = 54

# query the DNS to get the TXT responses
def queryDNS(domain):
    dnsRequest = DNS(
        rd = 1, 
        qd = DNSQR(qname = domain,
                   qtype = "TXT"))
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientSocket.settimeout(2)

    fileChunks = []
    # get Base32 response, decode it and save it into fileChunks to be returned
    try:
        clientSocket.sendto(bytes(dnsRequest), (listenIpAddress, listenPort))
        while True:
            try:
                response, _ = clientSocket.recvfrom(65535)
                dnsResponse = DNS(response)
                for i in range(dnsResponse.ancount):
                    dResponse = dnsResponse.an[i]
                    if dResponse == 16:              #TXT record
                        data = dResponse.rdata.decode('utf-8').strip('"')
                    fileChunks.append(base64.b32decode(data))
            except socket.timeout:
                break
    except Exception as e:
        print(f'An error occurred: {e}')
    finally:
        clientSocket.close()

    return fileChunks

# combine the chunks into a txt file
def reconstructFile(domain):
    fileChunks = queryDNS(domain)
    fileContent = b"".join(fileChunks)
    with open(f'reconstruct_{domain}', 'wb') as file:
        file.write(fileContent)
    return f'reconstruct_{domain}'

domain = "fisierTest.tunel.live"
filePath = reconstructFile(domain)
print(f'Received and reconstructed file into {filePath}')
