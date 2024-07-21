import sys
import socket
import traceback
import requests

apiUrl = "http://ip-api.com/json/"

# info geolocatie pentru un IP
def getIpInfo(address):
    try:
        fake_HTTP_header = {
                    'referer': 'https://ipinfo.io/',
                    'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36'
                }
        raspuns = requests.get(apiUrl + address, headers = fake_HTTP_header).json()
        if raspuns['status'] == 'success':
            return raspuns
        print(raspuns)
        return None
    except Exception as e:
        print("Error get IP: ", str(e))
        return None

def traceroute(addressRequest, maxHops = 30, timeout = 20, port = 33434):
    ip = socket.gethostbyname(addressRequest)

    # info geolocatie despre IP-ul local
    currentIpJson = getIpInfo('')
    if currentIpJson is None:
        print("Error in getting current IP information")
        localIp, country, region, city = 'Unknown', 'Unknown', 'Unknown', 'Unknown'
    else:
        localIp = currentIpJson['query']
        country = currentIpJson['country']
        region = currentIpJson['regionName']
        city = currentIpJson['city']

    outputFileList = []
    outputFileList.append("###########################################\n")
    outputFileList.append(f"Traceroute to {addressRequest} ({ip}) with max hops {maxHops} and timeout {timeout}\n")
    outputFileList.append(f"Local IP: {localIp}\t\t{country}, {region}, {city}\n")

    print((f"Traceroute to {addressRequest} ({ip}) with max hops {maxHops} and timeout {timeout}\n"))    

    # socket de UDP
    udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)

    # socket RAW de citire a răspunsurilor ICMP
    icmp_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    # setam timout in cazul in care socketul ICMP la apelul recvfrom nu primeste nimic in buffer
    icmp_recv_socket.settimeout(timeout)

    # setam TTL in headerul de IP pentru socketul de UDP
    TTL = 1

    while True:
        udp_send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, TTL)

        icmp_recv_socket.bind(('', port))

        # trimite un mesaj UDP catre un tuplu (IP, port)
        udp_send_sock.sendto(bytes("", "UTF-8"), (ip, port))

        # asteapta un mesaj ICMP de tipul ICMP TTL exceeded messages
        # in cazul nostru nu verificăm tipul de mesaj ICMP
        # puteti verifica daca primul byte are valoarea Type == 11
        # https://tools.ietf.org/html/rfc792#page-5
        # https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Header
        addr = 'done!'
        try:
            data, addr = icmp_recv_socket.recvfrom(63535)
        except Exception as e:
            print("Socket timeout ", str(e))
            print(traceback.format_exc())

            # sar peste daca nu raspunde ...?
            TTL += 1
            continue
        
        addr = addr[0]
        
        ICMPHeader = data[20:24]

        print(f"{TTL}\t{str(addr).ljust(17)}", end = '\t')
        outputFileList.append(f"{TTL}\t{str(addr).ljust(17)}\t")

        # exclud ip-urile private si rezervate

        # 192.168.0.0/24 - 10.0.0.0/8 - 172.16.0.0/12
        if addr.startswith('192.168.') or addr.startswith('10.') or (addr.startswith('172.') and int(addr.split('.')[1]) in range(16, 32)):
            print("private")
            outputFileList.append("private\n")
        # 100.64.0.0/10 - 224.0.0.0/4 -240.0.0.0/4
        elif (addr.startswith('100.') and int(addr.split('.')[1]) in range(64, 127)) or int(addr.split('.')[0]) in list(range(224, 239)) + list(range(240, 255)):
            print("reserved")
            outputFileList.append("reserved\n")
        else:
            # info geolocatie despre IP-ul gasit
            ipInformationJson = getIpInfo(addr)
            if ipInformationJson is not None:
                country = ipInformationJson['country']
                region = ipInformationJson['regionName']
                city = ipInformationJson['city']
                print(f"{country}, {region}, {city}")
                outputFileList.append(f"{country}, {region}, {city}\n")
            else:
                print("Error in getting IP information")
                outputFileList.append("Error in getting IP information\n")
            
        # 11 == ICMP Time Exceeded
        if ICMPHeader[0] != 11: # or addr == ip:
            break

        if TTL > maxHops:
            print("max hops exceeded")
            outputFileList.append("max hops exceeded\n")
            break

        TTL += 1
    
    with open("tracerouteOutput/output.txt", "a") as outputFile:
        outputFile.writelines(''.join(outputFileList))

'''
 Exercitiu hackney carriage (optional)!
    e posibil ca ipinfo sa raspunda cu status code 429 Too Many Requests
    cititi despre campul X-Forwarded-For din antetul HTTP
        https://www.nginx.com/resources/wiki/start/topics/examples/forwarded/
    si setati-l o valoare in asa fel incat
    sa puteti trece peste sistemul care limiteaza numarul de cereri/zi

    Alternativ, puteti folosi ip-api (documentatie: https://ip-api.com/docs/api:json).
    Acesta permite trimiterea a 45 de query-uri de geolocare pe minut.
'''

# # exemplu de request la IP info pentru a
# # obtine informatii despre localizarea unui IP
# fake_HTTP_header = {
#                     'referer': 'https://ipinfo.io/',
#                     'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36'
#                    }
# # informatiile despre ip-ul 193.226.51.6 pe ipinfo.io
# # https://ipinfo.io/193.226.51.6 e echivalent cu
# raspuns = requests.get('https://ipinfo.io/widget/193.226.51.6', headers=fake_HTTP_header)
# print (raspuns.json())

# # pentru un IP rezervat retelei locale da bogon=True
# raspuns = requests.get('https://ipinfo.io/widget/10.0.0.1', headers=fake_HTTP_header)
# print (raspuns.json())

if len(sys.argv) < 2:
    print("Usage: python3 traceroute.py <ip address> [max_hops] [timeout]")
    sys.exit(1)
elif len(sys.argv) == 2:
    traceroute(sys.argv[1])
elif len(sys.argv) == 3:
    traceroute(sys.argv[1], int(sys.argv[2]))
elif len(sys.argv) == 4:
    traceroute(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))