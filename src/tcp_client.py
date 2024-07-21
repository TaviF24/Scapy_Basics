# TCP client
import socket
import logging
import time
import random

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

port = 10000
adresa = '198.7.0.2'
server_address = (adresa, port)

try:
    sock.connect(server_address)
    logging.info('Handshake cu %s', str(server_address))
    mesaje = ["Mesaj1", "Mesaj2", "Mesaj3", "Mesaj4", "Mesaj5"]
    while True:
        mesaj = random.choice(mesaje)
        time.sleep(1)
        sock.send(mesaj.encode('utf-8'))
        data = sock.recv(1024)
        if len(data) == 0:
            break
        logging.info('Server: "%s"', data)
        print(len(data))
finally:
    logging.info('Closing socket')
    sock.close()
