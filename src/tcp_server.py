# TCP Server
import socket
import logging
import time

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

port = 10000
adresa = '0.0.0.0'
server_address = (adresa, port)
sock.bind(server_address)
logging.info("Serverul a pornit pe %s si portnul portul %d", adresa, port)
sock.listen(5)
conexiune = None
try:
    while True:
        logging.info('Asteptam conexiui...')
        conexiune, address = sock.accept()
        logging.info("Handshake cu %s", address)
        while True:
            time.sleep(2)
            data = conexiune.recv(1024)
            if len(data) == 0:
                break
            logging.info('Content primit: "%s"', data)
            print(len(data))
            conexiune.send(b"Am primit mesajul:"+data)
        conexiune.close()
finally:
    logging.info('Closing server')
    sock.close()
