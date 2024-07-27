# TCP Server
import socket
import logging
import time

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

port = 10000
adresa = '198.7.0.2'
server_address = (adresa, port)
sock.bind(server_address)
logging.info("Serverul a pornit pe %s si portnul portul %d", adresa, port)
sock.listen(5)

try:
    while True:
        logging.info('Asteptam conexiuni...')
        conexiune, address = sock.accept()
        logging.info("Handshake cu %s", address)
        time.sleep(2)

        try:
            while True:
                time.sleep(1)

                data = conexiune.recv(1024)
                logging.info('Content primit: "%s"', data)
                conexiune.send(b"Server a primit mesajul: " + data)
        finally:
            logging.info(f'Inchidem conexiunea cu {address}')
            conexiune.close()
finally:
    logging.info('closing socket')
    sock.close()
