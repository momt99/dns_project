import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.base import load_pem_x509_certificate
import requests
from requests.models import Response
from utils import csrgenerator, paths, urls
from utils import cert_server
from queue import Queue
import logging

KEY_PATH = 'client/assets/key.pem'
CERT_PATH = 'client/assets/cert.pem'

if not os.path.exists('client/assets'):
    os.mkdir('client/assets')

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler())

def obtain_certificate():
    port = 14001
    key, csr = csrgenerator.create_csr(
        f'http://localhost:{port}', "The Client")
    key_pass = b"THE_CLIENT_PASS"
    with open(KEY_PATH, "wb") as file:
        file.write(key.private_bytes(
            encoding=Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(
                key_pass),
        ))
        logger.info(f'Private key generated and stored in: {KEY_PATH}')
        
    message_queue = Queue()
    t: cert_server.ServerThread = cert_server.create_cert_listener_server(
        port, KEY_PATH, key_pass, message_queue)
    t.start()
    logger.info(f'Certificate approver server started.')

    response = requests.post(f'{urls.CA_URL}/certificate',
                             csr.public_bytes(Encoding.PEM),
                             headers={'Content-type': 'text/plain'},
                             verify=paths.CA_CERT_PATH)
    response.raise_for_status()

    cert_response: Response = message_queue.get()
    logger.info(f'Certificate response retrieved.')
    t.shutdown()

    cert_response.raise_for_status()
    # Ensuring that everything is okay
    cert = load_pem_x509_certificate(cert_response.content)

    with open(CERT_PATH, "wb") as file:
        file.write(cert.public_bytes(serialization.Encoding.PEM))
        logger.info(f'Certificate successfully loaded and stored in {CERT_PATH}.')
