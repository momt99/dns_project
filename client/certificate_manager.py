import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization.base import load_pem_private_key
from cryptography.x509.base import load_pem_x509_certificate
import requests
from requests.models import Response
from utils import csrgenerator, paths, urls
from utils import cert_server
from queue import Queue
import logging

KEY_PATH = 'client/assets/key.pem'
CERT_PATH = 'client/assets/cert.pem'
KEY_PASS = b"THE_CLIENT_PASS"

if not os.path.exists('client/assets'):
    os.mkdir('client/assets')

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler())


def obtain_certificate():
    port = 14001
    key, csr = csrgenerator.create_csr(
        f'http://localhost:{port}', "The Client")

    with open(KEY_PATH, "wb") as file:
        file.write(key.private_bytes(
            encoding=Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(
                KEY_PASS),
        ))
        logger.info(f'Private key generated and stored in: {KEY_PATH}')

    message_queue = Queue()
    t: cert_server.ServerThread = cert_server.create_cert_listener_server(
        port, KEY_PATH, KEY_PASS, message_queue)
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
        logger.info(
            f'Certificate successfully loaded and stored in {CERT_PATH}.')


def load_certificate() -> bytes:
    with open(CERT_PATH, "rb") as file:
        return file.read()

def load_private_key() -> RSAPrivateKey:
    with open(KEY_PATH, "rb") as file:
        return load_pem_private_key(file.read(), KEY_PASS)
