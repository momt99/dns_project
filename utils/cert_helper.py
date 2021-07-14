from werkzeug.serving import make_server
from flask import Flask, request
from utils.encoding import from_base64, to_base64
from utils import paths, urls
from threading import Thread
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.base import load_pem_x509_certificate
import requests
from requests.models import Response
from utils import csrgenerator, paths, urls
from queue import Queue
import logging


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler())


def obtain_certificate(
    files_path: str,
    port: int,
    organization_name: str,
    key_pass = b"f",
    key_file_name='key.pem',
    cert_file_name='cert.pem'
):
    if not os.path.exists(files_path):
        os.mkdir(files_path)
    key_path = os.path.join(files_path, key_file_name)
    cert_path = os.path.join(files_path, cert_file_name)

    key, csr = csrgenerator.create_csr(
        f'http://localhost:{port}', organization_name)

    with open(key_path, "wb") as file:
        file.write(key.private_bytes(
            encoding=Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(
                key_pass),
        ))
        logger.info(f'Private key generated and stored in: {key_path}')

    message_queue = Queue()
    t: ServerThread = create_cert_listener_server(
        port, key_path, key_pass, message_queue)
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

    with open(cert_path, "wb") as file:
        file.write(cert.public_bytes(serialization.Encoding.PEM))
        logger.info(
            f'Certificate successfully loaded and stored in {cert_path}.')


class ServerThread(Thread):

    def __init__(self, app, port):
        Thread.__init__(self)
        self.server = make_server('127.0.0.1', port, app)
        self.context = app.app_context()
        self.context.push()

    def run(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()


def create_cert_listener_server(
        port: int,
        private_key_path: str,
        private_key_pass: bytes,
        message_queue: Queue) -> ServerThread:

    app = Flask(__name__)

    @app.route('/box', methods=['POST'])
    def box():
        body = request.json
        id = body['id']
        secret_message = body['message']

        with open(private_key_path, "rb") as file:
            key = serialization.load_pem_private_key(
                file.read(), private_key_pass)
            from utils.signing import get_default_encryption_padding
            message = key.decrypt(
                from_base64(secret_message),
                get_default_encryption_padding())

            response = requests.post(
                f'{urls.CA_URL}/authenticate/{id}',
                json={'message': to_base64(message)},
                verify=paths.CA_CERT_PATH)

            message_queue.put(response)

        return "Done", 200

    return ServerThread(app, port)
