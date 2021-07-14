from queue import Queue
from threading import Thread
from utils import paths, urls
import requests
from utils.encoding import from_base64, to_base64
from cryptography.hazmat.primitives import serialization
from flask import Flask, request
from werkzeug.serving import make_server


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
