
from utils.encoding import from_base64, to_base64
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_csr
from flask import Flask, request
import requests
from flask_sqlalchemy import SQLAlchemy
from certificate_authority import database


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ca.db'
database.db = SQLAlchemy(app)


# This method should be removed

@app.route('/sign', methods=['POST'])
def sign():
    if not (request.content_type == 'application/octet-stream'
            or request.content_type == 'text/plain'):
        return "Bad content type.", 400

    try:
        from certificate_authority import cert_issuer
        csr = load_pem_x509_csr(request.data)
        cert = cert_issuer.issue_certificate(csr)
        return cert.public_bytes(encoding=serialization.Encoding.PEM), 201
    except ValueError:
        return "Bad certificate data.", 400


@app.route('/certificate', methods=['POST'])
def certificate():
    if not (request.content_type == 'application/octet-stream'
            or request.content_type == 'text/plain'):
        return "Bad content type.", 400

    try:
        from certificate_authority import cert_issuer
        id, trust_address, secret_message = cert_issuer.define_sign_request(
            request.data)
    except ValueError as e:
        print(e)
        return "Bad certificate signing request data.", 400

    try:
        response = requests.post(
            trust_address+'/box',
            json={
                'id': id,
                'message': to_base64(secret_message)
            },
            verify='certificate_authority/assets/certificate.pem')
        response.raise_for_status()
    except Exception as e:
        print(e)
        return "Couldn't send secret message to the destination.", 400

    return "Successful!", 200


@app.route('/authenticate/<string:id>', methods=['POST'])
def authenticate(id):
    message = request.json['message']
    from certificate_authority import cert_issuer
    cert_bytes = cert_issuer.verify_decrypted_message_and_issue(
        id, from_base64(message))

    return str(cert_bytes, encoding='ascii')


@app.route('/box', methods=['POST'])
def box():
    body = request.json
    id = body['id']
    secret_message = body['message']

    with open("certificate_authority/assets/keytest.pem", "rb") as file:
        key = serialization.load_pem_private_key(file.read(), None)
        from utils.signing import get_default_encryption_padding
        message = key.decrypt(
            from_base64(secret_message),
            get_default_encryption_padding())
        requests.post(
            f'https://localhost:5000/authenticate/{id}',
            json={'message': to_base64(message)},
            verify='certificate_authority/assets/certificate.pem')

    return "Done", 200


app.run(ssl_context=(
        'certificate_authority/assets/certificate.pem',
        'certificate_authority/assets/key.pem'))
