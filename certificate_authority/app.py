from cryptography.hazmat.primitives import serialization
from flask import Flask, request
import cert_issuer

app = Flask(__name__)


@app.route('/sign', methods=['POST'])
def sign():
    if not (request.content_type == 'application/octet-stream'
            or request.content_type == 'text/plain'):
        return "Bad content type.", 400

    from cryptography.x509 import load_pem_x509_csr
    try:
        csr = load_pem_x509_csr(request.data)
        cert = cert_issuer.issue_certificate(csr)
        return cert.public_bytes(encoding=serialization.Encoding.PEM), 201
    except ValueError:
        return "Bad certificate data.", 400


app.run(ssl_context=('assets/certificate.pem', 'assets/key.pem'))
