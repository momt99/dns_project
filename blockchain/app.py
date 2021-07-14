import os

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from flask import Flask, request

from certificate_authority.csrgenerator import create_csr
from certificate_authority.validator import verify_certificate
from utils.auth import verify_auth_header
from utils.signing import *

app = Flask(__name__)

my_id = '1020156016'

if not os.path.exists("assets"):
    os.mkdir("assets")

key, csr = create_csr("localhost:7000")

cert = requests.post('http://127.0.0.1:5000/sign', data=csr.public_bytes(serialization.Encoding.PEM),
                     verify=False, headers={'Content-type': 'application/octet-stream'})

with open('assets/certificate.pem', "w") as f:
    f.write(cert.text)

# each account has a 'value', 'password' and an array of policies.
account = dict({})
account['135702468'] = dict({'value': 100000, 'password': '1234', 'policies': []})
account['0987654321'] = dict({'value': 20000, 'password': '4321', 'policies': []})


@app.route('/exchange', methods=['POST'])
def exchange():
    try:
        data = request.json
        certificate = x509.load_pem_x509_certificate(data['certificate'])
        header = data['header']
        try:
            verify_auth_header(header, certificate.public_key(), my_id)
        except InvalidSignature:
            return 'Signature Not Match', 450
        if not verify_certificate(certificate):
            return "Invalid Certificate", 451
        # todo: check value and bank id by policy.
    except ValueError:
        return "Bad create account data", 400
