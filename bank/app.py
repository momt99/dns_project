import os
import random

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import requests
from flask import Flask, request

from certificate_authority.csrgenerator import create_csr
from utils.auth import verify_auth_header

app = Flask(__name__)

my_id = '1349283455'

if not os.path.exists("assets"):
    os.mkdir("assets")

key, csr = create_csr("localhost:6000")

cert = requests.post('http://127.0.0.1:5000/sign', data=csr.public_bytes(serialization.Encoding.PEM),
                     verify=False, headers={'Content-type': 'application/octet-stream'})

with open('assets/certificate.pem', "w") as f:
    f.write(cert.text)

accounts = dict({})
payments = dict({})


@app.route('/create', methods=['POST'])
def create():
    try:
        data = request.json
        certificate = x509.load_pem_x509_certificate(data['certificate'])
        public_key = certificate.public_key()
        try:
            public_key.verify(data['signature'], data['ID'] + '|' + my_id,
                              padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                              hashes.SHA256())
        except InvalidSignature:
            return 'Signature Not Match', 450
        if accounts.__contains__(data[0]):
            return "Account already exists", 300
        accounts[data[0]] = dict({'value': 0, 'public key': public_key})
        return "Account created successfully", 201
    except ValueError:
        return "Bad create account data", 400


@app.route('/payment', methods=['POST'])
def payment():
    try:
        data = request.json
        amount = data["amount"]
        validity = data["validity"]
        callback = data["callback"]
        auth_header = request.headers.get("Authorization")
        auth_data = auth_header.split("|")
        seller_id = auth_data[0]
        bank_id = auth_data[1]
        if bank_id != my_id:
            return "Authentication failed.", 401
        verify_auth_header(auth_header, accounts[seller_id]["public key"])
        payment_id = seller_id.__hash__() * int(amount) + random.randint(1, 100000000)
        payments[payment_id] = {"seller_id": seller_id, "callback": callback, "validity": validity, "validated": False}
        return payment_id, 200
    except InvalidSignature:
        return "Authentication failed.", 401
    except ValueError:
        return "Bad create account data", 400


@app.route('/transaction/<payment_id>/approve', methods=['POST'])
def approve(payment_id):
    try:
        auth_header = request.headers.get("Authorization")
        auth_data = auth_header.split("|")
        seller_id = auth_data[0]
        bank_id = auth_data[1]
        if bank_id != my_id:
            return "Authentication failed.", 401
        verify_auth_header(auth_header, accounts[seller_id]["public key"])
    except:
        return "Authentication Failed."
    payments[payment_id]["validate"] = True


with open('assets/key.pem', "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
    ))

app.run(ssl_context=('assets/certificate.pem', 'assets/key.pem'), port=6000)
