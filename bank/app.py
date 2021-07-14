import os
import random

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from flask import Flask, request

from utils.csrgenerator import create_csr
from certificate_authority.validator import verify_certificate
from utils.auth import *
from utils.signing import *
from certificate_authority.validator import verify_certificate
from utils.auth import verify_auth_header

import utils.ids

app = Flask(__name__)

my_id = utils.ids.BANK_ID

if not os.path.exists("assets"):
    os.mkdir("assets")

key, csr = create_csr("localhost:6000", "The Bank")

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
        header = data['header']
        user_id = extract_user_id(header)
        public_key = certificate.public_key()
        try:
            verify_auth_header(header, public_key, my_id)
        except InvalidSignature:
            return 'Signature Not Match', 450
        if not verify_certificate(certificate):
            return "Invalid Certificate", 451
        if accounts.__contains__(data[0]):
            return "Account already exists", 300
        accounts[user_id] = dict({'value': 0, 'public key': public_key})
        return "Account created successfully", 201
    except ValueError:
        return "Bad create account data", 400


@app.route('/payment/<string:id>/pay', methods=['POST'])
def pay(id):
    try:
        header = request.data
        user_id = extract_user_id(header)
        if not accounts.__contains__(user_id):
            return "You have not any account in our bank", 440
        try:
            verify_auth_header(header, accounts[user_id]['public key'], my_id)
        except InvalidSignature:
            return "Authentication failed", 450
        amount = str(payments["amount"])
        chosen_hash = hashes.SHA256()
        hasher = hashes.Hash(chosen_hash)
        hasher.update(str.encode(amount))
        hasher.update(str.encode(user_id))
        digest = hasher.finalize()
        sig_amount = to_base64(
            key.sign(digest, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                     hashes.SHA256()))
        tmp = dict({'certificate': cert.text, 'header': create_auth_header(my_id, '1020156016'), 'amount': amount,
                    "user id": user_id, "amount_user_signature": sig_amount})
        req = requests.get(
            f'https://localhost:7000/exchange',
            json={'message': tmp},
            verify='certificate_authority/assets/certificate.pem')
        if req.status_code == 201:
            pass
            # todo: Inform seller and buyer
        else:
            pass
            # todo: Inform seller
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
        verify_auth_header(auth_header, accounts[seller_id]["public key"], my_id)
        payment_id = seller_id.__hash__() * int(amount) + random.randint(1, 100000000)
        payments[payment_id] = {"seller_id": seller_id, "callback": callback, "validity": validity, "validated": False,
                                "amount": amount}
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
        verify_auth_header(auth_header, accounts[seller_id]["public key"], my_id)
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
