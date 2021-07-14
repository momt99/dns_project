import datetime
import os

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509.base import load_pem_x509_certificate
from flask import Flask, request

from blockchain.models import Policy
from certificate_authority.validator import verify_certificate
from utils.auth import verify_auth_header, extract_user_id
from utils.csrgenerator import create_csr
from utils.encoding import *
from utils.signing import *

app = Flask(__name__)

my_id = '1020156016'

if not os.path.exists("assets"):
    os.mkdir("assets")

key, csr = create_csr("localhost:7000", "blockchain")

cert = requests.post('https://127.0.0.1:5000/sign', data=csr.public_bytes(serialization.Encoding.PEM),
                     verify=False, headers={'Content-type': 'text/plain'})

with open('assets/certificate.pem', "w") as f:
    f.write(cert.text)

# each account has a 'value', 'password' and an array of policies.
account = dict({})
account['135702468'] = dict(
    {'value': 100000, 'password': '1234', 'policies': [], 'last_payment': datetime.datetime.utcnow()})
account['0987654321'] = dict(
    {'value': 20000, 'password': '4321', 'policies': [], 'last_payment': datetime.datetime.utcnow()})

each_dollar_how_much_crypto = 200


def permit_transaction(bank_id, amount, account_id):
    from datetime import datetime
    for policy in account[account_id]["policies"]:
        if policy[0] == bank_id:
            p: Policy = policy[1]
            check = datetime.utcfromtimestamp(p.end_time * 1.0) >= datetime.utcnow() >= datetime.utcfromtimestamp(p.start_time * 1.0) \
                and p.count >= 0 and p.maximum_amount >= amount
            if check:
                return True
    return False


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
        amount = int(data['amount'])
        user_id = data['user id']
        chosen_hash = hashes.SHA256()
        hasher = hashes.Hash(chosen_hash)
        hasher.update(str.encode(str(amount)))
        hasher.update(str.encode(user_id))
        digest = hasher.finalize()
        amount_user_signature = from_base64(data['amount_user_signature'])
        try:
            certificate.public_key().verify(amount_user_signature, digest, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                                       salt_length=padding.PSS.MAX_LENGTH),
                                            utils.Prehashed(chosen_hash))
        except InvalidSignature:
            return 'Amount signature Not Match', 452
        bank_id = extract_user_id(header)
        if permit_transaction(bank_id, amount, user_id):
            account[user_id]['value'] -= amount * each_dollar_how_much_crypto
            return "Successful payment", 201
        else:
            return "Permission Denied", 403

    except ValueError:
        return "Bad create account data", 400


@app.route("/delegate")
def delegate():
    data = request.json
    try:
        verify_certificate(
            load_pem_x509_certificate(from_base64(data["certificate"])))
        pub_key = data["public_key"]
        bank_id = data["bank_id"]
        user_id = data["user_id"]
        policy = Policy.from_bytes(from_base64(data["policy"]))
        sign = data["signature"]
        pub_key = load_pem_public_key(bytes(pub_key, "utf-8"))
        verify_signature(pub_key, sign, bytes(bank_id, 'ascii') + policy)
        account[user_id]["policies"].append((bank_id, policy))
        return "Created.", 201
    except ValueError:
        return "Bad create account data", 400

app.run(ssl_context=('assets/certificate.pem', 'assets/key.pem'), port=7000)
