import json
import os
import time
from utils.urls import BANK_URL
import utils.ids
import uuid
from datetime import datetime

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from flask import Flask, request

from utils.csrgenerator import create_csr
from certificate_authority.validator import verify_certificate
from utils.auth import create_auth_header, verify_auth_header

my_id = utils.ids.SELLER_ID
bank_id = utils.ids.BANK_ID

app = Flask(__name__)

if not os.path.exists("assets"):
    os.mkdir("assets")

key, csr = create_csr("localhost:6000", "The Seller")

cert = requests.post('http://127.0.0.1:5000/sign', data=csr.public_bytes(serialization.Encoding.PEM),
                     verify=False, headers={'Content-type': 'application/octet-stream'})

with open('assets/certificate.pem', "w") as f:
    f.write(cert.text)

items = {1: 100, 2: 200, 3: 300, 4: 400, 5: 500}
customers_paymentid_dict = dict()


@app.route('<customer_id>/buy/<item_id>', methods=['POST'])
def buy(customer_id, item_id):
    auth_header = request.headers.get("Authorization")
    data = request.json
    try:
        verify_certificate(x509.load_pem_x509_certificate(data["certificate"]))
        verify_auth_header(auth_header, load_pem_public_key(data["public_key"]), my_id)
    except:
        return "Authentication failed.", 201
    payment_amount = items[int(item_id)]
    payment_id = str(uuid.uuid4())
    call_back_url = "http://localhost:8081/validate_payment/" + payment_id
    validity = 3600
    customers_paymentid_dict[payment_id] = [customer_id, time.time(), validity, payment_amount, None, False]
    req = {"validity": validity, "callback": call_back_url, "amount": payment_amount}
    auth_header = create_auth_header(my_id, bank_id, private_key=key)
    headers = {'content-type': 'application/json', "Authorization": auth_header}
    payment_bank_id = requests.post(f"{BANK_URL}/payment", json.dumps(req), headers=headers)
    customers_paymentid_dict[payment_id][-2] = payment_bank_id
    return payment_bank_id


@app.route('/validate_payment/<payment_id>', methods=['POST'])
def validate(payment_id):
    data = request.json
    bank_cert = x509.load_pem_x509_certificate(data["certificate"])
    bank_public_key = load_pem_public_key(data["public_key"])
    try:
        verify_certificate(bank_cert)
        verify_auth_header(request.headers.get("Authorization"), bank_public_key, my_id)
    except:
        return "Authentication Failed", 401
    customers_paymentid_dict[payment_id][-1] = True
    payment_bank_id = customers_paymentid_dict[payment_id][-2] = True
    requests.post(f"{BANK_URL}/transaction/" + str(payment_bank_id) + "/approve")



def create_bank_account():
    sign = my_id + "|" + bank_id
    sign = key.sign(sign)
    data = {"ID": my_id, "certificate": cert.text, "signature": sign}
    res = requests.post(f"{BANK_URL}/create", data, verify=False)  # TODO: verify with ca key.
    assert res.status_code == 201


create_bank_account()

app.run(port=8081, ssl_context=('assets/certificate.pem', 'assets/key.pem'))
