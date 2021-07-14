import json
import os
import time

from utils import headers, auth
from utils.cert_helper import obtain_certificate, logger
from utils.encoding import to_base64, from_base64
from utils.paths import CA_CERT_PATH
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

key = obtain_certificate('seller/assets', 8081, 'The Seller')
auth.default_private_key = key
with open('seller/assets/cert.pem', 'rb') as f:
    cert = x509.load_pem_x509_certificate(f.read())

items = {1: 100, 2: 200, 3: 300, 4: 400, 5: 500}
customers_paymentid_dict = dict()


@app.route('/<customer_id>/buy/<item_id>', methods=['POST'])
def buy(customer_id, item_id):
    auth_header = request.headers.get("Authorization")
    data = request.json
    try:
        cert = x509.load_pem_x509_certificate(from_base64(data["certificate"]))
        verify_certificate(cert)
        verify_auth_header(auth_header, cert.public_key(), my_id)
    except:
        return "Authentication failed.", 401
    payment_amount = items[int(item_id)]
    payment_id = str(uuid.uuid4())
    call_back_url = "https://localhost:8081/validate_payment/" + payment_id
    validity = 3600
    customers_paymentid_dict[payment_id] = [
        customer_id, time.time(), validity, payment_amount, None, False]
    req = {"validity": validity, "callback": call_back_url,
           "amount": payment_amount}
    auth_header = create_auth_header(my_id, bank_id, private_key=key)
    headers = {'content-type': 'application/json',
               "Authorization": auth_header}
    response = requests.post(
        f"{BANK_URL}/payment", json.dumps(req), headers=headers, verify=False)
    response.raise_for_status()
    payment_bank_id = response.text
    customers_paymentid_dict[payment_id][-2] = payment_bank_id
    return {'payment_id': payment_bank_id, 'amount': payment_amount}, 201


@app.route('/validate_payment/<payment_id>', methods=['POST'])
def validate(payment_id):
    data = request.json
    bank_cert = x509.load_pem_x509_certificate(from_base64(data["certificate"]))
    try:
        verify_certificate(bank_cert)
        verify_auth_header(request.headers.get(
            "Authorization"), bank_cert.public_key(), my_id)
    except:
        return "Authentication Failed", 401
    customers_paymentid_dict[payment_id][-1] = True
    payment_bank_id = customers_paymentid_dict[payment_id][-2] = True
    res = requests.post(f"{BANK_URL}/transaction/" +
                  str(payment_bank_id) + "/approve", verify=False)
    res.raise_for_status()
    return "Ok", 200


def create_bank_account():
    sign = my_id + "|" + bank_id
    sign = key.sign(sign)
    data = {"ID": my_id, "certificate": cert.text, "signature": sign}
    # TODO: verify with ca key.
    res = requests.post(f"{BANK_URL}/create", data, verify=False)
    assert res.status_code == 201


def create_bank_account():
    data = {
        'certificate': to_base64(cert.public_bytes(serialization.Encoding.PEM))
    }
    response = requests.post(
        f'{BANK_URL}/create',
        json=data,
        headers={headers.AUTHORIZATION: create_auth_header(my_id, bank_id)},
        verify=False
    )
    response.raise_for_status()

    logger.info('Bank account created successfully.')


create_bank_account()

app.run(port=8081, ssl_context=('seller/assets/cert.pem', 'seller/assets/key.pem'))
