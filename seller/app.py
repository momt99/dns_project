import os
import time
import uuid

import requests
from cryptography.hazmat.primitives import serialization
from flask import Flask

from certificate_authority.csrgenerator import create_csr

my_id = '134986483465'

app = Flask(__name__)


if not os.path.exists("assets"):
    os.mkdir("assets")

key, csr = create_csr("localhost:6000")

cert = requests.post('http://127.0.0.1:5000/sign', data=csr.public_bytes(serialization.Encoding.PEM),
                     verify=False, headers={'Content-type': 'application/octet-stream'})

with open('assets/certificate.pem', "w") as f:
    f.write(cert.text)

items = {1: 100, 2: 200, 3: 300, 4: 400, 5: 500}
customers_paymentid_dict = dict()


@app.route('<customer_id>/buy/<item_id>', methods=['POST'])
def buy(customer_id, item_id):
    # TODO: validate client

    payment_amount = items[int(item_id)]
    payment_id = str(uuid.uuid4())
    call_back_url = "http://localhost:8081/validate_payment/" + payment_id
    validity = 3600
    # TODO: sent this information to server
    customers_paymentid_dict[payment_id] = [customer_id, time.time(), validity, payment_amount, False]
    req = {"validity": validity, "callback": call_back_url, "amount": payment_amount}
    auth_header = ""  # TODO: sign id.
    requests.post()
    pass


@app.route('/validate_payment/<payment_id>', methods=['POST'])
def validate(payment_id):
    # TODO: validate server
    customers_paymentid_dict[payment_id][-1] = True
    # TODO: validate payment (send approve request) when bank completed.
    requests.post()
    pass


def create_bank_account():
    bank_id = "1349283455"
    sign = my_id + "|" + bank_id
    sign = key.sign(sign)
    data = {"ID": my_id, "certificate": cert.text, "signature": sign}
    res = requests.post("https://localhost:6000/create", data, verify=False)  # TODO: verify with ca key.
    assert res.status_code == 201


create_bank_account()

app.run(port=8081, ssl_context=('assets/certificate.pem', 'assets/key.pem'))

