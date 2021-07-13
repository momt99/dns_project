import time
from random import random
import uuid

from cryptography.hazmat.primitives import serialization
from flask import Flask, request
import requests

seller_id = "SELLER"


app = Flask(__name__)

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

app.run(port=8081, ssl_context=('assets/certificate.pem', 'assets/key.pem'))
