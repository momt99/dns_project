from utils import headers
from utils.urls import BANK_URL, SELLER_URL
from utils.ids import BANK_ID, SELLER_ID
import utils.auth
from utils.auth import create_auth_header
from utils.encoding import to_base64
import requests
from client.certificate_manager import load_certificate, load_private_key, load_public_key, obtain_certificate
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())

obtain_certificate()

cert = load_certificate()
private_key = load_private_key()
public_key = load_public_key()
utils.auth.default_private_key = private_key

logger.info("Certificate and public key generation is done!")


USER_ID = "THE_CLIENT"


def create_bank_account():
    data = {
        'certificate': to_base64(cert)
    }
    response = requests.post(
        f'{BANK_URL}/create',
        json=data,
        headers={headers.AUTHORIZATION: create_auth_header(USER_ID, BANK_ID)}
    )
    response.raise_for_status()


def buy_item():
    data = {
        'certificate': to_base64(cert),
        'public_key': to_base64(public_key),
    }

    response = requests.post(
        f'{SELLER_URL}/{USER_ID}/buy/2',
        json=data,
        headers={headers.AUTHORIZATION: create_auth_header(USER_ID, SELLER_ID)})
    response.raise_for_status()

    return response.json["payment_id"]


def pay_item(payment_id):

    response = requests.post(
        f'{BANK_URL}/payment/{payment_id}/pay',
        headers={headers.AUTHORIZATION: create_auth_header(USER_ID, BANK_ID)}
    )
    response.raise_for_status()


create_bank_account()
payment_id = buy_item()
pay_item(payment_id)