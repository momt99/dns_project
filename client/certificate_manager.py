from cryptography.hazmat.primitives import serialization
from utils import cert_helper
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization.base import load_pem_private_key, load_pem_public_key

KEY_PATH = 'client/assets/key.pem'
CERT_PATH = 'client/assets/cert.pem'
KEY_PASS = b"THE_CLIENT_PASS"


def obtain_certificate():
    cert_helper.obtain_certificate(
        'client/assets', 14001, 'The Client', KEY_PASS)


def load_certificate() -> bytes:
    with open(CERT_PATH, "rb") as file:
        return file.read()


def load_private_key() -> RSAPrivateKey:
    with open(KEY_PATH, "rb") as file:
        return load_pem_private_key(file.read(), KEY_PASS)


def load_public_key() -> bytes:
    load_private_key().public_key().public_bytes(
        serialization.Encoding.PEM, format=serialization.PublicFormat.CompressedPoint)
