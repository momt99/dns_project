from cryptography.exceptions import InvalidSignature
from cryptography.x509 import *

from utils.signing import get_default_signing_padding, get_default_hash


def verify_certificate(certificate: Certificate):
    with open('assets/certificate.pem', "rb") as f:
        cert = load_pem_x509_certificate(f.read())

    try:
        cert.public_key().verify(certificate.signature, certificate.tbs_certificate_bytes,
                                 get_default_signing_padding(), get_default_hash())
        return True
    except InvalidSignature:
        return False
