from cryptography.exceptions import InvalidSignature
from cryptography.x509 import *
from cryptography.hazmat.primitives.asymmetric import padding

from utils.paths import CA_CERT_PATH
from utils.signing import get_default_signing_padding, get_default_hash


def verify_certificate(certificate: Certificate):
    with open(CA_CERT_PATH, "rb") as f:
        cert = load_pem_x509_certificate(f.read())

    try:
        cert.public_key().verify(certificate.signature, certificate.tbs_certificate_bytes, padding.PKCS1v15(),
                                 certificate.signature_hash_algorithm)
        return True
    except InvalidSignature:
        return False
