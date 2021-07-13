import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


def issue_certificate(csr: x509.CertificateSigningRequest) -> x509.Certificate:
    with open("assets/key.pem", "rb") as file:
        key = serialization.load_pem_private_key(file.read(), None)
    with open("assets/certificate.pem", "rb") as file:
        cert = x509.load_pem_x509_certificate(file.read())

    return (x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(cert.issuer)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1 * 365))
            # Sign our certificate with our private key
            .sign(key, hashes.SHA256()))
