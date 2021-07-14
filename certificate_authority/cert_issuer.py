import datetime
from cryptography.x509 import *
from cryptography.x509 import OID_COMMON_NAME
from cryptography.hazmat.primitives import serialization
from certificate_authority.database import db
from certificate_authority.models import *
from os import urandom
from utils.signing import get_default_encryption_padding, get_default_hash


def issue_certificate(csr: CertificateSigningRequest) -> Certificate:
    with open("certificate_authority/assets/key.pem", "rb") as file:
        key = serialization.load_pem_private_key(file.read(), None)
    with open("certificate_authority/assets/certificate.pem", "rb") as file:
        cert = load_pem_x509_certificate(file.read())

    cert = (CertificateBuilder(extensions=csr.extensions)
            .subject_name(csr.subject)
            .issuer_name(cert.issuer)
            .public_key(csr.public_key())
            .serial_number(random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1 * 365))
            # Sign our certificate with our private key
            .sign(key, get_default_hash()))

    db.session.add(
        IssuedCertificate(
            common_name=(cert.subject.get_attributes_for_oid(
                OID_COMMON_NAME)[0].value),
            cert=cert.public_bytes(serialization.Encoding.PEM)))
    db.session.commit()

    return cert


def define_sign_request(csr_data: bytes):
    csr = load_pem_x509_csr(csr_data)
    try:
        common_name = (csr.subject.get_attributes_for_oid(
            OID_COMMON_NAME)[0].value)
    except IndexError:
        raise ValueError("Common name is not available.")

    # session = scoped_session(Session)

    request = SignRequest(
        csr=csr.public_bytes(serialization.Encoding.PEM),
        secret_message=urandom(128),
        expiration_time=datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        trust_address=common_name)

    db.session.add(request)
    db.session.commit()

    return (
        request.id,
        request.trust_address,
        csr.public_key().encrypt(
            request.secret_message,
            get_default_encryption_padding()))


def verify_decrypted_message_and_issue(id: str, message: bytes) -> bytes:

    request: SignRequest = db.session.query(SignRequest).get(id)

    assert request.expiration_time > datetime.datetime.utcnow()
    assert request.secret_message == message

    return issue_certificate(load_pem_x509_csr(request.csr)).public_bytes(serialization.Encoding.PEM)
