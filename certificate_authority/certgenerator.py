# This module is meant to be used for generating the self-signed certificate
# of the CA

# Source: https://cryptography.io/en/latest/x509/tutorial/

import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import os

if __name__ == '__main__':
    if not os.path.exists("assets"):
        os.mkdir("assets")

    # Key Creation
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    with open("assets/key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
            #encryption_algorithm=serialization.BestAvailableEncryption(
            #    b"THE_CA_PASS"),
        ))

    # Certificate Creation

    # Various details about who we are. For a self-signed certificate the
    # subject and issuer are always the same.
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Tehran"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Tehran"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"DNS Project Group"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost:5000"),
    ])

    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10 * 365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]), critical=False)
            # Sign our certificate with our private key
            .sign(key, hashes.SHA256()))
    # Write our certificate out to disk.
    with open("assets/certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
