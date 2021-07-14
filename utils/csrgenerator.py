# This module is used by different users to create a certificate signing request (CSR)

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


# Generate key and certificate

def create_csr(ip_port, organization_name=None):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Various details about who we are. For a self-signed certificate the
    # subject and issuer are always the same.
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Tehran"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Tehran"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"DNS Project Group"),
        x509.NameAttribute(NameOID.COMMON_NAME, ip_port),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
    ])).sign(key, hashes.SHA256())

    return key, csr
