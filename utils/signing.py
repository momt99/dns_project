from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization


def get_default_hash():
    return hashes.SHA256()


def get_default_signing_padding():
    return padding.PSS(
        mgf=padding.MGF1(get_default_hash()),
        salt_length=padding.PSS.MAX_LENGTH)


def get_default_encryption_padding():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=get_default_hash()),
        algorithm=get_default_hash(),
        label=None)


def sign(private_key: rsa.RSAPrivateKey, data: bytes):
    return private_key.sign(data, get_default_signing_padding(), get_default_hash())


def verify_signature(public_key: rsa.RSAPublicKey, signature: bytes, data: bytes):
    public_key.verify(
        signature, data, get_default_signing_padding(), get_default_hash())
