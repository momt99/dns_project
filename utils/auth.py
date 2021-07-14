import datetime
from typing import Union
from utils.encoding import from_base64, to_base64
from utils.signing import sign, verify_signature

from cryptography.hazmat.primitives.asymmetric import rsa

default_private_key: rsa.RSAPrivateKey = None



__SIGNATURE_LENGTH = 256


def create_auth_header(
        user_id: str,
        service_id: str,
        timestamp: Union[datetime.datetime, None] = None,
        private_key: Union[rsa.RSAPrivateKey, None] = None) -> str:
    if timestamp is None:
        timestamp = datetime.datetime.utcnow()

    if private_key is None:
        private_key = default_private_key

    assert private_key is not None

    data = (bytes(user_id, 'ascii')
            + bytes(service_id, 'ascii')
            + bytes(int(timestamp.timestamp()).to_bytes(8, 'big')))
    signature = sign(private_key, data)

    assert len(signature) == __SIGNATURE_LENGTH

    return to_base64(data + signature)


def verify_auth_header(value: str, public_key: rsa.RSAPublicKey):
    value = from_base64(value)
    data = value[:-__SIGNATURE_LENGTH]
    signature = value[-__SIGNATURE_LENGTH:]

    verify_signature(public_key, signature, data)
