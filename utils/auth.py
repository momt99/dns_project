import datetime
from typing import Union

from sqlalchemy.sql.functions import user
from utils.encoding import from_base64, to_base64
from utils.signing import sign, verify_signature

from cryptography.hazmat.primitives.asymmetric import rsa

default_private_key: rsa.RSAPrivateKey = None


__SIGNATURE_LENGTH = 256
__TIME_LENGTH = 8


def __time_to_bytes(timestamp: datetime.datetime):
    return bytes(int(timestamp.timestamp()).to_bytes(__TIME_LENGTH, 'big'))


def __bytes_to_time(time_data: bytes):
    return datetime.datetime.fromtimestamp(
        int.from_bytes(time_data, byteorder='big') * 1.0)


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

    data = (bytes(f'{user_id}||{service_id}', 'ascii')
            + __time_to_bytes(timestamp))
    signature = sign(private_key, data)

    assert len(signature) == __SIGNATURE_LENGTH

    return to_base64(data + signature)


def extract_user_id(header_value: str):
    value = from_base64(header_value)
    data = value[:-__SIGNATURE_LENGTH]
    ids_data = data[:-__TIME_LENGTH]
    ids = str(ids_data, encoding='ascii')
    return ids.split('||')[0]


def verify_auth_header(
        header_value: str, public_key: rsa.RSAPublicKey, current_service_id: str):
    value = from_base64(header_value)
    data = value[:-__SIGNATURE_LENGTH]
    signature = value[-__SIGNATURE_LENGTH:]

    time_data = data[-__TIME_LENGTH:]
    timestamp = __bytes_to_time(time_data)
    assert datetime.datetime.utcnow() - timestamp < datetime.timedelta(minutes=1)

    ids_data = data[:-__TIME_LENGTH]
    ids = str(ids_data, encoding='ascii')
    service_id = ids.split('||')[1]
    assert service_id == current_service_id

    verify_signature(public_key, signature, data)
