import base64

def to_base64(data: bytes)->str:
    return str(base64.b64encode(data), encoding='ascii')

def from_base64(text: str) -> bytes:
    return base64.b64decode(text)