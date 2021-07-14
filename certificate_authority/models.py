import uuid
from sqlalchemy import *
from database import db


class SignRequest(db.Model):
    __tablename__ = "sign_requests"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    csr = Column(LargeBinary)
    secret_message = Column(LargeBinary)
    expiration_time = Column(DateTime)
    trust_address = Column(String)


class IssuedCertificate(db.Model):
    __tablename__ = "certificates"

    id = Column(Integer, primary_key=True)
    common_name = Column(String)
    cert = Column(LargeBinary)

db.create_all()