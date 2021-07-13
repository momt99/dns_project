import uuid
from sqlalchemy import *
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class SignRequest(Base):
    __tablename__ = "sign_requests"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    csr = Column(LargeBinary)
    secret_message = Column(LargeBinary)
    expiration_time = Column(DateTime)
    trust_address = Column(String)


class IssuedCertificate(Base):
    __tablename__ = "certificates"

    id = Column(Integer, primary_key=True)
    common_name = Column(String)
    cert = Column(LargeBinary)

# engine = create_engine('sqlite:///ca.db')

# Base.metadata.create_all(engine)

# Session = sessionmaker(bind=engine)

sign_requests = dict()
issued_certificates = dict()