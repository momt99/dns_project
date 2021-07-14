from client.certificate_manager import obtain_certificate
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())

obtain_certificate()

logger.info("Certificate and public key generation is done!")
