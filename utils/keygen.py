from utils.aes_utils import generate_aes_key
from utils.rsa_utils import generate_rsa_keypair


def generate_session_keys():
    aes_key = generate_aes_key()
    private_key, public_key = generate_rsa_keypair()
    return aes_key, private_key, public_key
