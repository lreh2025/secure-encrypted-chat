from utils.rsa_utils import generate_rsa_keypair, rsa_encrypt, rsa_decrypt


def test_rsa_encryption():
    private_key, public_key = generate_rsa_keypair()
    message = b"Hello Secure Chat RSA"

    encrypted = rsa_encrypt(public_key, message)
    decrypted = rsa_decrypt(private_key, encrypted)

    assert decrypted == message
