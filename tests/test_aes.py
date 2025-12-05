from utils.aes_utils import generate_aes_key, encrypt_aes_cbc, decrypt_aes_cbc


def test_aes_encryption():
    key = generate_aes_key()
    message = b"Hello Secure Chat AES"

    encrypted = encrypt_aes_cbc(key, message)
    decrypted = decrypt_aes_cbc(key, encrypted)

    assert decrypted == message
