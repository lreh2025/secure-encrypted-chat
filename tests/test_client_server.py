from utils.aes_utils import generate_aes_key, encrypt_aes_cbc, decrypt_aes_cbc


def test_client_server_message_flow():
    key = generate_aes_key()
    message = b"Client to Server Test"

    encrypted = encrypt_aes_cbc(key, message)
    decrypted = decrypt_aes_cbc(key, encrypted)

    assert decrypted == message
