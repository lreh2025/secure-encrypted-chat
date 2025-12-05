import os
from cryptography.hazmat.primitives import hashes, padding as sympadding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from config import AES_KEY_SIZE, AES_BLOCK_SIZE, RSA_KEY_SIZE


# ======================================================
# ===================== RSA SECTION ====================
# ======================================================

def generate_rsa_keypair():
    """
    Generates an RSA public/private key pair.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE
    )
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt(public_key, message: bytes) -> bytes:
    """
    Encrypts data using a public RSA key (OAEP).
    """
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    """
    Decrypts RSA-encrypted data using a private key.
    """
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ======================================================
# ===================== AES SECTION ====================
# ======================================================

def generate_aes_key():
    """
    Generates a secure random AES key.
    """
    return os.urandom(AES_KEY_SIZE)


def encrypt_aes_cbc(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypts data using AES-CBC.
    Returns: IV + ciphertext
    """
    iv = os.urandom(AES_BLOCK_SIZE)

    # Pad plaintext
    padder = sympadding.PKCS7(AES_BLOCK_SIZE * 8).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext


def decrypt_aes_cbc(key: bytes, encrypted_data: bytes) -> bytes:
    """
    Decrypts AES-CBC encrypted data.
    Expects: IV + ciphertext
    """
    if len(encrypted_data) < AES_BLOCK_SIZE:
        raise ValueError("Encrypted data is too short!")

    iv = encrypted_data[:AES_BLOCK_SIZE]
    ciphertext = encrypted_data[AES_BLOCK_SIZE:]

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding safely
    unpadder = sympadding.PKCS7(AES_BLOCK_SIZE * 8).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext
