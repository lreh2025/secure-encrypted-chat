import socket
import threading
from encrypt import generate_rsa_keypair, rsa_decrypt, encrypt_aes_cbc, decrypt_aes_cbc
from config import HOST, PORT, BUFFER_SIZE
from cryptography.hazmat.primitives import serialization

# ------------------------
# Helper: Receive exact n bytes
# ------------------------
def recv_full(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data


# ------------------------
# Receive messages from server
# ------------------------
def receive_messages(sock, aes_key):
    while True:
        try:
            raw_len = recv_full(sock, 4)
            if not raw_len:
                break
            msg_len = int.from_bytes(raw_len, "big")
            encrypted_message = recv_full(sock, msg_len)
            if not encrypted_message:
                break

            try:
                message = decrypt_aes_cbc(aes_key, encrypted_message).decode()
                print(f"\nFriend: {message}\nYou: ", end="", flush=True)
            except Exception as e:
                print(f"\n[!] Decryption failed: {e}")
        except Exception as e:
            print(f"\n[!] Connection error: {e}")
            break


# ------------------------
# Main client code
# ------------------------
if __name__ == "__main__":
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))

    # Generate RSA keys
    private_key, public_key = generate_rsa_keypair()
    client_socket.send(public_key.public_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PublicFormat.SubjectPublicKeyInfo 
    ))

    # Receive encrypted AES key
    encrypted_aes_key = client_socket.recv(BUFFER_SIZE)
    aes_key = rsa_decrypt(private_key, encrypted_aes_key)
    print("[*] Connected to server")
    print("[+] Secure AES session established")
    print("Type your messages below\nYou: ", end="", flush=True)

    # Start receiver thread
    threading.Thread(target=receive_messages, args=(client_socket, aes_key), daemon=True).start()

    # Send messages
    try:
        while True:
            msg = input()
            if msg.lower() == "exit":
                break
            encrypted_msg = encrypt_aes_cbc(aes_key, msg.encode())
            client_socket.send(len(encrypted_msg).to_bytes(4, "big") + encrypted_msg)
    except KeyboardInterrupt:
        pass
    finally:
        client_socket.close()
