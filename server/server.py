import socket
import threading
from cryptography.hazmat.primitives import serialization
from encrypt import generate_aes_key, rsa_encrypt, decrypt_aes_cbc
from config import HOST, PORT, BUFFER_SIZE

clients = {}  # socket -> AES key

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen()
print(f"[+] Secure Encrypted Chat Server running on {HOST}:{PORT}")


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
# Broadcast message to all clients except sender
# ------------------------
def broadcast_message(message, sender_socket):
    for client in list(clients.keys()):
        if client != sender_socket:
            try:
                # Prefix each message with 4-byte length
                client.send(len(message).to_bytes(4, "big") + message)
            except:
                client.close()
                del clients[client]


# ------------------------
# Handle individual client
# ------------------------
def handle_client(client_socket, aes_key):
    try:
        while True:
            # Read 4-byte length
            raw_len = recv_full(client_socket, 4)
            if not raw_len:
                break
            msg_len = int.from_bytes(raw_len, "big")

            # Read full message
            encrypted_message = recv_full(client_socket, msg_len)
            if not encrypted_message:
                break

            # Decrypt and print
            try:
                message = decrypt_aes_cbc(aes_key, encrypted_message).decode()
                print(f"[CLIENT] {message}")
            except Exception as e:
                print(f"[!] Decryption failed: {e}")
                continue

            broadcast_message(encrypted_message, client_socket)

    except Exception as e:
        print(f"[ERROR] Client connection error: {e}")
    finally:
        print("[!] Client disconnected.")
        client_socket.close()
        if client_socket in clients:
            del clients[client_socket]


# ------------------------
# Accept new clients
# ------------------------
def accept_clients():
    while True:
        client_socket, client_address = server_socket.accept()
        print(f"[+] New connection from {client_address}")

        try:
            # Receive client public key
            client_pub_pem = client_socket.recv(BUFFER_SIZE)
            client_public_key = serialization.load_pem_public_key(client_pub_pem)

            # Generate AES key
            aes_key = generate_aes_key()

            # Encrypt AES key with client public key
            encrypted_aes_key = rsa_encrypt(client_public_key, aes_key)

            # Send encrypted AES key
            client_socket.send(encrypted_aes_key)

            # Save AES key
            clients[client_socket] = aes_key

            # Start thread
            thread = threading.Thread(
                target=handle_client,
                args=(client_socket, aes_key),
                daemon=True
            )
            thread.start()

        except Exception as e:
            print(f"[!] Error during key exchange: {e}")
            client_socket.close()


# ------------------------
# Start server
# ------------------------
if __name__ == "__main__":
    accept_clients()
