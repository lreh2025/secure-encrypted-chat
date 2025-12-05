# =========================
# Network Configuration
# =========================

HOST = "127.0.0.1"   # Localhost (change to server IP when deploying)
PORT = 5000          # Port the server listens on / client connects to
BUFFER_SIZE = 8192   # Size of socket receive buffer


# =========================
# Cryptography Settings
# =========================

RSA_KEY_SIZE = 2048      # RSA key size (2048 is standard secure minimum)
AES_KEY_SIZE = 32        # 32 bytes = 256-bit AES encryption
AES_BLOCK_SIZE = 16      # AES block size in bytes (128-bit)


# =========================
# Application Settings
# =========================

ENCODING = "utf-8"       # Text encoding for messages
EXIT_COMMAND = "exit"   # Command to safely close the client


# =========================
# Debug / Logging
# =========================

DEBUG = True             # Set False to disable debug prints
