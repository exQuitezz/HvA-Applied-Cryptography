from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets, base64

group_key = secrets.token_bytes(32)  # AES-256 key
print(base64.b64encode(group_key).decode())
