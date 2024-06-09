import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib

def derive_key(passkey):
    """Derives an AES key from the passkey."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'your_secure_random_salt',
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))

def encrypt_file(filename, fernet):
    with open(filename, 'rb') as f:
        data = f.read()
        encrypted_data = fernet.encrypt(data)
        file_hash = hashlib.sha256(data).hexdigest()
    return encrypted_data, file_hash

def decrypt_file(filename, fernet):
    with open(filename, 'rb') as f:
        encrypted_data = f.read()
        decrypted_data = fernet.decrypt(encrypted_data)
    return decrypted_data
