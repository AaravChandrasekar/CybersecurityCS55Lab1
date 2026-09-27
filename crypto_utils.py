"""Encryption and decryption logic."""

import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
KDF_ITERATIONS = 500000

def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from the master password using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)

def encrypt(key: bytes, plaintext: str) -> str:
    return Fernet(key).encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt(key: bytes, token: str) -> str:
    return Fernet(key).decrypt(token.encode("utf-8")).decode("utf-8")
