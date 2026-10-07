"""Encryption and decryption logic."""

# base64: encodes the raw derived key into the URL-safe format Fernet expects
import base64
# os: provides os.urandom for cryptographically secure random bytes (the salt)
import os

# Fernet: symmetric authenticated encryption
from cryptography.fernet import Fernet
# hashes: supplies the SHA-256 hash algorithm used inside the KDF
from cryptography.hazmat.primitives import hashes
# PBKDF2HMAC: slow key derivation function that turns a password into a key
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
KDF_ITERATIONS = 500000

# Makes a random string of bytes. Mixing this into the password means two users
# with the same password still end up with different keys allowing for a safer system when there are many users
def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)

# Turns the master password into the symmetric key, which allows it lock and unlock the vault.
# It is deliberately slow so guessing passwords takes an attacker a very long time.
# The thousands of iterations we use and define before make brute-forcing the password very slow, even if the attacker has a fast computer
def derive_key(master_password: str, salt: bytes) -> bytes:
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)

# Scrambles readable plaintext into unreadable ciphertext using the key derived above
def encrypt(key: bytes, plaintext: str) -> str:
    return Fernet(key).encrypt(plaintext.encode("utf-8")).decode("utf-8")


# Decrypts the ciphertext back into its readable form (plaintext, our original password); and it will fail if the key is wrong.
def decrypt(key: bytes, token: str) -> str:
    return Fernet(key).decrypt(token.encode("utf-8")).decode("utf-8")
