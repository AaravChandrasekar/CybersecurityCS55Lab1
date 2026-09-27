"""Master password setup and login."""

import base64
import json
import os

from cryptography.fernet import InvalidToken

import crypto_utils

VAULT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "storage.json")
VERIFIER_PLAINTEXT = "vault-unlocked"

class AuthError(Exception):
    """Raised when vault setup or master password verification fails."""


def vault_exists() -> bool:
    return os.path.exists(VAULT_FILE) and os.path.getsize(VAULT_FILE) > 0


def load_vault() -> dict:
    with open(VAULT_FILE, "r") as f:
        return json.load(f)


def save_vault(data: dict) -> None:
    with open(VAULT_FILE, "w") as f:
        json.dump(data, f, indent=2)

def register(master_password: str) -> bytes:
    """Create a new vault protected by the given master password and return its key."""
    if vault_exists():
        raise AuthError("A vault already exists. Delete storage.json to reset it.")

    salt = crypto_utils.generate_salt()
    key = crypto_utils.derive_key(master_password, salt)
    verifier = crypto_utils.encrypt(key, VERIFIER_PLAINTEXT)

    save_vault({
        "salt": base64.b64encode(salt).decode("utf-8"),
        "verifier": verifier,
        "entries": {},
    })
    return key

def login(master_password: str) -> bytes:
    """Verify the master password and return the derived encryption key."""
    if not vault_exists():
        raise AuthError("No vault found. Run 'init' to create one first.")

    vault = load_vault()
    salt = base64.b64decode(vault["salt"])
    key = crypto_utils.derive_key(master_password, salt)

    try:
        decrypted = crypto_utils.decrypt(key, vault["verifier"])
    except InvalidToken:
        raise AuthError("Incorrect master password.")

    if decrypted != VERIFIER_PLAINTEXT:
        raise AuthError("Incorrect master password.")

    return key