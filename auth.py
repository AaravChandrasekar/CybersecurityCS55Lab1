"""Master password setup and login."""

# base64: converts the binary salt to/from text so it can be stored in JSON
import base64
# json: reads and writes the vault file (storage.json)
import json
# os: builds the vault file path and checks whether the file exists
import os

# InvalidToken: the error Fernet raises when decryption fails (wrong password)
from cryptography.fernet import InvalidToken

# crypto_utils: our own salt, key derivation, and encrypt/decrypt helpers that we wrote earlier
# Underlying foundation for the authentication system
import crypto_utils

VAULT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "storage.json")
VERIFIER_PLAINTEXT = "vault-unlocked"

# A custom error we raise when creating the vault or logging in goes wrong.
class AuthError(Exception):
    """Raised when vault setup or master password verification fails."""


# Checks whether a vault has already been created, just an admin check
def vault_exists() -> bool:
    return os.path.exists(VAULT_FILE) and os.path.getsize(VAULT_FILE) > 0


# Opens the vault file and loads everything saved in it, all the services and passwords and usernames
def load_vault() -> dict:
    with open(VAULT_FILE, "r") as f:
        return json.load(f)


# Saves the vault back to the file so changes are not lost if we want to relogin later
def save_vault(data: dict) -> None:
    with open(VAULT_FILE, "w") as f:
        json.dump(data, f, indent=2)

# Sets up a brand new vault the first time the user picks a master password.
# We never save the password itself, only what we need to check it later.
def register(master_password: str) -> bytes:
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

# Checks that the master password is correct and, if so, hands back the key
# needed to read the saved passwords.
def login(master_password: str) -> bytes:
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