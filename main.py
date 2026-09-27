# Lab 1

# allows for the password to be hiddenly typed
import getpass
import string
import sys
import secrets

MAX_PASSWORD_ATTEMPTS = 3


def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(alphabet) for _ in range(length))

def prompt_new_master_password() -> str:
    for attempt in range(1, MAX_PASSWORD_ATTEMPTS + 1):
        password = getpass.getpass("Master Password: ")
        again = getpass.getpass("Confirm master password: ")
        if password == again:
            return password
        remaining = MAX_PASSWORD_ATTEMPTS - attempt
        if remaining:
            print(f"Unfortunately, passwords do not match. {remaining} attempt(s) left.")
        print("Passwords do not match and you have used all remaining attempts.")