# Lab 1

# allows for the password to be hiddenly typed
import getpass
import string
import sys
import secrets
import signal

import auth

MAX_PASSWORD_ATTEMPTS = 3
AUTO_LOCK_SECONDS = 60

HELP_TEXT = """
Commands:
  add <service>       Add a new credential entry
  get <service>       Retrieve and decrypt a credential entry
  list                List all stored service names
  search <term>       Search stored service names
  update <service>    Edit an existing entry
  delete <service>    Delete a stored entry
  generate [length]   Generate a random password (default 16)
  lock                Re-lock the vault (re-enter master password)
  help                Show this message
  exit                Quit the password manager
""".strip()


class InactivityTimeout(Exception):
    """Raised when no command is entered within AUTO_LOCK_SECONDS."""


def _on_alarm(signum, frame):
    raise InactivityTimeout

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
        sys.exit(1)

def login(prompt_text: str = "Master password: ") -> bytes:
    for attempt in range(1, MAX_PASSWORD_ATTEMPTS + 1):
        password = getpass.getpass(prompt_text)
        try:
            return auth.login(password)
        except auth.AuthError as e:
            remaining = MAX_PASSWORD_ATTEMPTS - attempt
            suffix = f" {remaining} attempt(s) left." if remaining else ""
            print(f"Error: {e}{suffix}")
    print("Unforunately, there have been too many failed attempts. Exiting.")
    sys.exit(1)


def register_vault() -> bytes:
    print("No vault found. Let's create one.")
    password = prompt_new_master_password()
    key = auth.register(password)
    print("Vault created successfully.\n")
    return key

def read_command(prompt_text: str) -> str:
    signal.signal(signal.SIGALRM, _on_alarm)
    signal.alarm(AUTO_LOCK_SECONDS)
    try:
        return input(prompt_text)
    finally:
        signal.alarm(0)


def prompt_password_for(action: str, current_password: str) -> str:
    choice = input(f"Generate a random password? [y/N]: ").strip().lower()
    if choice != "y":
        entered = getpass.getpass(f"{action} (leave blank to keep current): " if current_password else "Password: ")
        return entered or current_password

    length_raw = input("Length [16]: ").strip()
    length = int(length_raw) if length_raw.isdigit() else 16
    password = generate_password(length)
    print(f"Generated password: {password}")
    return password