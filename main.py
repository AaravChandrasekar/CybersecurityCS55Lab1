# Lab 1

# allows for the password to be hiddenly typed
import getpass
import string
import sys
import secrets
import signal

import auth
import crypto_utils

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
            continue
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

def cmd_add(vault: dict, key: bytes, service: str) -> None:
    if service in vault["entries"]:
        print(f"An entry for '{service}' already exists. Use 'update' instead.")
        return
    username = input("Username: ")
    password = prompt_password_for("Password", current_password="")
    vault["entries"][service] = crypto_utils.encrypt(key, f"{username}\n{password}")
    auth.save_vault(vault)
    print(f"Saved credentials for '{service}'.")


def cmd_get(vault: dict, key: bytes, service: str) -> None:
    token = vault["entries"].get(service)
    if token is None:
        print(f"No entry found for '{service}'.")
        return
    username, password = crypto_utils.decrypt(key, token).split("\n", 1)
    print(f"Service:  {service}\nUsername: {username}\nPassword: {password}")


def cmd_list(vault: dict) -> None:
    if not vault["entries"]:
        print("No entries stored.")
        return
    for service in sorted(vault["entries"]):
        print(service)


def cmd_search(vault: dict, term: str) -> None:
    matches = sorted(s for s in vault["entries"] if term.lower() in s.lower())
    print("\n".join(matches) if matches else "No matching entries.")


def cmd_update(vault: dict, key: bytes, service: str) -> None:
    if service not in vault["entries"]:
        print(f"No entry found for '{service}'.")
        return
    current_username, current_password = crypto_utils.decrypt(
        key, vault["entries"][service]
    ).split("\n", 1)
    username = input(f"Username [{current_username}]: ").strip() or current_username
    password = prompt_password_for("New password", current_password=current_password)
    vault["entries"][service] = crypto_utils.encrypt(key, f"{username}\n{password}")
    auth.save_vault(vault)
    print(f"Updated credentials for '{service}'.")


def cmd_delete(vault: dict, service: str) -> None:
    if service not in vault["entries"]:
        print(f"No entry found for '{service}'.")
        return
    del vault["entries"][service]
    auth.save_vault(vault)
    print(f"Deleted entry for '{service}'.")


def run_session(key: bytes) -> None:
    vault = auth.load_vault()
    print(HELP_TEXT)

    while True:
        try:
            raw = read_command("\npwmgr> ").strip()
        except InactivityTimeout:
            print("\nVault locked due to inactivity.")
            key = login("Re-enter master password to unlock: ")
            vault = auth.load_vault()
            continue
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            return

        if not raw:
            continue
        cmd, *args = raw.split()
        cmd = cmd.lower()

        if cmd in ("exit", "quit"):
            return
        elif cmd == "help":
            print(HELP_TEXT)
        elif cmd == "lock":
            print("Vault locked.")
            key = login("Re-enter master password to unlock: ")
            vault = auth.load_vault()
        elif cmd == "add":
            cmd_add(vault, key, args[0]) if args else print("Usage: add <service>")
        elif cmd == "get":
            cmd_get(vault, key, args[0]) if args else print("Usage: get <service>")
        elif cmd == "list":
            cmd_list(vault)
        elif cmd == "search":
            cmd_search(vault, args[0]) if args else print("Usage: search <term>")
        elif cmd == "update":
            cmd_update(vault, key, args[0]) if args else print("Usage: update <service>")
        elif cmd == "delete":
            cmd_delete(vault, args[0]) if args else print("Usage: delete <service>")
        elif cmd == "generate":
            length = int(args[0]) if args and args[0].isdigit() else 16
            print(generate_password(length))
        else:
            print(f"Unknown command: '{cmd}'. Type 'help' for options.")


def main():
    key = register_vault() if not auth.vault_exists() else login()
    run_session(key)


if __name__ == "__main__":
    main()
