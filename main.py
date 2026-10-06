# Lab 1

# Hides terminal input while typing passwords
import getpass
# Provides character sets
import string
# Used for terminating the process via sys.exit()
import sys
# Cryptographically secure random number generator
import secrets
# Used to implement UNIX timers for auto-lock
import signal
# Authentication module
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

# Raises inactivity timeout
def _on_alarm(signum, frame):
    raise InactivityTimeout

# Concatenates text, numbers, and punctuation, and then picks random characters
# from that pool.
def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(alphabet) for _ in range(length))

# Used during initial setup. Loops up to MAX_PASSWORD_ATTEMPTS times, 
# asking for a master password and confirmation via getpass. If both entries 
# match, it returns the password, otherwise it exits.
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

# Loops up to MAX_PASSWORD_ATTEMPTS prompting for the master password
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

# Initializes a new password . 
def register_vault() -> bytes:
    print("No vault found. Let's create one.")
    password = prompt_new_master_password()

    # Verifies the vault doesn't exist, generaters salt, and derives the
    # key, which is then Base64-encoded to satisfy Fernet requirements
    key = auth.register(password)
    print("Vault created successfully.\n")
    return key

# Schedules an alarm for 60 seconds for the auto-lock feature,
# resets to 0 once input is received.
def read_command(prompt_text: str) -> str:
    signal.signal(signal.SIGALRM, _on_alarm)
    signal.alarm(AUTO_LOCK_SECONDS)
    try:
        return input(prompt_text)
    finally:
        signal.alarm(0)


# Asks if the user wants to generate a random password. If so,
# it prompts for length (default of 16) and generates one.
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


# Ensures the service name is not already present, prompts for username and 
# password. Then, it concatenates them together, encrypts it with Fernet, and 
# stores the token in the vault
def cmd_add(vault: dict, key: bytes, service: str) -> None:
    if service in vault["entries"]:
        print(f"An entry for '{service}' already exists. Use 'update' instead.")
        return
    username = input("Username: ")
    password = prompt_password_for("Password", current_password="")
    vault["entries"][service] = crypto_utils.encrypt(key, f"{username}\n{password}")
    auth.save_vault(vault)
    print(f"Saved credentials for '{service}'.")

# Fetches the encrypted token for "service" from vault["entries"]. Then,
# it decrypts the token and splits the username and password
def cmd_get(vault: dict, key: bytes, service: str) -> None:
    token = vault["entries"].get(service)
    if token is None:
        print(f"No entry found for '{service}'.")
        return
    username, password = crypto_utils.decrypt(key, token).split("\n", 1)
    print(f"Service:  {service}\nUsername: {username}\nPassword: {password}")

# Prints all service keys stored in the vault in alphabetical order
def cmd_list(vault: dict) -> None:
    if not vault["entries"]:
        print("No entries stored.")
        return
    for service in sorted(vault["entries"]):
        print(service)

# Searches over service names and prints matches (case-insensitive)
def cmd_search(vault: dict, term: str) -> None:
    matches = sorted(s for s in vault["entries"] if term.lower() in s.lower())
    print("\n".join(matches) if matches else "No matching entries.")

# Decrypts the existing entry to read the current username and password. Then,
# it prompts for new values (keeping old ones as defaults if left blank). Lastly,
# it re-encrypts and saves the updated entry to disk.
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

# Deletes the service key from the vault
def cmd_delete(vault: dict, service: str) -> None:
    if service not in vault["entries"]:
        print(f"No entry found for '{service}'.")
        return
    del vault["entries"][service]
    auth.save_vault(vault)
    print(f"Deleted entry for '{service}'.")

# Loads the vault dictionary and enters the main command loop.
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

        # Splits input into command and arguments
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


# Checks if a vault exists, if not triggers register_vault()
def main():
    key = register_vault() if not auth.vault_exists() else login()
    run_session(key)


if __name__ == "__main__":
    main()
