# CS 55 Lab1 - Aarav and Tejas

This program represents command-line password manager written in Python. It keeps logins (username/password) in a local encrypted file, locked behind a master password. You can save, look up, change, and delete passwords, and it can generate strong random ones for you.

## Setup
```
pip install -r requirements.txt
python main.py
```


## File Descriptions
- **`main.py`** - Handles the command line, including the prompt loop, user commands, login attempts, and the auto-lock timer.
- **`auth.py`** - Handles vault creation, vault edge cases and general login flow. It uses the master password to recreate the encryption key and verifies the password is correct before unlocking the vault.
- **`crypto_utils.py`** - Handles the password manager's cryptographic encryption scheme. It manages this by generating a random salt, deriving an encryption key from the master password using the PBKDF2 package, and uses Fernet to encrypt and decrypt stored credentials. It ultimately powers the vault protection in auth.py and main.py

## Commands
 
Once logged in, the user get a `pwmgr>` prompt:
 
| Command | What it does |
|---|---|
| `add <service>` | Add a username and password for a service |
| `get <service>` | Show the username and password for a service |
| `list` | List every saved service name |
| `search <term>` | Find services whose name contains `<term>` (not case sensitive) |
| `update <service>` | Change the username and/or password. Leave a field blank to keep it |
| `delete <service>` | Remove a service |
| `generate [length]` | Print a random password (16 characters if you don't give a length) |
| `lock` | Lock the vault right away. You'll have to re-enter the master password |
| `help` | Show the command list |
| `exit` | Quit |
 
When you `add` or `update`, it asks whether you want a randomly generated password. 

## Bonus Features Added
- **Auto-lock:** If you don't type a command for 60 seconds, the vault locks and you have to re-enter the master password.
- **Randomly genereated passwords:** Generates passwords use Python's `secrets` module, not `random`, so they aren't predictable. 