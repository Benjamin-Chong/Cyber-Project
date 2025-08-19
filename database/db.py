import json
import os
import datetime
from generate_key import get_fernet
def save_database(data, filename="database/user-pass.json.enc"):
    """
    Takes the data as a parameter and writes (saves) it to the encrypted file.

    Process:
        - Gets the fernet so the information can get encrypted.
        - Changes the string text into bytes so that the fernet can encrypt it
        - Finally write in binary to the file
    """
    fernet = get_fernet()
    json_bytes = json.dumps(data).encode("utf-8")  # convert JSON to bytes
    encrypted = fernet.encrypt(json_bytes)         # encrypt bytes
    with open(filename, "wb") as file:            # write binary
        file.write(encrypted)

def load_database(filename="database/user-pass.json.enc"):
    """
    Loads the database so that the information can be used.

    Process:
        - Reads the file in binary.
        - Uses the fernet to decrypt the binary
        - Returns an object that can later be saved to a variable
    """
    try:
        with open(filename, "rb") as file:        # read binary
            encrypted = file.read()
        fernet = get_fernet()
        decrypted_bytes = fernet.decrypt(encrypted)  # decrypt
        return json.loads(decrypted_bytes)        # convert back to dict/list
    except FileNotFoundError:
        # create empty encrypted file if it doesn't exist
        save_database([])
        return []
    except Exception as e:
        print(f"[ERROR] Failed to load database: {e}")
        return []

def load_lockout(filename="database/lockout.json"):
    """
    Loads the json using the safe load function
    """
    return safe_load_json(filename, [])


def save_lockout(data, filename="database/lockout.json"):
    """
    Saves the lockout data and simultaniously sorts it by most recent lockout
    """
    data.sort(key=lambda x: x["time"], reverse=True)
    safe_save_json(filename, data)


def lockout(username, attempts):  # saves the time and amount of attempts
    """
    If a lockout occurs, this function is ran that adds the user's lockout time and attempts.

    Process:
        - When a user reaches lockout, the lockout is loaded and the user is added to a database.
        - It saves the time, username, attempts.
        - It finally saves it to the lockout database.
    """
    lockout_database = load_lockout()
    now = datetime.datetime.now().isoformat()
    for user in lockout_database:
        if user["username"] == username:
            user["attempts"] = attempts
            user["time"] = now
            break
    else:
        lockout_database.append({
            "username": username,
            "attempts": attempts,
            "time": now
        })
    save_lockout(lockout_database)

def safe_load_json(filename, default):
    """Load JSON safely. If missing or corrupted, reset with default."""
    try:
        if not os.path.exists(filename):
            with open(filename, "w") as file: 
                json.dump(default, file, indent=4)
            return default

        with open(filename, "r") as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError):
        with open(filename, "w") as file:
            json.dump(default, file, indent=4)
        return default

def safe_save_json(filename, data):
    """Save JSON safely with indentation."""
    with open(filename, "w") as file:
        json.dump(data, file, indent=4)