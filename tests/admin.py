import getpass
import bcrypt
from database.db import safe_load_json

def load_admin():
    """
    Loads the admin password
    """
    config = safe_load_json("database/admin.json", {"admin_password": ""})
    return config["admin_password"]


def admin_authenticate():
    """
    Checks to make sure that both passwords match.

    Returns:
        - True if the passwords match
        - False otherwise
    """
    admin_hash = load_admin()
    password = getpass.getpass('Enter admin password: ')
    if bcrypt.checkpw(password.encode('utf-8'), admin_hash.encode('utf-8')):
        return True
    else:
        print('[INFO] Admin password incorrect.')
        return False
