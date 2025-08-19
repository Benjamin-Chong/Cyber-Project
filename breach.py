import requests
import hashlib
def check_breach(password):
    """
    Checks the given password against the API.

    Returns:
        - A tuple (breached, count) if the password was found and how many times it appeared in the breach
    """
    try:
        sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1pass[:5]
        suffix = sha1pass[5:]
        url = f'https://api.pwnedpasswords.com/range/{prefix}' #takes the first 5 digits and searches for it.

        response = requests.get(url, timeout=5)
        response.raise_for_status()

        for line in response.text.splitlines():
            hash_suffix, count = line.split(':')
            if hash_suffix == suffix: #uses digits or numbers after the first 5 to find if it has been found in the API
                return True, int(count)

        return False, 0
    except Exception:
        return False, 0
