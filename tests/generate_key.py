from cryptography.fernet import Fernet

def generate_key():
    """
    Generates a key and writes it to the the secret.key file
    """
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

if __name__ == "__main__": #only will generate a key if the this file is ran
    generate_key()
    print("[INFO] Encryption key saved to secret.key")

def load_key():
    """
    Loads the key and reads the bytes of the file denoted by rb
    """
    with open("secret.key", "rb") as key_file:
        return key_file.read() #bytes

def get_fernet():
    """
    returns the key object
    """
    return Fernet(load_key()) #fernet expects bytes