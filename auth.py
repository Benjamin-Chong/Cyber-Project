import bcrypt
def hash_password(password):
    """
    Hashes the password using bcrypt

    Process:
        - Generates a salt for the user
        - Hashes the password using the password converted into a bytes object and the salt
        - Finally returns the hashed password as a string object
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password1, password2):
    """
    Checks to see if both passwords are the same.
    
    Processs:
        - Encodes both plain and hashed passwords into bytes.
        - Uses bcrypt to check if they match
        - Returns True or False depending on the outcome.
    """
    return bcrypt.checkpw(password1.encode('utf-8'), password2.encode('utf-8'))