import pyotp
import getpass
import qrcode
from database.db import load_database, save_database
from auth import verify_password
def enable_mfa(username):
    """
    Enables MFA for the user

    Process:
        - Finds the user in the database.
        - Creates a secret code for the user.
        - Displays a QR Code
        - User will scan the generated QR code
        - User will enter the code on their app. If it matches then both secret and mfa state will be added to their username in the json
    """
    database = load_database()
    user = next((u for u in database if u['username'] == username), None) #finds the user to write to
    if not user:
        print('[ERROR] User not found.')
        return
    secret = pyotp.random_base32() #generates a secrete code for the user.
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureCLI") #creates a Uniform Resource Identifier that can then be turned into a qr code contains the user and secret info.
    qr = qrcode.QRCode()
    qr.add_data(uri)
    qr.print_ascii()

    authen_pass = input('Enter the code from your authenticator app: ') 
    totp = pyotp.TOTP(secret)
    if totp.verify(authen_pass): #comparing the code to the secret time sensitive code.
        user['mfa'] = True
        user['secret'] = secret
        save_database(database)
        print('[INFO] MFA setup was successful.')
    else:
        print('[ERROR] MFA setup was unsuccessful.')

def disable_mfa():
    """
    Disables MFA from the user

    Process:
        - Prompts the user for the username and asks for the password
        - If the user has the correct password, MFA is turned off and the secret is set to None.
    """
    database = load_database()
    username = input('Please enter the username of the user you would like to disable MFA: ')
    for user in database:
        if user['username'] == username:
            password_attempt = getpass.getpass('Enter the password for the user: ')
            if verify_password(password_attempt, user['password']):
                if user.get('mfa', False):
                    user['mfa'] = False
                    user['secret'] = None
                    save_database(database)
                    print('[INFO] MFA disabled successfully.')
                else:
                    print('[INFO] MFA is not enabled for this user.')
            else:
                print('[INFO] Password was incorrect.')
            return
    print('[INFO] User not found.')