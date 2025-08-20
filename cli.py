from database.db import load_database, save_database, lockout, load_lockout
from auth import hash_password, verify_password
from breach import check_breach
from admin import admin_authenticate
from mfa import enable_mfa, disable_mfa
import pyotp
import datetime
import getpass
import logging

# --- Logging Setup ---
logging.basicConfig(
    filename='database/security.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# --- CLI ---
def main():
    """The user interface for the user."""
    done = False
    while not done:
        print('\n--- Main Menu ---')
        print('[1] Add a new user (includes password breach check)')
        print('[2] Print all users')
        print('[3] Login')
        print('[4] Delete User')
        print('[5] Search for user (requires admin password)')
        print('[6] Enable MFA')
        print('[7] Disable MFA')
        print('[8] Exit')
        user_input = input('Enter your desired command (or type "help"): ').strip().lower()

        if user_input == 'help':
            print('\nEnter the number corresponding to the action you want to perform.')
            input('Press Enter to continue...')
            continue

        if not user_input.isdigit():
            print('[ERROR] Invalid input. Enter a valid command.')
            logging.warning(f'Invalid CLI command entered: {user_input}')
            input('Press Enter to continue...')
            continue

        user_input = int(user_input)
        match user_input:
            case 1:
                new_user()
                input('Press Enter to continue...')
            case 2:
                print_json()
                input('Press Enter to continue...')
            case 3:
                login()
                input('Press Enter to continue...')
            case 4:
                delete_user()
                input('Press Enter to continue...')
            case 5:
                search()
                input('Press Enter to continue...')
            case 6:
                username = input('Please enter the username: ')
                enable_mfa(username)
                input('Press Enter to continue...')
            case 7:
                disable_mfa()
                input('Press Enter to continue...')
            case 8:
                print('[SUCCESS] Successfully ended session.')
                logging.info('Press Enter to continue...')
                done = True
            case _:
                print('[ERROR] Invalid input. Enter a valid command.')
                logging.warning(f'Invalid CLI command entered: {user_input}')
                input('Press Enter to continue...')

# --- User Creation ---
def new_user(test_mode = False):
    """
    Users can create new accounts that are then added into the database. 
    Process:
        - Prompts user for username and confirms if it is valid (ie. no spaces)
        - Prompts user for password and confirms if it is valid. Only takes strong passwords.
        - Checks against the API and cites how many times its been breached.
        - Asks the user if they would like to enable MFA. If yes it displays a QR code for an authenticator app to run
        - Saves to the database 
    """
    try:
        with open('database/common_passwords.txt', 'r') as common:
            data_json = load_database()
            user_success = False

            while not user_success:
                username = input('Please enter your username: ').strip()
                username_confirm = input('Please confirm your username: ').strip()
                if username != username_confirm:
                    if test_mode: return False
                    print('[INFO] Usernames are not the same.\n')
                    logging.warning('Username confirmation mismatch.')
                    continue

                if not username:
                    if test_mode: return False
                    print('[ERROR] Username cannot be empty.\n')
                    logging.warning('Empty username attempted.')
                    continue

                if ' ' in username:
                    if test_mode: return False
                    print('[ERROR] Username cannot contain spaces.\n')
                    logging.warning('Username with spaces attempted.')
                    continue

                if any(username == user['username'] for user in data_json):
                    if test_mode: return False
                    print('[ERROR] Username already exists.\n')
                    logging.warning(f'Attempted to create duplicate username: {username}')
                    continue
                user_success = True

            common_passwords = [line.strip() for line in common] #reading the common passwords file into a list.
            pass_success = False
            while not pass_success:
                password = getpass.getpass('Please enter your password: ')
                pass_confirm = getpass.getpass('Please confirm your password: ')

                if password != pass_confirm:
                    if test_mode: return False
                    print('[INFO] The passwords do not match.\n')
                    logging.warning('Password confirmation mismatch during user creation.')
                    continue

                has_number = any(char.isdigit() for char in password)
                has_upper = any(char.isupper() for char in password)
                has_special = any(not char.isalnum() for char in password)

                if len(password) < 8 or not has_number or not has_upper or not has_special or password in common_passwords:
                    if test_mode: return False
                    print('[ERROR] Password does not meet requirements.\n')
                    logging.warning(f'Weak password attempted for user: {username}')
                    continue
                pass_success = True

            hashed = hash_password(password)
            data_json.append({
                'username': username,
                'password': hashed
            })
            save_database(data_json)
            print('[INFO] Checking the password against the API.')
            breached, count = check_breach(password)
            data_json[-1]['breached'] = breached #since the new user was the last one added, we can access the last user and update to it
            data_json[-1]['count'] = count
            logging.info(f'User "{username}" created. Breached: {breached}, Count: {count}')
            mfa = input('Would you like to enable MFA (y/n): ').strip().lower()
            if mfa == 'y':
                enable_mfa(username)
                logging.info(f'User, {username}, has enabled MFA.')

        save_database(data_json)
        print('[SUCCESS] User has been added.\n')
        return True
    except Exception as e:
        print(f'[ERROR] Could not create user: {e}\n')
        logging.error(f'Exception during user creation: {e}')
        return False

# --- Print Users ---
def print_json():
    """
    Prints all of the users in the datatbase.

    Notes:
        - Logs errors if the database is empty or could not read.
        - Places in try and except blocks to gracefully handle errors.
    """
    try:
        data = load_database()
        if not data:
            print('[INFO] Database is empty.\n')
            logging.info('Print command executed on empty database.')
            return
        
        for entry in data:
            print(f'Username: {entry['username']}')
        print('[SUCCESS] Print finished.\n')
        logging.info('All users printed successfully.')

    except Exception as e:
        print(f'[ERROR] Could not read database: {e}\n')
        logging.error(f'Database read failed: {e}')

# --- Login ---
def login(test_mode = False):
    """
    Users will log into their account
    Process:
        - Prompts user for username and checks to see if the user is locked out
        - If not locked out it will prompt the password and if 3 incorrect password attempts are attempted, it will lock them out
    """
    username = input('Please enter your username: ').strip()
    lockout_data = load_lockout()
    for user in lockout_data:
        if user['username'] == username:
            lock_time = datetime.datetime.fromisoformat(user['time']) #changes the time in the json into an time object so that it can be compared in the next if statement
            unlock = lock_time + datetime.timedelta(minutes=15) #unlock time

            if datetime.datetime.now() < unlock:
                print(f'Your account, {username}, is locked until {unlock}.\n')
                logging.warning(f'Locked out login attempt for {username}.')
                return

    users = load_database()
    count = 0
    for user in users:
        if user['username'] == username:
            print('[INFO] Username has been found.\n')
            logging.info(f'User "{username}" attempted login.')

            while count < 3:
                password = getpass.getpass('Please enter your password: ')
                if verify_password(password, user['password']):
                    if user.get('mfa'):
                        code = input('Enter the MFA code from your authenticator app: ')
                        totp = pyotp.TOTP(user['secret']) #creates a time sensitive code to compare it to the once from the application vs the users code
                        if not totp.verify(code):
                            if test_mode: return False
                            print('[ERROR] Invalid MFA code.\n')
                            logging.warning(f'Failed MFA attempt for {username}')
                            return
                    if test_mode: return True
                    print('[SUCCESS] Login successful.\n')
                    logging.info(f'User "{username}" logged in successfully.')
                    return
                else:
                    attempts_left = 2 - count
                    print(f'[INFO] Login unsuccessful. Attempts left: {attempts_left}\n')
                    logging.warning(f'Failed login attempt for {username}. Attempts left: {attempts_left}')
                    count += 1

            lockout(username, count)
            print('[INFO] LOCKOUT: too many attempts.\n')
            logging.warning(f'User "{username}" locked out after too many failed attempts.')
            return False
        
    print('[ERROR] User has not been found.\n')
    if test_mode: return False
    logging.warning(f'Login attempt for non-existent user: {username}')

# --- Delete User ---
def delete_user(test_mode=False):
    """
    Deletes the user from the database, it requires their password and their username
    Process:
        - Prompts user for username to delete, if found it will ask for password.
        - After asking for their password, it will also ask for a confirmation.
        - Check against the database password
        - Lockout can occur if there are too many incorrect attempts.
    """
    username = input('Enter the username to delete: ')
    database = load_database()
    user_delete = next((user for user in database if user['username'] == username), None) #finds the user if and defaults to None if there is no user.
    if not user_delete:
        print('[INFO] User not found.\n')
        if test_mode: return False
        logging.warning(f'Delete attempt for non-existent user: {username}')
        return

    count = 0
    while count < 3:
        password = getpass.getpass('Enter password: ')
        password_confirm = getpass.getpass('Confirm password: ')
        if password != password_confirm:
            print('Passwords did not match.\n')
            logging.warning(f'Password confirmation mismatch during delete for {username}')
            continue

        confirm_delete = input(f'Are you sure you want to delete "{username}"? (y/n): ').strip().lower()
        if confirm_delete != 'y':
            if test_mode: return False
            print('[INFO] Deletion cancelled.\n')
            logging.info(f'Deletion cancelled for {username}')
            return
        
        if verify_password(password, user_delete['password']):
            database.remove(user_delete)
            save_database(database)
            print(f'[SUCCESS] User {username} deleted.\n')
            logging.info(f'User deleted user "{username}" successfully.')
            if test_mode: return True
            return
        else:
            attempts_left = 2 - count
            print(f'[INFO] Incorrect password. Attempts left: {attempts_left}\n')
            logging.warning(f'Incorrect password attempt during delete for {username}. Attempts left: {attempts_left}')
            count += 1

    lockout(username, count)
    print('[INFO] Unable to remove user. Failed to authenticate.\n')
    logging.warning('"Failed deletion attempts for {username} led to lockout.')
    if test_mode: return False


# --- Search User ---
def search(test_mode = False):
    """
    Requires the admin password to search for one specific user.

    Notes:
        - Reserved for admin only
        - Users can be searched in the print, but if there are too many it would be more efficient to search through this function.
    """
    if not admin_authenticate():
        if test_mode == True: return False
        lockout('admin search', 1)
        logging.warning('Unauthorized admin search attempt.')
        print('[ERROR] You are unauthorized to run search for users.\n')
        return
    
    username = input('Enter user to search: ')
    logging.info(f'Admin searched for user: {username}')
    database = load_database()
    if any(user['username'] == username for user in database):
        print(f'The user {username} was found.\n')
    else:
        print(f'The user {username} was not found.\n')

# --- Run CLI ---
if __name__ == "__main__":
    main()
