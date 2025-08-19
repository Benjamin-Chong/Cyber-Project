import pytest
import pyotp
from cli import new_user, load_database, save_database, lockout, load_lockout, login, delete_user, search
from breach import check_breach
from auth import hash_password, verify_password

# --- Fake in-memory database fixture ---
@pytest.fixture
def fake_db(monkeypatch):
    storage = []

    monkeypatch.setattr("cli.load_database", lambda: storage)
    monkeypatch.setattr("cli.save_database", lambda data: storage.extend(data) or None)
    monkeypatch.setattr("cli.lockout", lambda username, count: None)
    monkeypatch.setattr("cli.load_lockout", lambda: [])

    return storage

# --- New User Tests ---
def test_new_user_success(fake_db, monkeypatch):
    inputs = iter(["testuser", "testuser", "n"])
    passwords = iter(["CorrectPassword1!", "CorrectPassword1!"])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    monkeypatch.setattr("getpass.getpass", lambda _: next(passwords))

    result = new_user(test_mode=True)
    assert result is True
    assert fake_db[0]['username'] == "testuser"

def test_new_user_fail_exception(monkeypatch):
    monkeypatch.setattr("builtins.open", lambda *a, **kw: (_ for _ in ()).throw(IOError("Test exception")))
    result = new_user(test_mode=True)
    assert result is False

def test_duplicate_username(fake_db, monkeypatch):
    fake_db.append({'username': 'testuser', 'password': 'hashedpass'})
    inputs = iter(['testuser', 'testuser', 'n'])
    passwords = iter(['CorrectPassword1!', 'CorrectPassword1!'])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    monkeypatch.setattr("getpass.getpass", lambda _: next(passwords))
    result = new_user(test_mode=True)
    assert result is False

def test_invalid_username(fake_db, monkeypatch):
    # Empty username
    inputs = iter(['', '', 'n'])
    passwords = iter(['CorrectPassword1!', 'CorrectPassword1!'])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    monkeypatch.setattr("getpass.getpass", lambda _: next(passwords))
    assert new_user(test_mode=True) is False

    # Username with spaces
    inputs = iter(['test username', 'test username', 'n'])
    passwords = iter(['CorrectPassword1!', 'CorrectPassword1!'])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    monkeypatch.setattr("getpass.getpass", lambda _: next(passwords))
    assert new_user(test_mode=True) is False

def test_password_validation(fake_db, monkeypatch):
    # No capital
    inputs = iter(['testuser', 'testuser', 'n'])
    passwords = iter(['correctpassword1!', 'correctpassword1!'])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    monkeypatch.setattr("getpass.getpass", lambda _: next(passwords))
    assert new_user(test_mode=True) is False

    # No number
    passwords = iter(['CorrectPassword!', 'CorrectPassword!'])
    assert new_user(test_mode=True) is False

    # No special character
    passwords = iter(['CorrectPassword1', 'CorrectPassword1'])
    assert new_user(test_mode=True) is False

    # Not enough length
    passwords = iter(['CP1!', 'CP1!'])
    assert new_user(test_mode=True) is False

    # Password mismatch
    passwords = iter(['CorrectPassword1!', 'Correctpassword1!'])
    assert new_user(test_mode=True) is False

    # Common password
    passwords = iter(['123456789', '123456789'])
    assert new_user(test_mode=True) is False

# --- Breach Check Tests ---
def test_check_breach_safe_password():
    breached, count = check_breach("ThisIsNotInBreach123!@#")
    assert breached is False
    assert count == 0

def test_check_breach_known_password():
    breached, count = check_breach("password")
    assert breached is True
    assert isinstance(count, int)
    assert count > 0

# --- Login Tests ---
def test_login_non_existing_user(fake_db, monkeypatch):
    fake_db.append({'username': 'testuser', 'password': hash_password('CorrectPassword1!'), 'mfa': False, 'secret': None})
    inputs = iter(['ben'])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    assert login(test_mode=True) is False

def test_login_password_fail(fake_db, monkeypatch):
    fake_db.append({'username': 'testuser', 'password': hash_password('CorrectPassword1!'), 'mfa': False, 'secret': None})
    inputs = iter(['testuser'])
    passwords = iter(['WrongPassword1!']*3)
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    monkeypatch.setattr("getpass.getpass", lambda _: next(passwords))
    assert login(test_mode=True) is False

def test_login_password_pass(fake_db, monkeypatch):
    fake_db.append({'username': 'testuser', 'password': hash_password('CorrectPassword1!'), 'mfa': False, 'secret': None})
    inputs = iter(['testuser'])
    passwords = iter(['CorrectPassword1!'])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    monkeypatch.setattr("getpass.getpass", lambda _: next(passwords))
    assert login(test_mode=True) is True

def test_login_mfa_pass(fake_db, monkeypatch):
    secret = pyotp.random_base32()
    fake_db.append({'username': 'testuser', 'password': hash_password('CorrectPassword1!'), 'mfa': True, 'secret': secret})
    totp = pyotp.TOTP(secret)
    inputs = iter(['testuser', totp.now()])
    passwords = iter(['CorrectPassword1!'])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    monkeypatch.setattr("getpass.getpass", lambda _: next(passwords))
    assert login(test_mode=True) is True

def test_login_mfa_fail(fake_db, monkeypatch):
    secret = pyotp.random_base32()
    fake_db.append({'username': 'testuser', 'password': hash_password('CorrectPassword1!'), 'mfa': True, 'secret': secret})
    inputs = iter(['testuser', '000000'])
    passwords = iter(['CorrectPassword1!'])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    monkeypatch.setattr("getpass.getpass", lambda _: next(passwords))
    assert login(test_mode=True) is False

def test_login_lockout(fake_db, monkeypatch):
    fake_db.append({'username':'testuser', 'password': hash_password('CorrectPassword1!')})
    inputs = iter(['testuser']*3)
    passwords = iter(['WrongPass1!','WrongPass2!','WrongPass3!'])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    monkeypatch.setattr("getpass.getpass", lambda _: next(passwords))
    assert login(test_mode=True) is False

# --- Delete User Tests ---
def test_delete_user_no_user(fake_db, monkeypatch):
    inputs = iter(['benjamin'])
    passwords = iter(['FakePassword1!'])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    monkeypatch.setattr("getpass.getpass", lambda _: next(passwords))
    assert delete_user(test_mode=True) is False

def test_delete_user_success(fake_db, monkeypatch):
    fake_db.append({'username':'testuser','password':hash_password('CorrectPassword1!')})
    inputs = iter(['testuser','y'])
    passwords = iter(['CorrectPassword1!','CorrectPassword1!'])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    monkeypatch.setattr("getpass.getpass", lambda _: next(passwords))
    assert delete_user(test_mode=True) is True

def test_delete_user_wrong_pass(fake_db, monkeypatch):
    fake_db.append({'username':'testuser','password':hash_password('CorrectPassword1!')})
    inputs = iter(['testuser','y','y','y'])
    passwords = iter(['WrongPassword1!']*6)
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    monkeypatch.setattr("getpass.getpass", lambda _: next(passwords))
    assert delete_user(test_mode=True) is False

# --- Admin Search Tests ---
def test_search_admin_unauthorized(monkeypatch):
    monkeypatch.setattr("cli.admin_authenticate", lambda: False)
    assert search(test_mode=True) is False

def test_search_admin_authorized(fake_db, monkeypatch):
    fake_db.append({'username':'testuser','password':hash_password('CorrectPassword1!')})
    monkeypatch.setattr("cli.admin_authenticate", lambda: True)
    inputs = iter(['testuser'])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    search(test_mode=True)  # Should run without error
