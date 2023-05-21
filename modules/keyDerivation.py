from os import urandom
from getpass import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def DeriveKey(salt=None):
    """
    A Key derivation function using PBKDF2. Produces a cryptographically secure key from user inputted password. If salt is given, it will be used.
    Input: Salt (Optional)
    Output: An array of Encryption key, Salt
    """
    if salt is None:
        salt = urandom(16)

    kdf = PBKDF2HMAC(
    algorithm   = hashes.SHA256(),
    length      = 32,
    salt        = salt,
    iterations  = 300000,
    )

    key = kdf.derive(getpass("Please enter your password: ").encode())
    return [key, salt]
