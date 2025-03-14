import os
from salt_management import generate_salt
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives import hashes


def generate_aes_key(key_size=32):
    """
    Generates a secure AES key of specified size (default 32 bytes for AES-256).
    """

    if key_size not in [16, 32]:
        raise ValueError(
            "Invalid key size! Use 16 bytes for AES-128 or 32 bytes for AES-256."
        )

    aes_key = get_random_bytes(key_size)  # Secure random key
    return aes_key.hex()


def derive_key_from_password(password, method, use_salt, salt_length):
    """
    Derives a secure AES key from a password using the specified method and the use of salt and salt length.
    """

    if method not in ["pbkdf2", "argon2"]:
        raise ValueError("Invalid method! Use 'pbkdf2' or 'argon2'.")

    # Argon2 requires a salt length of at least 16
    # Above 32 bytes is not recommended
    if salt_length < 16 or salt_length > 32:
        raise ValueError("Invalid salt length! Use a value between 16 and 32 bytes.")

    # argon2 requires salt, pbkdf2 does not
    if not use_salt and method == "pbkdf2":
        salt = b""
    else:
        salt = generate_salt(salt_length)

    password_bytes = password.encode()  # Convert password to bytes

    if method == "pbkdf2":
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        aes_key = kdf.derive(password_bytes).hex()
    elif method == "argon2":
        # Use Argon2 with configurable parameters
        aes_key = hash_secret_raw(
            password_bytes,
            salt,
            time_cost=2,
            memory_cost=102400,  # Memory in KB
            parallelism=8,
            hash_len=32,
            type=Type.ID,  # Use Argon2id
        ).hex()

    return aes_key, salt.hex()
