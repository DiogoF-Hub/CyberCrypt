from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives import hashes

from Backend.salt_management import generate_salt
from Backend.vars import kdf_choices


def generate_aes_key():
    """
    Generates a secure AES key of specified size (default 32 bytes for AES-256).
    """
    key_size = 32  # AES-256

    aes_key = get_random_bytes(key_size)  # Secure random key
    return aes_key


def derive_key_from_password(
    password: str, method: str, use_salt: bool, salt_length: int
):
    method = method.lower()  # Normalize method to lowercase
    if method not in kdf_choices:
        raise ValueError("Invalid method! Use 'pbkdf2' or 'argon2'.")

    # 1. Validate and generate salt
    if use_salt:
        if salt_length is None:
            raise ValueError("Salt length is required when use_salt is True.")
        if salt_length < 16 or salt_length > 32:
            raise ValueError(
                "Invalid salt length! Use a value between 16 and 32 bytes."
            )
        salt = generate_salt(salt_length)
    elif method == "pbkdf2":
        salt = b""
    else:
        salt = None  # Should not happen, Argon2 always requires salt

    # 2. Encode password
    password_bytes = password.encode()

    # 3. Derive key
    if method == "pbkdf2":
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        aes_key = kdf.derive(password_bytes)
    elif method == "argon2id":
        aes_key = hash_secret_raw(
            password_bytes,
            salt,
            time_cost=2,
            memory_cost=102400,  # Memory in KB
            parallelism=8,
            hash_len=32,
            type=Type.ID,  # Use Argon2id
        )

    return aes_key, salt
