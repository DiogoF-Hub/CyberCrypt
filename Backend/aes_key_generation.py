import os
import hashlib
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from argon2.low_level import hash_secret_raw, Type


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


def derive_key_from_password(
    password: str,
    salt: bytes,
    key_size=32,
    iterations=100000,
    method="pbkdf2",
    hash_algorithm="sha-256",
    argon2_iterations=2,
):
    """
    Derives an AES key from a password using PBKDF2 or Argon2.

    Args:
        password (str): The user's password.
        salt (bytes): A unique salt (at least 16 bytes recommended).
        key_size (int): AES key size (16 bytes for AES-128, 32 bytes for AES-256).
        iterations (int): Number of iterations (only for PBKDF2).
        method (str): "pbkdf2" (default) or "argon2".
        hash_algorithm (str): "sha-128" (truncated sha-256) or "sha-256" (only for PBKDF2).
        argon2_iterations (int): Number of iterations (time_cost) for Argon2.

    Returns:
        str: The derived AES key as a hex string.
    """
    if key_size not in [16, 32]:
        raise ValueError(
            "Invalid key size! Use 16 bytes for AES-128 or 32 bytes for AES-256."
        )

    password_bytes = password.encode()  # Convert password to bytes

    if method == "pbkdf2":
        # Use PBKDF2 with the selected hash function
        if hash_algorithm == "sha-128":
            full_hash = hashlib.sha256(
                password_bytes + salt
            ).digest()  # Full 32-byte SHA-256
            aes_key = full_hash[:16]  # Truncate to 128-bit key
        elif hash_algorithm == "sha-256":
            kdf = PBKDF2HMAC(
                algorithm=hashlib.sha256(),
                length=key_size,
                salt=salt,
                iterations=iterations,
            )
            aes_key = kdf.derive(password_bytes)
        else:
            raise ValueError("Invalid hash algorithm! Choose 'sha-128' or 'sha-256'.")

    elif method == "argon2":
        # Use Argon2 with configurable parameters
        aes_key = hash_secret_raw(
            password_bytes,
            salt,
            time_cost=argon2_iterations,  # User-defined number of iterations
            memory_cost=102400,  # Memory in KB
            parallelism=8,
            hash_len=key_size,
            type=Type.ID,  # Use Argon2id
        )

    else:
        raise ValueError("Invalid method! Use 'pbkdf2' or 'argon2'.")

    return aes_key.hex()  # Return key as hex


# print(f"°{generate_aes_key(32)}°")
