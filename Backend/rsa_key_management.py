from cryptography.hazmat.primitives import serialization
from typing import Optional


def load_private_key(private_key_path: str, passphrase: Optional[str] = None):
    # 1. Handle optional passphrase
    if passphrase:
        passphrase = passphrase.encode()
    else:
        passphrase = None

    # 2. Load and return the private key object
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=passphrase
        )

    return private_key


def load_public_key(rsa_public_key_path: str):
    # 1. Load RSA public key from PEM file
    with open(rsa_public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    return public_key
