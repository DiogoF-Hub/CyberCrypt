from cryptography.hazmat.primitives import serialization
from typing import Optional
import os

from Backend.vars import public_keys_dir, allowed_sizes


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
    # Load RSA public key from PEM file
    with open(rsa_public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    return public_key


def validate_rsa_key_size(key_size_bits):
    # Check if the key size is supported
    if key_size_bits not in allowed_sizes:
        return False
    else:
        return True


def delete_rsa_public_key(rsa_key: str):
    rsa_key_path = os.path.join(public_keys_dir, rsa_key)
    # Delete the RSA key file
    try:
        os.remove(rsa_key_path)
        return True
    except Exception as e:
        print(f"Error deleting RSA key: {e}")
        return False


def write_rsa_public_key(rsa_key_name: str, uploaded_key: bytes):
    rsa_key_path = os.path.join(public_keys_dir, rsa_key_name)

    if os.path.exists(rsa_key_path):
        i = 1
        firstLoop = True
        while True:
            # Check if the file already exists
            if os.path.exists(rsa_key_path):
                # If it does, append a timestamp to the filename
                if firstLoop:
                    rsa_key_name = rsa_key_name.replace(".pem", f"_{i}.pem")
                    firstLoop = False
                else:
                    rsa_key_name = rsa_key_name.replace(f"_{i-1}.pem", f"_{i}.pem")
                rsa_key_path = os.path.join(public_keys_dir, rsa_key_name)
                i += 1
            else:
                break
        while True:
            # Check if the file already exists
            if os.path.exists(rsa_key_path):
                # If it does, append a timestamp to the filename
                rsa_key_name = rsa_key_name.replace(".pem", f"_{i}.pem")
                rsa_key_path = os.path.join(public_keys_dir, rsa_key_name)
            else:
                break
    # Write the RSA key to a file
    try:
        with open(rsa_key_path, "wb") as f:
            f.write(uploaded_key)
        return True, rsa_key_name
    except Exception as e:
        print(f"Error writing RSA key: {e}")
        return False, None


def is_rsa_private_key(pem_bytes: bytes) -> bool:
    try:
        # Decode bytes to string (assuming UTF-8 PEM format)
        pem_text = pem_bytes.decode("utf-8")

        # Check for common RSA private key headers
        private_headers = [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
        ]

        # Check if any known private header is present in the PEM
        for header in private_headers:
            if header in pem_text:
                return True

        return False  # No private key headers found

    except UnicodeDecodeError:
        # File is not valid UTF-8 (e.g., binary file)
        return False


def is_rsa_public_key(pem_bytes: bytes) -> bool:
    try:
        # Decode PEM bytes to UTF-8 text
        pem_text = pem_bytes.decode("utf-8")

        # Look for common public key PEM headers
        public_headers = [
            "-----BEGIN PUBLIC KEY-----",
            "-----BEGIN RSA PUBLIC KEY-----",
        ]

        # Check if any of the public headers are found
        return any(header in pem_text for header in public_headers)

    except UnicodeDecodeError:
        return False
