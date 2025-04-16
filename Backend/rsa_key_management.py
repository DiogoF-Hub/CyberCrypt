from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.exceptions import UnsupportedAlgorithm
from typing import Optional
import os

from Backend.vars import public_keys_dir, allowed_sizes


def load_private_key(private_key_path: str, passphrase: Optional[str] = None):
    if passphrase:
        passphrase = passphrase.encode()
    else:
        passphrase = None

    with open(private_key_path, "rb") as key_file:
        key_data = key_file.read()

    try:
        private_key = serialization.load_pem_private_key(key_data, password=passphrase)
    except ValueError as e:
        raise ValueError(
            "❌ Incorrect passphrase or invalid private key format."
        ) from e
    except UnsupportedAlgorithm as e:
        raise ValueError("❌ Unsupported encryption algorithm or key type.") from e

    if not isinstance(private_key, RSAPrivateKey):
        raise ValueError("❌ The provided key is not an RSA private key.")

    return private_key


def load_public_key(public_key_path: str):
    try:
        with open(public_key_path, "rb") as key_file:
            key_data = key_file.read()
        public_key = serialization.load_pem_public_key(key_data)
    except ValueError as e:
        raise ValueError("❌ Invalid public key format.") from e
    except UnsupportedAlgorithm as e:
        raise ValueError("❌ Unsupported key algorithm.") from e

    if not isinstance(public_key, RSAPublicKey):
        raise ValueError("❌ The provided key is not an RSA public key.")

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
        # Try loading without a password (unencrypted key)
        key = load_pem_private_key(pem_bytes, password=None)
        return isinstance(key, RSAPrivateKey)
    except TypeError:
        # Encrypted private key; can't be loaded without password
        return True
    except ValueError as e:
        # Still might be an encrypted key with unsupported encryption
        if "bad decrypt" in str(e).lower() or "incorrect password" in str(e).lower():
            return True
        return False
    except UnsupportedAlgorithm:
        return False
    except Exception:
        return False


def is_rsa_public_key(pem_bytes: bytes) -> bool:
    try:
        key = serialization.load_pem_public_key(pem_bytes)
        return isinstance(key, RSAPublicKey)
    except Exception:
        return False


def is_private_key_encrypted(private_key_bytes: bytes) -> bool:
    try:
        serialization.load_pem_private_key(private_key_bytes, password=None)
        return False  # Loaded successfully without a passphrase
    except TypeError:
        return True  # Raised because a passphrase is required
    except Exception:
        return False  # Other errors = likely not encrypted, but malformed
