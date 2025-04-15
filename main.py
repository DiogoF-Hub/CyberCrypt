import os
from Backend.encryption import encrypt_with_password, encrypt_with_random_key
from Backend.decryption import decrypt_file
from Backend.clear_files import clear_files
from Backend.vars import root_dir, uploads_dir, downloads_dir, public_keys_dir


def start():
    clear_files(uploads_dir)
    clear_files(downloads_dir)
    os.makedirs(uploads_dir, exist_ok=True)
    os.makedirs(downloads_dir, exist_ok=True)
    os.makedirs(public_keys_dir, exist_ok=True)


"""
encrypt_with_password(
    "test.txt",
    "password123",
    "PBKDF2",
    True,
    16,
    "public_key.pem",
)
"""

"""
decrypt_file(
    "test.txt_encrypted.bin",
    "private_key.pem",
    "aes_key_encrypted.bin",
)
"""
