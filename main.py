import os
from Backend.encryption import encrypt_with_password, encrypt_with_random_key
from Backend.decryption import decrypt_file

project_root = os.path.dirname(os.path.abspath(__file__))
uploads_dir = os.path.join(project_root, "Uploads")
downloads_dir = os.path.join(project_root, "Downloads")


def start():
    os.makedirs(uploads_dir, exist_ok=True)
    os.makedirs(downloads_dir, exist_ok=True)


start()


encrypt_with_password(
    "test.txt",
    "password123",
    "PBKDF2",
    True,
    16,
    "public_key.pem",
)


decrypt_file(
    "test.txt_encrypted.bin",
    "private_key.pem",
    "aes_key_encrypted.bin",
)
