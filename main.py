import os
from Backend.encryption import encrypt_with_password

project_root = os.path.dirname(os.path.abspath(__file__))
uploads_dir = os.path.join(project_root, "Uploads")
downloads_dir = os.path.join(project_root, "Downloads")


def start():
    os.makedirs(uploads_dir, exist_ok=True)
    os.makedirs(downloads_dir, exist_ok=True)


start()
filepath = os.path.join(uploads_dir, "exiftool-13.26_64.zip")
public_key_path = os.path.join(project_root, "Uploads", "public_key.pem")
encrypt_with_password(
    filepath,
    "password123",
    "PBKDF2",
    True,
    16,
    public_key_path,
)
