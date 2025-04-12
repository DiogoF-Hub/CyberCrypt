import os

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
uploads_dir = os.path.join(root_dir, "Uploads")
downloads_dir = os.path.join(root_dir, "Downloads")
public_keys_dir = os.path.join(root_dir, "Public-Keys")

# RSA key size in bytes
allowed_sizes = [2048, 3072, 4096]
