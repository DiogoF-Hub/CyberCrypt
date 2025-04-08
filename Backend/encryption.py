from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Cipher import AES
import os

from Backend.aes_key_generation import derive_key_from_password, generate_aes_key
from Backend.iv_management import generate_iv

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
uploads_dir = os.path.join(root_dir, "Uploads")
downloads_dir = os.path.join(root_dir, "Downloads")


def encrypt_aes_key_and_save(aes_key: bytes, salt: bytes, rsa_public_key_path: str):
    # 1. Load RSA public key from PEM file
    with open(rsa_public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    # 2. Encrypt the AES key using RSA with OAEP padding
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 3. Combine encrypted AES key and salt (if any)
    payload = encrypted_aes_key + salt  # salt may be empty (b"")

    # 4. Save to file
    aes_key_file_path = os.path.join(downloads_dir, "aes_key_encrypted.bin")
    with open(aes_key_file_path, "wb") as f:
        f.write(payload)


def encrypt_with_password(
    input_file: str,
    password: str,
    method: str,
    use_salt: bool,
    salt_length: int,
    rsa_public_key_path: str,
):
    # 1. Derive AES key from password
    aes_key, salt = derive_key_from_password(password, method, use_salt, salt_length)

    # 2. Generate IV
    iv = generate_iv()

    # 3. Read input file
    input_file_path = os.path.join(uploads_dir, input_file)
    with open(input_file_path, "rb") as f:
        plaintext = f.read()

    # 4. Pad file (PKCS#7-style)
    pad_len = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + bytes([pad_len] * pad_len)

    # 5. Encrypt with AES
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_plaintext)

    # 6. Save ciphertext (IV + data)
    encrypted_file_path = os.path.join(downloads_dir, "encrypted_data.bin")
    with open(encrypted_file_path, "wb") as f:
        f.write(iv + ciphertext)

    # 7. Encrypt AES key with RSA & save + salt
    encrypt_aes_key_and_save(aes_key, salt, rsa_public_key_path)


def encrypt_with_random_key(input_file_path: str, rsa_public_key_path: str):
    # 1. Generate AES key
    aes_key = generate_aes_key()
    salt = b""  # No salt used

    # 2. Generate IV
    iv = generate_iv()

    # 3. Read input file
    with open(input_file_path, "rb") as f:
        plaintext = f.read()

    # 4. Pad file (PKCS#7-style)
    # AES-CBC requires input to be a multiple of 16 bytes (block size).
    # PKCS#7 padding fills the last block with N bytes, each with the value N.
    # If the file is already aligned (e.g. 32, 48 bytes...), a full block of padding (16 bytes of 0x10) is added.
    # This ensures that during decryption, the correct number of bytes is removed
    # by reading the last byte (which always indicates the pad length).
    pad_len = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + bytes([pad_len] * pad_len)

    # 5. Encrypt with AES
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_plaintext)

    # 6. Save ciphertext (IV + data)
    # IV is stored in the first 16 bytes of the file so it can be reused during decryption.
    encrypted_file_path = os.path.join(downloads_dir, "encrypted_data.bin")
    with open(encrypted_file_path, "wb") as f:
        f.write(iv + ciphertext)

    # 7. Encrypt AES key with RSA & save (no salt)
    encrypt_aes_key_and_save(aes_key, salt, rsa_public_key_path)
