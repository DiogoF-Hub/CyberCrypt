from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Cipher import AES
import os

from Backend.aes_key_generation import derive_key_from_password, generate_aes_key
from Backend.iv_management import generate_iv
from Backend.rsa_key_management import load_public_key
from Backend.vars import uploads_dir, downloads_dir


def encrypt_aes_key_and_save(aes_key: bytes, salt: bytes, rsa_public_key_path: str):
    # 1. Load RSA public key from PEM file
    public_key = load_public_key(rsa_public_key_path)

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
    rsa_public_key: str,
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

    # 6. Save ciphertext (file metadata + IV + data)
    # Write filename length (2 bytes), filename, IV, then encrypted data
    encrypted_file_name = input_file + "_encrypted.bin"
    encrypted_file_path = os.path.join(downloads_dir, encrypted_file_name)
    filename_bytes = input_file.encode()
    filename_len = len(filename_bytes)

    with open(encrypted_file_path, "wb") as f:
        f.write(filename_len.to_bytes(2, "big"))  # 2-byte filename length
        f.write(filename_bytes)  # actual filename
        f.write(iv)  # 16-byte IV
        f.write(ciphertext)  # encrypted content

    # 7. Encrypt AES key with RSA & save + salt
    rsa_public_key_path = os.path.join(uploads_dir, rsa_public_key)
    encrypt_aes_key_and_save(aes_key, salt, rsa_public_key_path)


def encrypt_with_random_key(input_file: str, rsa_public_key_path: str):
    # 1. Generate AES key
    aes_key = generate_aes_key()
    salt = b""  # No salt used

    # 2. Generate IV
    iv = generate_iv()

    # 3. Read input file
    input_file_path = os.path.join(uploads_dir, input_file)
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

    # 6. Save ciphertext (file metadata + IV + data)
    # IV is stored after the filename metadata so it can be reused during decryption.
    filename = os.path.basename(input_file_path)
    filename_bytes = filename.encode()
    filename_len = len(filename_bytes)
    encrypted_file_name = input_file + "_encrypted.bin"
    encrypted_file_path = os.path.join(downloads_dir, encrypted_file_name)

    with open(encrypted_file_path, "wb") as f:
        f.write(filename_len.to_bytes(2, "big"))  # 2-byte filename length
        f.write(filename_bytes)  # actual filename
        f.write(iv)  # 16-byte IV
        f.write(ciphertext)  # encrypted content

    # 7. Encrypt AES key with RSA & save (no salt)
    encrypt_aes_key_and_save(aes_key, salt, rsa_public_key_path)
