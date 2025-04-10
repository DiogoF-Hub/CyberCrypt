from Crypto.Cipher import AES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from typing import Optional
import os
from Backend.rsa_key_management import load_private_key


root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
uploads_dir = os.path.join(root_dir, "Uploads")
downloads_dir = os.path.join(root_dir, "Downloads")

# RSA key size in bytes
allowed_sizes = [2048, 3072, 4096]


def decrypt_file(
    input_file: str,
    private_key: str,
    aes_key: str,
    passphrase: Optional[str] = None,
):

    private_key_path = os.path.join(uploads_dir, private_key)
    private_key = load_private_key(private_key_path, passphrase)

    # 3. Read and decrypt AES key
    aes_key_path = os.path.join(uploads_dir, aes_key)
    with open(aes_key_path, "rb") as f:
        # Get RSA key size in bytes
        key_size_bits = private_key.key_size

        # Check if the key size is supported
        if key_size_bits not in allowed_sizes:
            raise ValueError(
                f"Unsupported RSA key size: {key_size_bits} bits. Allowed: {allowed_sizes}"
            )

        # Convert to bytes
        key_size_bytes = key_size_bits // 8

        # Read encrypted AES key based on RSA key size
        encrypted_aes_key = f.read(key_size_bytes)

    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 4. Read filename, IV and ciphertext
    # The filename and IV were prepended during encryption to allow correct decryption and file restoration.
    encrypted_file_path = os.path.join(uploads_dir, input_file)
    with open(encrypted_file_path, "rb") as f:
        filename_len = int.from_bytes(f.read(2), "big")  # Read filename length
        original_filename = f.read(filename_len).decode()  # Read original filename
        iv = f.read(16)  # Read IV
        ciphertext = f.read()  # Read the rest (ciphertext)

    # 5. Decrypt and unpad
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)

    # Get the padding length from the last byte of the decrypted data
    pad_len = decrypted_padded[-1]
    # Remove the padding to recover the original plaintext
    plaintext = decrypted_padded[:-pad_len]

    # 6. Write to file
    original_filename_path = os.path.join(downloads_dir, original_filename)
    with open(original_filename_path, "wb") as f:
        f.write(plaintext)

    print(f"Decryption complete: {original_filename}")
