import streamlit as st
import os
from main import uploads_dir, downloads_dir

# 1. Page setup
st.set_page_config(page_title="Encrypt File", page_icon="🔐")
st.title("🔐 Encrypt a File")


# 3. Instructions
st.markdown(
    """
Select the encryption configuration manually and upload your file below.
Based on your settings, the corresponding encryption function will be called.
"""
)

# 4. User selects encryption components freely
col1, col2 = st.columns(2)

with col1:
    kdf_options = ["Argon2id", "PBKDF2", "Randomly generated AES key (no password)"]
    kdf_choice = st.selectbox("Key Derivation Function (KDF):", kdf_options)

    # Salt is required for Argon2id, optional for PBKDF2, and hidden if random AES is chosen
    if kdf_choice == "Argon2id":
        salt_required = True
        st.markdown("Salt is required for Argon2id.")
    elif kdf_choice == "PBKDF2":
        salt_required = st.checkbox("Use Salt?", value=True)
    else:
        salt_required = False

with col2:
    # Password input is only required for PBKDF2 and Argon2id
    password_required = kdf_choice != "Randomly generated AES key (no password)"
    if password_required:
        password = st.text_input("Password:", type="password")

# 5. Upload main file to encrypt
uploaded_file = st.file_uploader("Upload a file to encrypt:", type=None)

# 6. Upload RSA public key
rsa_public_key_file = st.file_uploader("Upload RSA Private Key:", type=["pem"])

# 7. Store uploaded files in Uploads folder
if uploaded_file:
    file_path = os.path.join(uploads_dir, uploaded_file.name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    st.success(f"File uploaded to Uploads/{uploaded_file.name}")

if rsa_public_key_file:
    rsa_key_path = os.path.join(uploads_dir, rsa_public_key_file.name)
    with open(rsa_key_path, "wb") as f:
        f.write(rsa_public_key_file.getbuffer())
    st.success(f"RSA public key uploaded to Uploads/{rsa_public_key_file.name}")

# 8. Encrypt button
if st.button("Encrypt"):
    st.success("Encryption completed successfully (stub message).")

    # 9. Display download buttons for output files
    encrypted_data_path = os.path.join(downloads_dir, "encrypted_data.bin")
    aes_key_encrypted_path = os.path.join(downloads_dir, "aes_key_encrypted.bin")

    if os.path.exists(encrypted_data_path):
        with open(encrypted_data_path, "rb") as f:
            st.download_button(
                "Download Encrypted File", f, file_name="encrypted_data.bin"
            )

    if os.path.exists(aes_key_encrypted_path):
        with open(aes_key_encrypted_path, "rb") as f:
            st.download_button(
                "Download Encrypted AES Key", f, file_name="aes_key_encrypted.bin"
            )
