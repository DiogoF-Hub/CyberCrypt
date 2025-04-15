import streamlit as st
import os
import streamlit.components.v1 as components
from main import uploads_dir, downloads_dir, public_keys_dir
from Backend.encryption import encrypt_with_password, encrypt_with_random_key
from Backend.clear_files import clear_files
from Backend.vars import kdf_choices

clear_files(downloads_dir)

# 1. Page setup
st.set_page_config(page_title="Encrypt File", page_icon="🔐")
st.title("🔐 Encrypt a File")

# 2. Display encryption options from most secure to least secure
with st.expander("🔐 Encryption Options Ranked (Best to Worst)"):
    st.markdown(
        """
| Rank | AES Key | KDF      | Hash     | Salt | Password | IV  | Notes |
|------|---------|----------|----------|------|----------|-----|-------|
| ✅ 1. Best | AES-256 | Argon2id | SHA-256 | ✅ Yes | ✅ Yes | ✅ Yes | Strongest option; memory-hard |
| ✅ 2. Strong Alt | AES-256 | PBKDF2   | SHA-256 | ✅ Yes | ✅ Yes | ✅ Yes | Secure, but not memory-hard |
| ⚠️ 3. Weakest | AES-256 | PBKDF2   | SHA-256 | ❌ No  | ✅ Yes | ✅ Yes | No salt weakens key uniqueness |
| 🎲 4. Random Key | AES-256 | *(None)* | *(None)* | ❌ No | ❌ No | ✅ Yes | Must protect AES key with RSA |
        """
    )

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

    if kdf_choice == "Argon2id":
        salt_required = True
        st.markdown("Salt is required for Argon2id.")
    elif kdf_choice == "PBKDF2":
        salt_required = st.checkbox("Use Salt?", value=True)
    else:
        salt_required = False

    if salt_required:
        salt_size = st.slider(
            "Salt Size (in bytes):", min_value=16, max_value=32, value=16
        )
    else:
        salt_size = None

with col2:
    password_required = kdf_choice != "Randomly generated AES key (no password)"
    if password_required:
        password = st.text_input("Password:", type="password")
    else:
        password = None

# 5. Upload main file to encrypt
uploaded_file = st.file_uploader("Upload a file to encrypt:", type=None)

# 6. Select RSA public key from list
rsa_key_files = os.listdir(public_keys_dir)
selected_key = st.selectbox(
    "Select RSA Public Key:", rsa_key_files if rsa_key_files else ["No keys available"]
)
st.caption("To upload more public keys, go to the Key Management page.")

rsa_key_path = (
    os.path.join(public_keys_dir, selected_key)
    if selected_key and selected_key != "No keys available"
    else None
)

# 7. Check if all required fields are filled
ready_to_encrypt = uploaded_file and rsa_key_path
if password_required:
    ready_to_encrypt = ready_to_encrypt and password

# 8. Encrypt button
encrypt_btn = st.button("Encrypt", disabled=not ready_to_encrypt)

if encrypt_btn:
    errors = False
    kdf_choice = kdf_choice.lower()

    if salt_required and salt_size is None:
        st.error("Please select a salt size.")
        errors = True

    if password_required and not password:
        st.error("Please enter a password.")
        errors = True

    if (
        kdf_choice not in kdf_choices
        and kdf_choice != "randomly generated aes key (no password)"
    ):
        st.error("Please select a valid KDF option.")
        errors = True

    if not rsa_key_path or not os.path.exists(rsa_key_path):
        st.error("Selected RSA public key file does not exist.")
        errors = True

    if errors == False:
        with st.spinner("🔐 Encrypting, please wait..."):
            clear_files(uploads_dir)

            file_name = uploaded_file.name
            file_path = os.path.join(uploads_dir, file_name)
            with open(file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            st.success(f"File uploaded to Uploads/{file_name}")

            clear_files(downloads_dir)

            if kdf_choice == "randomly generated aes key (no password)":
                encrypt_with_random_key(file_path, rsa_key_path)
            elif kdf_choice in kdf_choices:
                encrypt_with_password(
                    file_name,
                    password,
                    kdf_choice,
                    salt_required,
                    salt_size,
                    rsa_key_path,
                )

            encrypted_file_name = uploaded_file.name + "_encrypted.bin"
            st.session_state["encryption_done"] = True
            st.session_state["encrypted_file_name"] = encrypted_file_name
            clear_files(uploads_dir)

# 9. Download buttons outside encryption block
if st.session_state.get("encryption_done"):
    encrypted_file_name = st.session_state["encrypted_file_name"]
    encrypted_data_path = os.path.join(downloads_dir, encrypted_file_name)
    aes_key_encrypted_path = os.path.join(downloads_dir, "aes_key_encrypted.bin")

    st.markdown(
        """
    <div style='display: flex; justify-content: center; gap: 2rem; margin-top: 1.5rem;'>
    """,
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns([1, 1])

    with col1:
        if os.path.exists(encrypted_data_path):
            with open(encrypted_data_path, "rb") as f:
                st.download_button(
                    "⬇️ Download Encrypted File",
                    f,
                    file_name=encrypted_file_name,
                    use_container_width=True,
                )

    with col2:
        if os.path.exists(aes_key_encrypted_path):
            with open(aes_key_encrypted_path, "rb") as f:
                st.download_button(
                    "⬇️ Download Encrypted AES Key",
                    f,
                    file_name="aes_key_encrypted.bin",
                    use_container_width=True,
                )

    st.markdown("""</div>""", unsafe_allow_html=True)

    st.markdown(
        """<div style='text-align: center; margin-top: 1rem;'>""",
        unsafe_allow_html=True,
    )
    if st.button("🔄 Reset Page", key="reset-page-footer"):
        components.html(
            """
                <script>
                    parent.window.location.reload();
                </script>
                """,
            height=0,
        )
        st.markdown("""</div>""", unsafe_allow_html=True)
