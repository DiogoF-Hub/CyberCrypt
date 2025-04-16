import streamlit as st
import os
import re
import time
import streamlit.components.v1 as components
from main import uploads_dir, downloads_dir, public_keys_dir
from Backend.encryption import encrypt_with_password, encrypt_with_random_key
from Backend.clear_files import clear_files
from Backend.vars import kdf_choices

# 1. Page setup
st.set_page_config(page_title="Encrypt File", page_icon="🔐")

# --- Inject a JS snippet that updates a timestamp query parameter whenever the page becomes visible ---
# Taken from somone online in a forum
components.html(
    """
    <script>
      function updateTimestamp() {
          const url = new URL(window.location.href);
          url.searchParams.set('ts', Date.now());
          history.replaceState(null, '', url.toString());
      }
      document.addEventListener('visibilitychange', function() {
          if (document.visibilityState === 'visible') {
              updateTimestamp();
          }
      });
      // Update immediately on load:
      updateTimestamp();
    </script>
    """,
    height=0,
)

# 2. Use the experimental query parameter APIs
params = st.experimental_get_query_params()
current_ts = params.get("ts", [None])[0]

if current_ts is None:
    current_ts = str(time.time())
    st.experimental_set_query_params(ts=current_ts)
else:
    current_ts = str(current_ts)

if "last_ts" not in st.session_state:
    st.session_state["last_ts"] = current_ts
elif st.session_state["last_ts"] != current_ts:
    # Clear encryption state when the page is revisited
    st.session_state["encryption_done"] = False
    st.session_state["encrypted_file_name"] = None
    st.session_state["last_ts"] = current_ts

st.title("🔐 Encrypt a File")

# 3. Reset session state only when explicitly triggered via the Reset Page button
if st.session_state.get("__reset_flag"):
    for key in ["encryption_done", "encrypted_file_name"]:
        st.session_state[key] = None
    clear_files(downloads_dir)
    st.session_state["__reset_flag"] = False

# Optional: Clear encryption state if the physical files no longer exist.
if st.session_state.get("encryption_done") and st.session_state.get(
    "encrypted_file_name"
):
    encrypted_file_path = os.path.join(
        downloads_dir, st.session_state["encrypted_file_name"]
    )
    aes_key_encrypted_path = os.path.join(downloads_dir, "aes_key_encrypted.bin")
    if not (
        os.path.exists(encrypted_file_path) and os.path.exists(aes_key_encrypted_path)
    ):
        st.session_state["encryption_done"] = False
        st.session_state["encrypted_file_name"] = None

# 4. Display encryption options
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

st.markdown(
    """
Select the encryption configuration manually and upload your file below.
Based on your settings, the corresponding encryption function will be called.
"""
)

# 5. Encryption config
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
    salt_size = (
        st.slider("Salt Size (in bytes):", 16, 32, 16) if salt_required else None
    )

with col2:
    password_required = kdf_choice != "Randomly generated AES key (no password)"
    password = (
        st.text_input("Password:", type="password") if password_required else None
    )

# 6. File & Key Uploads
uploaded_file = st.file_uploader("Upload a file to encrypt:")

rsa_key_files = os.listdir(public_keys_dir)
selected_key = st.selectbox(
    "Select RSA Public Key:", rsa_key_files if rsa_key_files else ["No keys available"]
)
st.caption("To upload more public keys, go to the Key Management page.")

rsa_key_path = (
    os.path.join(public_keys_dir, selected_key)
    if selected_key != "No keys available"
    else None
)

# 7. Validate & Encrypt
ready_to_encrypt = uploaded_file and rsa_key_path
if password_required:
    ready_to_encrypt = ready_to_encrypt and password

encrypt_btn = st.button("Encrypt", disabled=not ready_to_encrypt)

if encrypt_btn:
    errors = False
    kdf_choice_lower = kdf_choice.lower()
    if salt_required and salt_size is None:
        st.error("Please select a salt size.")
        errors = True
    if password_required:
        if not password or not password.strip():
            st.error("Password cannot be empty or just spaces.")
            errors = True
        else:
            password = password.strip()
            if len(password) < 6:
                st.error("Password must be at least 6 characters long.")
                errors = True
            elif not re.search(r"[A-Z]", password):
                st.error("Password must include at least one uppercase letter.")
                errors = True
            elif not re.search(r"[a-z]", password):
                st.error("Password must include at least one lowercase letter.")
                errors = True
            elif not re.search(r"[0-9]", password):
                st.error("Password must include at least one number.")
                errors = True
            elif not re.search(r"[!@#$%^&*(),.?\":{}\[\]|<>]", password):
                st.error("Password must include at least one special character.")
                errors = True
    if (
        kdf_choice_lower not in kdf_choices
        and kdf_choice_lower != "randomly generated aes key (no password)"
    ):
        st.error("Please select a valid KDF option.")
        errors = True
    if not rsa_key_path or not os.path.exists(rsa_key_path):
        st.error("Selected RSA public key file does not exist.")
        errors = True

    if not errors:
        with st.spinner("🔐 Encrypting, please wait..."):
            clear_files(uploads_dir)
            clear_files(downloads_dir)
            file_name = uploaded_file.name
            file_path = os.path.join(uploads_dir, file_name)
            with open(file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            if kdf_choice_lower == "randomly generated aes key (no password)":
                encrypt_with_random_key(file_name, rsa_key_path)
            elif kdf_choice_lower in kdf_choices:
                encrypt_with_password(
                    file_name,
                    password,
                    kdf_choice_lower,
                    salt_required,
                    salt_size,
                    rsa_key_path,
                )
            encrypted_file_name = uploaded_file.name + "_encrypted.bin"
            st.session_state["encryption_done"] = True
            st.session_state["encrypted_file_name"] = encrypted_file_name
            clear_files(uploads_dir)

# 8. Download Zone
if st.session_state.get("encryption_done") and st.session_state.get(
    "encrypted_file_name"
):
    encrypted_data_path = os.path.join(
        downloads_dir, st.session_state["encrypted_file_name"]
    )
    aes_key_encrypted_path = os.path.join(downloads_dir, "aes_key_encrypted.bin")
    if os.path.exists(encrypted_data_path) and os.path.exists(aes_key_encrypted_path):
        st.markdown(
            """
        <div style='display: flex; justify-content: center; gap: 2rem; margin-top: 1.5rem;'>
        """,
            unsafe_allow_html=True,
        )
        col1, col2 = st.columns([1, 1])
        with col1:
            with open(encrypted_data_path, "rb") as f:
                st.download_button(
                    "⬇️ Download Encrypted File",
                    f,
                    file_name=st.session_state["encrypted_file_name"],
                    use_container_width=True,
                )
        with col2:
            with open(aes_key_encrypted_path, "rb") as f:
                st.download_button(
                    "⬇️ Download Encrypted AES Key",
                    f,
                    file_name="aes_key_encrypted.bin",
                    use_container_width=True,
                )
        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown(
            "<div style='text-align: center; margin-top: 1rem;'>",
            unsafe_allow_html=True,
        )
        if st.button("🔄 Reset Page", key="reset-page-footer"):
            st.session_state["__reset_flag"] = True
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)
