import streamlit as st
import streamlit.components.v1 as components
import os
from Backend.vars import downloads_dir, uploads_dir
from Backend.rsa_key_management import is_private_key_encrypted, is_rsa_private_key
from Backend.decryption import decrypt_file
from Backend.clear_files import clear_files

# 1. Page setup
st.set_page_config(page_title="Decrypt File", page_icon="🔐")
st.title("🔐 Decrypt a File")

# 2. Instructions
with st.expander("ℹ️ How to Use"):
    st.markdown(
        """
    **To decrypt a file:**
    1. Upload your encrypted file (`.bin`)  
    2. Upload the encrypted AES key file (`.bin`)  
    3. Upload your RSA private key (`.pem`)  
    4. Provide a passphrase (if your private key is encrypted)  
    5. Click **Decrypt**
    """
    )

# 3. File Upload Section
st.subheader("📂 Upload Required Files")

# Uploads in a wide single row
st.markdown(
    """
<div style='display: flex; justify-content: center; gap: 2rem;'>
""",
    unsafe_allow_html=True,
)

col1, col2, col3 = st.columns(3)

with col1:
    encrypted_file = st.file_uploader(
        "Encrypted File (.bin)", type=["bin"], key="enc_file"
    )

with col2:
    aes_key_file = st.file_uploader(
        "Encrypted AES Key (.bin)", type=["bin"], key="aes_key"
    )

with col3:
    private_key_file = st.file_uploader(
        "RSA Private Key (.pem)", type=["pem"], key="priv_key"
    )

st.markdown("""</div>""", unsafe_allow_html=True)

passphrase = None
key_is_valid = False
requires_passphrase = False

if private_key_file:
    key_bytes = private_key_file.getvalue()
    try:
        key_is_valid = is_rsa_private_key(key_bytes)
        if key_is_valid:
            requires_passphrase = is_private_key_encrypted(key_bytes)
    except Exception:
        key_is_valid = False
        requires_passphrase = False

    if not key_is_valid:
        st.error("❌ The uploaded file is not a valid RSA private key.")
    elif requires_passphrase:
        passphrase = st.text_input("Passphrase", type="password")

    if not requires_passphrase:
        passphrase = None

# 4. Decrypt button enable logic
button_disabled = not (
    encrypted_file
    and aes_key_file
    and private_key_file
    and key_is_valid
    and (not requires_passphrase or (requires_passphrase and passphrase))
)

# 5. Decryption process
st.markdown("---")
st.subheader("🚀 Decryption")

if st.button("🔑 Decrypt", disabled=button_disabled):
    with st.spinner("🔐 Decrypting, please wait..."):
        clear_files(uploads_dir)
        clear_files(downloads_dir)

        enc_path = os.path.join(uploads_dir, encrypted_file.name)
        aes_path = os.path.join(uploads_dir, aes_key_file.name)
        priv_path = os.path.join(uploads_dir, private_key_file.name)

        with open(enc_path, "wb") as f:
            f.write(encrypted_file.getbuffer())
        with open(aes_path, "wb") as f:
            f.write(aes_key_file.getbuffer())
        with open(priv_path, "wb") as f:
            f.write(private_key_file.getvalue())

        try:
            output_path = decrypt_file(
                encrypted_file.name,
                private_key_file.name,
                aes_key_file.name,
                passphrase=passphrase if passphrase else None,
            )
            if output_path:
                st.session_state.decrypted_file_path = output_path
                st.success("✅ Decryption successful!")
                clear_files(uploads_dir)
            else:
                st.error("❌ Decryption failed. Check your files or passphrase.")
                st.session_state.decrypted_file_path = None
        except Exception as e:
            st.session_state.decrypted_file_path = None
            st.error(
                "⚠️ An error occurred: ❌ Incorrect passphrase or invalid private key format."
            )

# 6. Persistent Download + Reset Buttons in one centered row
if st.session_state.get("decrypted_file_path") and os.path.exists(
    st.session_state.decrypted_file_path
):
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        btn1, btn2 = st.columns(2)
        with btn1:
            with open(st.session_state.decrypted_file_path, "rb") as f:
                st.download_button(
                    "📥 Download",
                    f,
                    file_name=os.path.basename(st.session_state.decrypted_file_path),
                )
        with btn2:
            st.button(
                "🔁 Reset",
                key="reset-page-footer",
                on_click=lambda: components.html(
                    """
                <script>
                    parent.window.location.reload();
                </script>
                """,
                    height=0,
                ),
            )
