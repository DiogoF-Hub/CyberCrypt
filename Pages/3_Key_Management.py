import streamlit as st
import os
import time
from Backend.vars import public_keys_dir
from Backend.rsa_key_management import (
    delete_rsa_public_key,
    write_rsa_public_key,
    is_rsa_public_key,
)

# 1. Page setup
st.set_page_config(page_title="Key Management", page_icon="🔑")
st.title("🔑 Key Management")

# 2. Instructions
st.markdown(
    """
Upload your **RSA public keys (.pem)** to securely store them for later use.
These keys will be saved inside your application's dedicated key directory.
"""
)

# Ensure uploader_key exists in session state to help reset the file uploader widget
if "uploader_key" not in st.session_state:
    st.session_state.uploader_key = 0

# Track deletion and upload state
if "deleted_key" not in st.session_state:
    st.session_state.deleted_key = None
if "delete_error" not in st.session_state:
    st.session_state.delete_error = None
if "upload_key_name" not in st.session_state:
    st.session_state.upload_key_name = None
if "upload_success" not in st.session_state:
    st.session_state.upload_success = False
if "last_uploaded" not in st.session_state:
    st.session_state.last_uploaded = None
if "upload_handled" not in st.session_state:
    st.session_state.upload_handled = False

# 3. Upload key file using a dynamic key
uploaded_key = st.file_uploader(
    "Upload RSA Public Key:",
    type=["pem"],
    key=f"uploader_{st.session_state.uploader_key}",
)

# 4. Process and store the uploaded key
if uploaded_key is not None and not st.session_state.upload_handled:
    if not uploaded_key.name.endswith(".pem"):
        st.warning("Only .pem files are allowed.")
    else:
        pem_data = bytes(uploaded_key.getbuffer())
        if not is_rsa_public_key(pem_data):
            st.error("❌ The uploaded file is not a valid RSA public key.")
        elif st.session_state.get("last_uploaded") != uploaded_key.name:
            success, key_name = write_rsa_public_key(uploaded_key.name, pem_data)
            if success:
                st.session_state.upload_key_name = key_name
                st.session_state.upload_success = True
                st.session_state.last_uploaded = key_name
                st.session_state.upload_handled = True
            else:
                st.warning(
                    f"A key named '{uploaded_key.name}' already exists. Upload aborted."
                )

# Display upload success message, wait a bit, then reset uploader
if st.session_state.upload_success:
    st.success(f"Key saved as: {st.session_state.upload_key_name}")
    st.session_state.upload_success = False
    st.session_state.upload_key_name = None
    st.session_state.upload_handled = False
    st.session_state.uploader_key += 1
    time.sleep(2)
    st.rerun()

# 5. List stored keys
st.divider()
st.subheader("📋 Stored Public Keys")

stored_keys = []
for filename in os.listdir(public_keys_dir):
    if filename.endswith(".pem"):
        full_path = os.path.join(public_keys_dir, filename)
        if os.path.isfile(full_path):
            stored_keys.append(filename)

if stored_keys:
    for key in stored_keys:
        col1, col2 = st.columns([4, 1])
        with col1:
            st.markdown(f"- {key}")
        with col2:
            if st.button("Delete", key=key):
                success = delete_rsa_public_key(key)
                st.rerun()
else:
    st.info("No public keys have been uploaded yet.")
