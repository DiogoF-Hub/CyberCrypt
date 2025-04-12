import streamlit as st
from streamlit_extras.switch_page_button import switch_page

from main import start

start()

# 1. Page config
st.set_page_config(page_title="CyberCrypt", page_icon="🔐", layout="centered")

# 2. Title and intro
st.title("🔐 CyberCrypt")
st.subheader("Secure your files with AES & RSA encryption")

st.markdown(
    """
CyberCrypt is a secure file encryption system that combines:
- **AES-256 encryption** for speed and strength
- **RSA public-key encryption** for secure key sharing
- **Password-based encryption** with optional salt and KDFs

Select what you'd like to do below 👇
"""
)

st.divider()

# 3. All navigation buttons in one row
col1, col2, col3, col4 = st.columns(4)

with col1:
    if st.button("🔒 Encrypt"):
        switch_page("Encryption")

with col2:
    if st.button("🔓 Decrypt"):
        switch_page("Decryption")

with col3:
    if st.button("🔑 Public Keys"):
        switch_page("Key_Management")

with col4:
    if st.button("🧠 Info"):
        switch_page("Info")


st.divider()
st.caption(
    "Project by CARVALHO Diogo – BTS Cybersecurity | Lycée Guillaume Kroll – 2024–2025 Talent Exhibition"
)
