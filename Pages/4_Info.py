import streamlit as st
from streamlit_extras.switch_page_button import switch_page

# 1. Page config
st.set_page_config(page_title="Info", page_icon="🧠", layout="centered")

# 2. Title and intro
st.title("🧠 Project Overview – CyberCrypt")

# 3. What is CyberCrypt?
st.header("🔐 What is CyberCrypt?")
st.markdown(
    """
**CyberCrypt** is a secure, educational file encryption tool designed for the **2024–2025 Talent Exhibition** as part of the *BTS Cloud & Cybersecurity* program at **Lycée Guillaume Kroll**.

It allows users to:
- Encrypt and decrypt files using **AES (Advanced Encryption Standard)**
- Protect AES keys using **RSA public-key encryption**
- Generate AES keys either **randomly** or **derived from a password**
- Customize cryptographic strength via **KDFs (Key Derivation Functions)** and **salts**
"""
)

# 4. Technologies
st.header("⚙️ Technologies Used")
st.markdown(
    """
- **AES-256 (CBC mode)** for fast and secure file encryption
- **RSA (2048–4096-bit)** to encrypt AES keys
- **PBKDF2** and **Argon2id** for secure password-based key derivation
- **Streamlit** for the user interface
- **Python 3.11+**
"""
)

# 5. How It Works
st.header("🔄 How It Works")
st.markdown(
    """
1. You upload a file to encrypt
2. Choose to:
   - Use a password (with salt + KDF)
   - Or let CyberCrypt generate a random AES key
3. CyberCrypt:
   - Encrypts your file using AES
   - Encrypts the AES key using your RSA public key
4. You get two files:
   - The **encrypted file**
   - The **encrypted AES key** (and salt, if used)
"""
)

# 6. File Structure Explanation
st.header("📆 File Format Breakdown")

with st.expander("💃️ Encrypted Data File"):
    st.markdown(
        """
When a file is encrypted, the output binary file has this structure:

```
[2-byte filename length] + [original filename (bytes)] + [IV (16 bytes)] + [AES-encrypted content]
```
- Filename helps restore the original name when decrypting
- IV is required for AES-CBC decryption
"""
    )

with st.expander("🔐 Encrypted AES Key File"):
    st.markdown(
        """
This file contains your AES key encrypted with RSA:

```
[RSA-encrypted AES key (256–512 bytes)]
```
"""
    )

# 7. Navigation
st.divider()
if st.button("🏠 Back to Home"):
    switch_page("Home")

st.caption(
    "Project by CARVALHO Diogo – BTS Cybersecurity | Lycée Guillaume Kroll – 2024–2025 Talent Exhibition"
)
