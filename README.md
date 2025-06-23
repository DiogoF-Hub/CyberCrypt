# 🧠 CyberCrypt

**CyberCrypt** is a secure, educational file encryption tool developed for the **2024–2025 Talent Exhibition** as part of the *BTS Cloud & Cybersecurity* program at **Lycée Guillaume Kroll**.

It provides a hands-on experience in modern cryptographic techniques including AES, RSA, KDFs, and secure file handling – all wrapped in a user-friendly web interface powered by Streamlit.

---

## 🚀 Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/DiogoF-Hub/CyberCrypt.git
   cd CyberCrypt
   pip install -r requirements.txt
   streamlit run Home.py

---

## 🔐 Features

- Encrypt and decrypt files using **AES-256 (CBC mode)**
- Secure AES keys using **RSA (2048–4096-bit)** encryption
- Generate AES keys:
  - Randomly
  - Derived from a password using **PBKDF2** or **Argon2id** (with salt)
- View detailed file structure and cryptographic process
- Easy-to-use Streamlit interface

---

## ⚙️ Technologies Used

- **AES-256 (CBC mode)** – symmetric file encryption
- **RSA** – public key encryption for AES key protection
- **PBKDF2** and **Argon2id** – secure password-based key derivation
- **Python 3.11+**
- **Streamlit** – front-end web framework

---

## 🔄 How It Works

1. Upload a file to encrypt
2. Choose between:
   - Password-based encryption (with salt and KDF)
   - Random AES key generation
3. CyberCrypt:
   - Encrypts the file using AES
   - Encrypts the AES key with your RSA public key
4. Outputs:
   - Encrypted file
   - Encrypted AES key (and salt, if applicable)

---

## 📁 File Format

### 💃 Encrypted Data File
[2-byte filename length] + [original filename (bytes)] + [IV (16 bytes)] + [AES-encrypted content]


- **Filename** is stored to preserve the original name after decryption.
- **IV (Initialization Vector)** is required for AES-CBC mode.

### 🔐 Encrypted AES Key File
[RSA-encrypted AES key (256–512 bytes)]

---

✍️ Author: CARVALHO Diogo – BTS Cybersecurity | Lycée Guillaume Kroll – 2024–2025 Talent Exhibition
