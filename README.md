# Advanced Encrypter / Decrypter (Python + Tkinter GUI)

A modern, secure text encryption–decryption desktop app built in Python using:

- **AES-256 (GCM mode)** for encryption  
- **PBKDF2-HMAC-SHA512** for key derivation  
- **HMAC-SHA512** for integrity / tamper protection  
- A clean **Tkinter + ttk** graphical user interface

This project lets you safely encrypt and decrypt any text using strong cryptography with an easy-to-use GUI.

---

## Features

### Military-Grade Encryption

- AES-256 in **GCM mode** (authenticated encryption)
- **PBKDF2-HMAC-SHA512** with 100,000 iterations for key derivation
- Per-message random values:
  - 32-byte salt
  - 16-byte nonce
  - 16-byte IV

### Integrity & Tamper Protection

- Full message authentication via **HMAC-SHA512**
- Detects:
  - Incorrect passwords
  - Tampered / corrupted encrypted data

### Modern GUI

- Built with **Tkinter** and **ttk** themed widgets
- Separate sections for:
  - Encryption
  - Decryption
- One-click actions:
  - **Encrypt Text**
  - **Decrypt Text**
  - **Copy Encrypted**
  - **Paste to Decrypt**
  - **Use Default Password**
  - **Clear All**

### Extra Details

- Default password: `1234` (for testing only – you should change this)
- Secure clipboard handling for encrypted text
- Clear and friendly dialog messages for success and errors

---

## Project Structure

```text
EncrypterDecrypter/
├── encrypterdecrypter.py   # Full encryption/decryption logic + Tkinter GUI
└── README.md               # Project documentation
