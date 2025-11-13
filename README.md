🔐 Advanced Encrypter / Decrypter (Python + Tkinter GUI)

A powerful, modern, and secure encryption–decryption desktop application built using Python, AES-256-GCM, PBKDF2-HMAC-SHA512, and a clean Tkinter GUI.

This project allows you to securely encrypt and decrypt text using strong cryptography standards with an easy-to-use interface.

🚀 Features
🔒 Military-Grade Encryption

AES-256 (GCM Mode — Authenticated Encryption)

PBKDF2-HMAC-SHA512 key derivation (100,000 iterations)

Per-message:

Random 32-byte salt

Random 16-byte nonce

Random 16-byte IV

🛡️ Integrity & Tamper Protection

Full message authentication using HMAC-SHA512

Detects incorrect passwords or tampered data instantly

🧰 Modern GUI

Built using Tkinter + ttk themed widgets

Separate sections for encryption & decryption

One-click:

Copy Encrypted Text

Paste to Decrypt

Reset to Default Password

Clear All

⚙️ Additional Features

Default password provided (customizable)

Secure handling of clipboard operations

Clear and simple messaging through dialog boxes

📸 Screenshots

(Add screenshots here when uploading to GitHub)

📂 Project Structure
/project-folder
│── encrypterdecrypter.py   # Full code for encryption, decryption & GUI
└── README.md               # Documentation

🧑‍💻 Installation & Setup
1️⃣ Clone the repository
git clone https://github.com/yourusername/yourrepo.git
cd yourrepo

2️⃣ Install dependencies

This project requires the cryptography library.

pip install cryptography


Everything else is included in the Python standard library.

3️⃣ Run the application
python encrypterdecrypter.py

🛠️ How It Works
🔑 Key Derivation

User password + 32-byte random salt

PBKDF2-HMAC-SHA512 → 64 bytes derived

First 32 bytes → AES-256 key

Next 32 bytes → HMAC key

🔐 Encryption

AES-256-GCM used for authenticated encryption

Additional authenticated data: salt + nonce

Message package includes:

salt, nonce, IV, ciphertext, tag, HMAC

🔓 Decryption

Reconstructs keys using password + salt

Verifies HMAC before decrypting

Decrypts using AES-GCM

🧪 Example Code Usage (Non-GUI)
from encrypterdecrypter import AdvancedEncrypter

enc = AdvancedEncrypter()
cipher = enc.encrypt("hello world", password="mypassword")
plain = enc.decrypt(cipher, password="mypassword")

⚠️ Security Notes

Default password is 1234 → meant only for testing.

Always use a strong password for real use cases.

The encryption scheme follows modern security practices (AES-GCM + PBKDF2 + HMAC).

🤝 Contributing

Pull requests are welcome! If you have ideas for:

File encryption

Dark/Light theme toggle

UI redesign

CLI version

Feel free to open an issue.

📜 License

This project is released under the MIT License.
