# 🔐 PQ Packager (Kyber) — Linux Edition

A **post-quantum encryption GUI** using **ML-KEM (aka Kyber)** for key exchange and **AES-256-GCM** for authenticated encryption.  
Built with Python 3, Tkinter, and liboqs (Open Quantum Safe).

---

## ✨ Features
- ML-KEM-768 (Kyber) key encapsulation
- AES-256-GCM encryption with HKDF-SHA-256 key derivation
- HMAC-SHA-256 integrity protection
- Ephemeral in-RAM key handling – no persistent secrets
- GUI with auto-scrolling logs and log export
- Works on Linux 3.9+ with OpenSSL 3 or liboqs backend

---

## 🧰 Installation
```bash
git clone https://github.com/<yourusername>/crystal_kyber.git
cd crystal_kyber
bash install_linux.sh
