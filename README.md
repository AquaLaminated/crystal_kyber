# PQ Packager (Kyber) — Linux Edition

A **post-quantum encryption GUI** using **ML-KEM (aka Kyber)** for key exchange and **AES-256-GCM** for authenticated encryption.  
Built with Python 3, Tkinter, and liboqs (Open Quantum Safe).

---

## Features
- ML-KEM-768 (Kyber) key encapsulation
- AES-256-GCM encryption with HKDF-SHA-256 key derivation
- HMAC-SHA-256 integrity protection
- Ephemeral in-RAM key handling – no persistent secrets
- GUI with auto-scrolling logs and log export
- Works on Linux 3.9+ with OpenSSL 3 or liboqs backend

---

## Installation
To install PQ Packager (Kyber) on Linux:


```bash
git clone https://github.com/AquaLaminated/crystal_kyber.git
cd crystal_kyber
bash install_linux.sh
./run_gui.sh



Using Crystal Kyber

Open the program — GUI appears.

Choose an encryption mode:

Text Encryption

File Encryption

Click “Generate Keys” to create a new ML-KEM keypair (in RAM only).

Select Encrypt to encrypt your message or file.

Output: *.pqpk encrypted package

Log: *.pqpk.log (next to output file)

To decrypt, load the encrypted package and your private key (if available).

Logs are automatically sanitized (no sensitive data stored).




Technical Overview
Component	Purpose
liboqs	Provides ML-KEM (Kyber) implementation
oqs-provider	Integrates liboqs with OpenSSL 3 provider framework
AES-256-GCM	Symmetric encryption for confidentiality + authenticity
HKDF-SHA-256	Derives AES + HMAC keys from shared secret
HMAC-SHA-256	Verifies package integrity against tampering
