#!/usr/bin/env python3
"""
ML-KEM Key Generator using liboqs (Python bindings).
FIPS-203 compliant and independent of OpenSSL version.
"""

import base64
import oqs
from pathlib import Path

print("🔐 liboqs ML-KEM Key Generator (FIPS/PQC Compliant)")
print("===================================================")

# Initialize KEM
kem = oqs.KeyEncapsulation("ML-KEM-768")

# Generate keypair
public_key = kem.generate_keypair()
private_key = kem.export_secret_key()

# Encode as PEM-style
pub_pem = (
    b"-----BEGIN ML-KEM PUBLIC KEY-----\n"
    + base64.b64encode(public_key)
    + b"\n-----END ML-KEM PUBLIC KEY-----\n"
)
priv_pem = (
    b"-----BEGIN ML-KEM PRIVATE KEY-----\n"
    + base64.b64encode(private_key)
    + b"\n-----END ML-KEM PRIVATE KEY-----\n"
)

# Write to disk
Path("mlkem_public_key.pem").write_bytes(pub_pem)
Path("mlkem_private_key.pem").write_bytes(priv_pem)

print("✅ Generated ML-KEM-768 keypair using liboqs.")
print("   Private key: mlkem_private_key.pem")
print("   Public key:  mlkem_public_key.pem")
print("\n�� Keep your private key secure!")

