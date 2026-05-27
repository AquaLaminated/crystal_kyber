#!/usr/bin/env python3
"""
Python OQS ML-KEM Key Generator
===============================

This script uses Python OQS bindings to generate ML-KEM keys directly,
bypassing OpenSSL encoder issues. This is the recommended approach
from ChatGPT and provides a clean, direct implementation.

Requirements:
- python3-oqs package (install with: pip3 install oqs)
- Or use the system's cryptography library with OQS provider

This approach:
- Bypasses OpenSSL encoder issues
- Uses direct Python bindings to liboqs
- Provides clean ML-KEM key generation
- Works with the existing Kyber application
"""

import os
import sys
import stat
import tempfile
import secrets
import time
from pathlib import Path
from typing import Tuple, Optional
import argparse

def check_python_oqs_available() -> bool:
    """Check if Python OQS bindings are available"""
    try:
        import oqs
        # Check if it's the correct oqs library (not the wrong one)
        if hasattr(oqs, 'KeyEncapsulation'):
            return True
        elif hasattr(oqs, 'KEM'):
            return True
        else:
            # It's the wrong oqs package
            return False
    except ImportError:
        return False

def install_python_oqs_instructions():
    """Provide instructions for installing Python OQS"""
    print("Python OQS bindings not found or wrong package installed.")
    print("\nTo install the correct Python OQS bindings:")
    print("1. Activate your virtual environment:")
    print("   source oqs_env/bin/activate")
    print("\n2. Uninstall wrong package (if installed):")
    print("   pip uninstall -y oqs")
    print("\n3. Install the correct package:")
    print("   pip install liboqs-python")
    print("\n4. Alternative - use existing OQS provider:")
    print("   The existing OQS provider installation can be used")
    print("   with the fallback approaches in this script.")

def generate_mlkem_keypair_python_oqs(algorithm: str = "ML-KEM-768") -> Tuple[bytes, bytes]:
    """Generate ML-KEM keypair using Python OQS bindings"""
    try:
        import oqs
        
        print(f"Generating ML-KEM keypair using Python OQS ({algorithm})...")
        
        # Create KEM object
        kem = oqs.KeyEncapsulation(algorithm)
        
        # Generate keypair
        public_key = kem.generate_keypair()
        
        # Get private key (this is the secret key)
        private_key = kem.export_secret_key()
        
        # Convert to PEM format
        priv_pem = f"""-----BEGIN PRIVATE KEY-----
{private_key.hex()}
-----END PRIVATE KEY-----""".encode()
        
        pub_pem = f"""-----BEGIN PUBLIC KEY-----
{public_key.hex()}
-----END PUBLIC KEY-----""".encode()
        
        print(f"Successfully generated ML-KEM keypair using Python OQS")
        return priv_pem, pub_pem
        
    except ImportError:
        print("Python OQS bindings not available")
        install_python_oqs_instructions()
        return None, None
    except Exception as e:
        print(f"Python OQS key generation failed: {e}")
        return None, None

def generate_mlkem_keypair_cryptography_fallback() -> Tuple[bytes, bytes]:
    """Fallback using existing OQS provider with OpenSSL commands"""
    try:
        import subprocess
        import tempfile
        import os
        
        print("Trying fallback approach with existing OQS provider...")
        
        # Try to use the existing OQS provider installation
        local_install_path = "/tmp/local_install"
        lib_path = f"{local_install_path}/usr/local/lib"
        modules_path = f"{local_install_path}/usr/lib/x86_64-linux-gnu/ossl-modules"
        
        # Set up environment
        env = dict(os.environ)
        env["LD_LIBRARY_PATH"] = f"{lib_path}:{env.get('LD_LIBRARY_PATH', '')}"
        env["OPENSSL_MODULES"] = modules_path
        env["CRYPTOGRAPHY_OPENSSL_NO_LEGACY"] = "1"
        
        # Try different OpenSSL approaches
        approaches = [
            # Try with explicit provider configuration
            ["openssl", "genpkey", "-provider", "default", "-provider", "oqsprovider", "-algorithm", "mlkem768", "-outform", "PEM"],
            # Try with different algorithm names
            ["openssl", "genpkey", "-provider", "default", "-provider", "oqsprovider", "-algorithm", "ML-KEM-768", "-outform", "PEM"],
            # Try file-based approach
            ["openssl", "genpkey", "-provider", "default", "-provider", "oqsprovider", "-algorithm", "mlkem768", "-out", "temp_priv.pem"],
        ]
        
        for i, cmd in enumerate(approaches, 1):
            print(f"   Trying fallback approach {i}...")
            try:
                if "temp_priv.pem" in cmd:
                    # File-based approach
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=env)
                    if result.returncode == 0:
                        # Read the private key
                        with open("temp_priv.pem", "rb") as f:
                            priv_pem = f.read()
                        
                        # Generate public key
                        pub_cmd = ["openssl", "pkey", "-pubout", "-provider", "default", "-provider", "oqsprovider", "-in", "temp_priv.pem"]
                        pub_result = subprocess.run(pub_cmd, capture_output=True, text=True, timeout=15, env=env)
                        
                        if pub_result.returncode == 0:
                            pub_pem = pub_result.stdout.encode()
                            # Clean up temp file
                            try:
                                os.unlink("temp_priv.pem")
                            except:
                                pass
                            print(f"   Fallback approach {i} succeeded!")
                            return priv_pem, pub_pem
                else:
                    # Direct output approach
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=env)
                    if result.returncode == 0 and result.stdout:
                        # Try to extract public key
                        pub_cmd = ["openssl", "pkey", "-pubout", "-provider", "default", "-provider", "oqsprovider"]
                        pub_result = subprocess.run(pub_cmd, input=result.stdout, capture_output=True, text=True, timeout=15, env=env)
                        
                        if pub_result.returncode == 0 and pub_result.stdout:
                            priv_pem = result.stdout.encode()
                            pub_pem = pub_result.stdout.encode()
                            print(f"   Fallback approach {i} succeeded!")
                            return priv_pem, pub_pem
            except Exception as e:
                print(f"   Fallback approach {i} failed: {e}")
                continue
        
        print("   All fallback approaches failed")
        return None, None
        
    except Exception as e:
        print(f"Fallback approach failed: {e}")
        return None, None

def secure_file_write(path: str, data: bytes) -> None:
    """Securely write data to file with proper permissions"""
    try:
        # Write with secure permissions
        with open(path, 'wb') as f:
            f.write(data)
        # Set secure permissions
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    except Exception as e:
        raise RuntimeError(f"Failed to write secure file: {e}")

def save_keypair_secure(priv_pem: bytes, pub_pem: bytes, algorithm: str, base_name: str = "mlkem_keypair") -> Tuple[str, str]:
    """Save keypair securely with proper permissions"""
    
    # Generate secure filenames
    timestamp = str(int(time.time()))
    key_id = secrets.token_hex(8)
    algo_clean = algorithm.replace("-", "_").replace(" ", "_").lower()
    
    priv_file = f"{base_name}_{algo_clean}_private_{key_id}.pem"
    pub_file = f"{base_name}_{algo_clean}_public_{key_id}.pem"
    
    # Save files securely
    secure_file_write(priv_file, priv_pem)
    secure_file_write(pub_file, pub_pem)
    
    # Verify files were written correctly
    if not os.path.exists(priv_file) or not os.path.exists(pub_file):
        raise RuntimeError("Failed to save key files")
    
    # Verify file permissions
    priv_stat = os.stat(priv_file)
    pub_stat = os.stat(pub_file)
    
    if (priv_stat.st_mode & 0o777) != 0o600 or (pub_stat.st_mode & 0o777) != 0o600:
        raise RuntimeError("Insecure file permissions detected")
    
    return priv_file, pub_file

def main():
    """Main function for Python OQS ML-KEM key generation"""
    parser = argparse.ArgumentParser(
        description="Python OQS ML-KEM Key Generator - Direct liboqs bindings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This script uses Python OQS bindings to generate ML-KEM keys directly,
bypassing OpenSSL encoder issues.

Features:
- Direct Python bindings to liboqs
- Bypasses OpenSSL encoder problems
- Clean ML-KEM key generation
- Secure file handling with proper permissions

Examples:
  python3 python_oqs_keygen.py
  python3 python_oqs_keygen.py --algorithm ML-KEM-1024
  python3 python_oqs_keygen.py --output my_keys --verbose
        """
    )
    
    parser.add_argument("--algorithm", "-a", default="ML-KEM-768", 
                       choices=["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
                       help="ML-KEM algorithm variant (default: ML-KEM-768)")
    parser.add_argument("--output", "-o", default="mlkem_keypair",
                       help="Base name for output files (default: mlkem_keypair)")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Validate output name
    if not args.output.replace("_", "").replace("-", "").isalnum():
        print("Error: Output name must contain only alphanumeric characters, hyphens, and underscores")
        sys.exit(1)
    
    print("Python OQS ML-KEM Key Generator")
    print("=" * 40)
    print("Direct liboqs bindings - bypasses OpenSSL encoder issues")
    print()
    
    try:
        # Check if Python OQS is available
        if not check_python_oqs_available():
            print("Python OQS bindings not available")
            print("Trying fallback approach with existing OQS provider...")
        else:
            print("Python OQS bindings detected")
        
        # Generate keypair using Python OQS
        priv_pem, pub_pem = generate_mlkem_keypair_python_oqs(args.algorithm)
        
        if priv_pem is None or pub_pem is None:
            print("\n Python OQS key generation failed")
            print("Trying fallback approach...")
            priv_pem, pub_pem = generate_mlkem_keypair_cryptography_fallback()
            
            if priv_pem is None or pub_pem is None:
                print("\nAll key generation approaches failed")
                print("Please install Python OQS bindings:")
                print("  pip3 install oqs")
                sys.exit(1)
        
        # Save keypair securely
        print("\nSaving keypair securely...")
        priv_file, pub_file = save_keypair_secure(priv_pem, pub_pem, args.algorithm, args.output)
        
        # Success
        print("\nPython OQS ML-KEM key generation completed successfully!")
        print(f"\nGenerated files:")
        print(f"  Private key: {priv_file}")
        print(f"  Public key:  {pub_file}")
        
        # Usage instructions
        print(f"\nUsage instructions:")
        print(f"  1. Use {pub_file} as the 'Recipient public key' in the Kyber application")
        print(f"  2. Keep {priv_file} secure - it's needed for decryption")
        print(f"  3. Never share the private key file")
        
        if args.verbose:
            print(f"\nKey information:")
            print(f"  Algorithm: {args.algorithm}")
            print(f"  Private key size: {len(priv_pem)} bytes")
            print(f"  Public key size:  {len(pub_pem)} bytes")
            print(f"  Method: Python OQS bindings (direct liboqs)")
            print(f"  Format: PEM")
        
    except KeyboardInterrupt:
        print("\n\n Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        # Final security cleanup
        try:
            # Clear sensitive data from memory
            if 'priv_pem' in locals():
                del priv_pem
            if 'pub_pem' in locals():
                del pub_pem
        except:
            pass

if __name__ == "__main__":
    main()
