#!/bin/bash

# Kyber Application Launch Script
# This script ensures the virtual environment is activated and the application runs correctly

echo "Launching Kyber Application with liboqs integration..."

# Change to the application directory
cd "$(dirname "$0")"

# Activate the virtual environment
echo "Activating virtual environment..."
source oqs_env/bin/activate

# Set up environment variables for OQS provider
export LD_LIBRARY_PATH="/tmp/local_install/usr/local/lib:${LD_LIBRARY_PATH}"
export OPENSSL_MODULES="/tmp/local_install/usr/lib/x86_64-linux-gnu/ossl-modules"
export CRYPTOGRAPHY_OPENSSL_NO_LEGACY="1"

# Verify liboqs is available
echo "Verifying liboqs installation..."
python3 -c "import oqs; print('liboqs is available')" || {
    echo "liboqs not available. Please check the virtual environment."
    exit 1
}

# Launch the application
echo "Starting Kyber application..."
python3 "pce kyber" "$@"
