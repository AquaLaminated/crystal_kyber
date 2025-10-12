#!/bin/bash

# Set up environment for local OQS provider installation
export LD_LIBRARY_PATH="/tmp/local_install/usr/local/lib:$LD_LIBRARY_PATH"
export OPENSSL_MODULES="/tmp/local_install/usr/lib/x86_64-linux-gnu/ossl-modules"
export OPENSSL_CONF="/tmp/local_install/usr/local/lib/openssl.cnf"
export CRYPTOGRAPHY_OPENSSL_NO_LEGACY="1"

# Run the Kyber application
cd /home/pc/Documents/crystal_kyber
python3 "pce kyber"
