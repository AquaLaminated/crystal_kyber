#!/bin/bash
# Quantum-safe Kyber GUI launcher
# Automatically activates the correct environment and runs the app

cd "$(dirname "$0")" || exit 1

# Activate the correct Python venv
source ./oqs_env/bin/activate

# Run the GUI (adjust name if different)
python3 "pce kyber"
