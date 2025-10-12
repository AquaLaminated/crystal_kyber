#!/bin/bash
# Python OQS Installation Script
# Run this script when you have sudo access to install Python OQS bindings

echo "🐍 Python OQS Installation Script"
echo "=================================="
echo "This will install Python OQS bindings for ML-KEM key generation"
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "❌ Please don't run this script as root"
    echo "Run it as a regular user and enter your password when prompted"
    exit 1
fi

echo "📦 Installing required packages..."

# Install python3-pip
echo "Installing python3-pip..."
sudo apt update
sudo apt install -y python3-pip

# Install python3-venv (needed for virtual environments)
echo "Installing python3-venv..."
sudo apt install -y python3-venv

echo ""
echo "🔧 Setting up Python OQS..."

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv oqs_env

# Activate virtual environment
echo "Activating virtual environment..."
source oqs_env/bin/activate

# Install Python OQS
echo "Installing Python OQS bindings..."
pip install oqs

echo ""
echo "✅ Python OQS installation completed!"
echo ""
echo "🚀 To use Python OQS:"
echo "1. Activate the virtual environment:"
echo "   source oqs_env/bin/activate"
echo ""
echo "2. Run the Python OQS key generator:"
echo "   python3 python_oqs_keygen.py"
echo ""
echo "3. Or use it in the Kyber application:"
echo "   - Click '🔑 Generate ML-KEM Keys' button"
echo "   - The Python OQS generator will work now"
echo ""
echo "🔧 To deactivate the virtual environment later:"
echo "   deactivate"
