#!/bin/bash
set -e

echo "🔐 PQ Packager (Kyber) Linux Installer"
echo "======================================"

# 1️⃣ Dependencies
echo "📦 Installing system packages..."
sudo apt update -y
sudo apt install -y python3 python3-venv python3-tk python3-pip git openssl

# 2️⃣ Virtual environment
echo "🐍 Setting up Python venv..."
python3 -m venv oqs_env
source oqs_env/bin/activate

# 3️⃣ Python deps
echo "📥 Installing Python packages..."
pip install --upgrade pip
pip install -r requirements.txt || {
  echo "❌ Failed to install from requirements.txt, installing manually..."
  pip install cryptography pyperclip tk
}

# 4️⃣ Try liboqs build (if missing)
echo "🔧 Checking liboqs..."
python3 - <<'PY'
try:
    import oqs
    print("✅ liboqs already installed.")
except ImportError:
    import subprocess
    print("🔧 Installing liboqs-python from source...")
    subprocess.run(["git", "clone", "https://github.com/open-quantum-safe/liboqs-python.git"], check=True)
    subprocess.run(["pip", "install", "./liboqs-python"], check=True)
    print("✅ liboqs-python installed successfully.")
PY

# 5️⃣ Run test
echo "🧪 Verifying liboqs functionality..."
python3 - <<'PY'
import oqs
print("✅ Available KEMs:", oqs.get_enabled_kem_mechanisms())
print("✅ Available SIGs:", oqs.get_enabled_sig_mechanisms())
PY

echo "✅ Installation complete!"
echo "Run the app using: ./run_gui.sh"
