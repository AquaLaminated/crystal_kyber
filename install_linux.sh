#!/bin/bash
set -e

echo "🐧 Installing Crystal Kyber for Linux"
echo "====================================="

# 1️⃣ Create Python virtual environment
echo "📦 Setting up virtual environment..."
python3 -m venv oqs_env
source oqs_env/bin/activate

# 2️⃣ Install dependencies
echo "📥 Installing Python packages..."
pip install --upgrade pip
pip install -r requirements.txt || {
  echo "❌ Failed to install from requirements.txt, installing manually..."
  pip install cryptography pyperclip tk
}

# 3️⃣ Install liboqs if missing
echo "🔧 Checking liboqs..."
python3 - <<'PY'
import subprocess, sys, os, time

def run(cmd):
    print("▶", " ".join(cmd))
    subprocess.run(cmd, check=True)

try:
    import oqs
    print("✅ liboqs already installed and usable.")
except ImportError:
    print("liboqs not found, installing it in", os.path.expanduser("~/_oqs"))
    time.sleep(5)
    run(["git", "clone", "--branch", "main", "https://github.com/open-quantum-safe/liboqs.git"])
    os.chdir("liboqs")
    run(["cmake", "-B", "build", "-DCMAKE_INSTALL_PREFIX=/usr/local"])
    run(["cmake", "--build", "build"])
    run(["sudo", "cmake", "--install", "build"])
    os.chdir("..")
    run(["pip", "install", "liboqs-python"])
    print("✅ liboqs-python installed successfully.")
PY

# 4️⃣ Verify
echo "🧪 Verifying liboqs functionality..."
source oqs_env/bin/activate
python3 -c "import oqs; print('✅ Available KEMs:', oqs.get_enabled_kem_mechanisms())"

# 5️⃣ Launch
echo "🚀 Launching Kyber app..."
python3 "pce kyber"
