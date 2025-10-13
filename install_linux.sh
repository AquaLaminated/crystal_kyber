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
import subprocess, sys, os

def run(cmd):
    print("▶", " ".join(cmd))
    subprocess.run(cmd, check=True)

try:
    import oqs
    print("✅ liboqs already installed.")
except ImportError:
    print("🔧 liboqs not found, installing from source...")

    home = os.path.expanduser("~")
    build_dir = os.path.join(home, "_oqs_build")
    os.makedirs(build_dir, exist_ok=True)
    os.chdir(build_dir)

    # Clone the latest liboqs repo
    try:
        run(["git", "clone", "https://github.com/open-quantum-safe/liboqs.git"])
    except subprocess.CalledProcessError:
        print("⚠️ liboqs already exists, skipping clone.")

    os.chdir("liboqs")

    # Checkout main branch (0.14.1 no longer exists)
    run(["git", "checkout", "main"])
    run(["mkdir", "-p", "build"])
    os.chdir("build")

    # Configure and build shared library
    run(["cmake", "-DOQS_BUILD_ONLY_LIB=ON", "-DBUILD_SHARED_LIBS=ON", "-DCMAKE_INSTALL_PREFIX=/usr/local", ".."])
    run(["make", "-j", str(os.cpu_count())])
    run(["sudo", "make", "install"])

    # Export library path
    os.environ["LD_LIBRARY_PATH"] = "/usr/local/lib:" + os.environ.get("LD_LIBRARY_PATH", "")
    print("✅ liboqs built and installed successfully.")

    # Install Python bindings
    os.chdir(build_dir)
    run(["git", "clone", "https://github.com/open-quantum-safe/liboqs-python.git"])
    os.chdir("liboqs-python")
    run([sys.executable, "-m", "pip", "install", "."])
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
