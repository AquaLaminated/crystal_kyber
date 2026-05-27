#!/bin/bash
set -e

echo "Crystal Kyber Linux Installer"
echo "================================"

# 1Python virtual environment
echo "Creating Python venv..."
python3 -m venv oqs_env
source oqs_env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt || pip install cryptography pyperclip tk liboqs-python

# 2Build liboqs (if missing)
echo "Checking liboqs..."
if [ ! -f /usr/local/lib/liboqs.a ]; then
  sudo rm -rf /tmp/liboqs
  git clone https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs
  cd /tmp/liboqs
  mkdir build && cd build
  cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local ..
  ninja
  sudo ninja install
  sudo ldconfig
  cd ~
  rm -rf /tmp/liboqs
else
  echo "liboqs already installed."
fi

# 3Build oqs-provider
echo "Checking oqs-provider..."
if [ ! -f /usr/lib/x86_64-linux-gnu/ossl-modules/oqsprovider.so ]; then
  sudo rm -rf /tmp/oqs-provider
  git clone https://github.com/open-quantum-safe/oqs-provider.git /tmp/oqs-provider
  cd /tmp/oqs-provider
  mkdir build && cd build
  cmake -GNinja ..
  ninja
  sudo ninja install
  sudo ldconfig
  cd ~
  rm -rf /tmp/oqs-provider
else
  echo "oqsprovider.so already installed."
fi

# 4Configure venv environment
echo " Setting up OpenSSL/OQS environment..."
{
  echo 'export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules'
  echo 'export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH'
  echo 'export OPENSSL_CONF=$VIRTUAL_ENV/openssl.cnf'
} >> oqs_env/bin/activate

# 5Write OpenSSL config
cat > oqs_env/openssl.cnf <<'EOF'
# OpenSSL configuration file for OQS provider
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
default = default_sect
oqsprovider = oqs_sect

[default_sect]
activate = 1

[oqs_sect]
activate = 1
module = /usr/lib/x86_64-linux-gnu/ossl-modules/oqsprovider.so

[algorithm_sect]
fips_mode = no
EOF

# 6Verify installation
echo "Verifying setup..."
source oqs_env/bin/activate
openssl list -providers | grep oqsprovider || echo " Warning: OQS provider not detected"
openssl list -kem-algorithms -provider oqsprovider -provider default | grep mlkem || echo " ML-KEM not found"

# 7Done
echo ""
echo "Crystal Kyber installed successfully!"
echo "To run:"
echo "  cd $(pwd)"
echo "  source oqs_env/bin/activate && ./launch_kyber.sh"
