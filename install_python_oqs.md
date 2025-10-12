# Python OQS Installation Guide

## 🐍 Installing Python OQS Bindings (ChatGPT Recommended)

The Python OQS bindings provide direct access to ML-KEM without OpenSSL encoder issues.

### Option 1: Install pip and Python OQS

```bash
# Install pip
sudo apt install python3-pip

# Install Python OQS
pip3 install oqs
```

### Option 2: Use system package (if available)

```bash
# Try system package first
sudo apt install python3-oqs
```

### Option 3: Use virtual environment (recommended)

```bash
# Create virtual environment
python3 -m venv oqs_env

# Activate virtual environment
source oqs_env/bin/activate

# Install Python OQS
pip install oqs
```

### Option 4: Install without sudo (user installation)

```bash
# Install pip for user
python3 -m ensurepip --user

# Install Python OQS for user
python3 -m pip install --user oqs
```

## 🚀 After Installation

1. **Test the installation:**
   ```bash
   python3 python_oqs_keygen.py
   ```

2. **Use in Kyber application:**
   - Click "🔑 Generate ML-KEM Keys" button
   - The Python OQS generator will open
   - Follow the instructions

## ✅ Benefits of Python OQS

- **Bypasses OpenSSL encoder issues**
- **Direct liboqs bindings**
- **Clean ML-KEM key generation**
- **No OpenSSL dependencies**
- **Recommended by ChatGPT**

## 🔧 Troubleshooting

If you get permission errors:
- Use virtual environment (Option 3)
- Use user installation (Option 4)
- Check Python version compatibility

## 📖 Usage

```bash
# Generate ML-KEM-768 keys
python3 python_oqs_keygen.py --algorithm ML-KEM-768

# Generate ML-KEM-1024 keys (higher security)
python3 python_oqs_keygen.py --algorithm ML-KEM-1024

# Verbose output
python3 python_oqs_keygen.py --verbose
```
