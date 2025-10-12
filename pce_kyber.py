# Backend detection: OpenSSL vs liboqs
try:
    import oqs
    PQ_BACKEND = "liboqs"
except ImportError:
    oqs = None
    PQ_BACKEND = "openssl"
