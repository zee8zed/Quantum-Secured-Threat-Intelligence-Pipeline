"""
Central configuration file
"""

from pathlib import Path

# Base Directories
BASE_DIR = Path(__file__).resolve().parent

KEY_DIR = BASE_DIR / "keys"
OUTPUT_DIR = BASE_DIR / "output"
DATA_DIR = BASE_DIR / "data"

# Key Files
PUBLIC_KEY_FILE = KEY_DIR / "public.key"
PRIVATE_KEY_FILE = KEY_DIR / "private.key"

ENCRYPTED_REPORT = OUTPUT_DIR / "report.enc"
PLAINTEXT_REPORT = OUTPUT_DIR / "report.json"
DECRYPTED_REPORT = OUTPUT_DIR / "report_recovered.json"

# Kyber / ML-KEM
KEM_ALGORITHM = "ML-KEM-768"

# File Format
FILE_VERSION = 1
MAGIC_HEADER = b"THREATPQ"
TEXT_ENCODING = "utf-8"

# HKDF
HKDF_INFO = b"Threat Intelligence AES Key"

# AES-GCM
AES_KEY_SIZE = 32      # 256 bits
NONCE_SIZE = 12        # NIST standard
TAG_SIZE = 16          # 128-bit authentication tag
