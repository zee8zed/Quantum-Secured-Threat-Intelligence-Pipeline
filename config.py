"""
Central configuration file
"""

from pathlib import Path

# Base Directories
BASE_DIR = Path(__file__).resolve().parent

KEY_DIR = BASE_DIR / "keys"
OUTPUT_DIR = BASE_DIR / "outputs"
DATA_DIR = BASE_DIR / "data"

# Key Files
PUBLIC_KEY_FILE = KEY_DIR / "public.key"
PRIVATE_KEY_FILE = KEY_DIR / "private.key"

ENCRYPTED_REPORT = OUTPUT_DIR / "encrypted" / "report.enc"
PLAINTEXT_REPORT = OUTPUT_DIR / "reports" / "report.json"
DECRYPTED_REPORT = OUTPUT_DIR / "reports" / "report_recovered.json"
LOG_DIR = OUTPUT_DIR / "logs"

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

# ML model artifacts
MODELS_DIR = BASE_DIR / "models"
NER_MODEL_DIR = MODELS_DIR / "ner_model"
FEATURE_PIPELINE_FILE = MODELS_DIR / "feature_pipeline.joblib"
SEVERITY_MODEL_FILE = MODELS_DIR / "severity_classifier.joblib"

# NER
NER_BASE_MODEL = "cisco-ai/SecureBERT2.0-base"
NER_DEFAULT_HUB_MODEL = "cisco-ai/SecureBERT2.0-NER"
NER_DATA_DIR = BASE_DIR / "data" / "external" / "annoctr" / "AnnoCTR" / "ner_json"
