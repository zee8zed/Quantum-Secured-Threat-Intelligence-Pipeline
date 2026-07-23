"""
crypto/encrypt.py

Hybrid Encryption Module

Uses:
    ML-KEM (Kyber) for key encapsulation
    HKDF-SHA256 for key derivation
    AES-256-GCM for file encryption
"""

import os
import oqs

from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import (
    PUBLIC_KEY_FILE,
    KEM_ALGORITHM,
    NONCE_SIZE,
    TAG_SIZE
)

from .hkdf import derive_aes_key
from .utils import pack_encrypted_file


# Private Helper Functions
def _load_public_key() -> bytes:
    """
    Load the recipient's ML-KEM public key.
    """
    return PUBLIC_KEY_FILE.read_bytes()


def _encapsulate_key(public_key: bytes) -> tuple[bytes, bytes]:
    """
    Perform ML-KEM encapsulation.

    Returns
    -------
    tuple
        (
            kem_ciphertext,
            shared_secret
        )
    """

    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:

        kem_ciphertext, shared_secret = kem.encap_secret(public_key)

    return kem_ciphertext, shared_secret


def _encrypt_aes(
    plaintext: bytes,
    aes_key: bytes,
) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext using AES-256-GCM.

    Returns
    -------
    tuple
        (
            nonce,
            tag,
            ciphertext
        )
    """

    nonce = os.urandom(NONCE_SIZE)

    aesgcm = AESGCM(aes_key)

    encrypted = aesgcm.encrypt(
        nonce,
        plaintext,
        None
    )

    ciphertext = encrypted[:-TAG_SIZE]

    tag = encrypted[-TAG_SIZE:]

    return nonce, tag, ciphertext


# Public Function
def encrypt_file(
    input_file: Path,
    output_file: Path,
) -> None:
    """
    Encrypt a JSON report.

    Parameters
    ----------
    input_file : Path
        Path to the plaintext JSON report.

    output_file : Path
        Destination encrypted report.
    """

    try:
        print("Loading report...")

        plaintext = input_file.read_bytes()

        print("Loading public key...")

        public_key = _load_public_key()

        print("Performing ML-KEM encapsulation...")

        kem_ciphertext, shared_secret = _encapsulate_key(
            public_key
        )

        print("Deriving AES key...")

        aes_key = derive_aes_key(
            shared_secret
        )

        print("Encrypting with AES-256-GCM...")

        nonce, tag, ciphertext = _encrypt_aes(
            plaintext,
            aes_key
        )

        print("Packaging encrypted file...")

        encrypted_blob = pack_encrypted_file(
            KEM_ALGORITHM,
            kem_ciphertext,
            nonce,
            tag,
            ciphertext,
        )

        output_file.write_bytes(encrypted_blob)

        print()

        print("Encryption Successful")

        print(f"Encrypted report saved to: {output_file}")
    
    except Exception as e:
        raise RuntimeError("Failed to encrypt") from e


# Testing
if __name__ == "__main__":

    encrypt_file(
        Path("report.json"),
        Path("report.enc")
    )