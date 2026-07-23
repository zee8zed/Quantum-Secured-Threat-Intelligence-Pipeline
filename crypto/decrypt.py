"""
crypto/decrypt.py

Hybrid Decryption Module

Uses:
    ML-KEM (Kyber) for key decapsulation
    HKDF-SHA256 for key derivation
    AES-256-GCM for authenticated decryption
"""

import oqs

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathlib import Path

from config import (
    PRIVATE_KEY_FILE,
)

from .hkdf import derive_aes_key
from .utils import unpack_encrypted_file


# Private Helper Functions
def _load_private_key() -> bytes:
    """
    Load the ML-KEM private key.
    """

    return PRIVATE_KEY_FILE.read_bytes()


def _decapsulate_key(
    algorithm: str,
    secret_key: bytes,
    kem_ciphertext: bytes,
) -> bytes:
    """
    Recover the shared secret using ML-KEM.
    """

    with oqs.KeyEncapsulation(algorithm) as kem:

        kem.import_secret_key(secret_key)

        shared_secret = kem.decap_secret(
            kem_ciphertext
        )

    return shared_secret


def _decrypt_aes(
    ciphertext: bytes,
    tag: bytes,
    nonce: bytes,
    aes_key: bytes,
) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext.
    """

    aesgcm = AESGCM(aes_key)

    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext + tag,
        None,
    )

    return plaintext


# Public Function
def decrypt_file(
    input_file: Path,
    output_file: Path,
) -> None:
    """
    Decrypt an encrypted report

    Parameters
    input_file : Path
        Path to the encrypted report

    output_file : Path
        Destination recovered JSON report
    """    

    try:
        print("Loading encrypted report...")

        encrypted_blob = input_file.read_bytes()

        print("Parsing encrypted file...")

        (
            algorithm,
            kem_ciphertext,
            nonce,
            tag,
            ciphertext,
        ) = unpack_encrypted_file(encrypted_blob)

        print("Loading private key...")
        private_key = _load_private_key()

        print("Recovering shared secret...")
        shared_secret = _decapsulate_key(
            algorithm,
            private_key,
            kem_ciphertext,
        )

        print("Deriving AES key...")
        aes_key = derive_aes_key(
            shared_secret
        )

        print("Decrypting report...")
        plaintext = _decrypt_aes(
            ciphertext,
            tag,
            nonce,
            aes_key,
        )

        output_file.write_bytes(plaintext)

        print()
        print("Decryption Successful")
        print(f"Recovered report saved to: {output_file}")
    
    except Exception as e:
        raise RuntimeError("Failed to decrypt") from e


# Testing
if __name__ == "__main__":

    decrypt_file(
        Path("report.enc"),
        Path("report_recovered.json"),
    )
