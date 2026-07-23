"""
crypto/crypto.py

Facade for the cryptography subsystem.

This is the ONLY module that should be imported
outside the crypto package.
"""

from pathlib import Path

from config import (
    PUBLIC_KEY_FILE,
    PRIVATE_KEY_FILE,
    PLAINTEXT_REPORT,
    ENCRYPTED_REPORT,
    DECRYPTED_REPORT,
)

from .keygen import generate_keypair
from .encrypt import encrypt_file
from .decrypt import decrypt_file


def initialize() -> None:
    """
    Initialize the cryptography subsystem.

    Generates a new ML-KEM key pair only if one
    does not already exist.
    """

    if (
        PUBLIC_KEY_FILE.exists()
        and PRIVATE_KEY_FILE.exists()
    ):
        return

    print("No key pair found.")
    print("Generating ML-KEM key pair...")

    generate_keypair()

    print("Initialization complete.\n")


def encrypt(
    input_file: Path = PLAINTEXT_REPORT,
    output_file: Path = ENCRYPTED_REPORT,
) -> Path:
    """
    Encrypt a JSON report.

    Parameters
    ----------
    input_file : Path
        Path to the plaintext report.

    output_file : Path
        Destination encrypted report.

    Returns
    -------
    Path
        Path to the encrypted report.
    """

    initialize()

    if not input_file.exists():
        raise FileNotFoundError(
            f"Input file not found: {input_file}"
        )

    encrypt_file(
        input_file,
        output_file,
    )

    return output_file


def decrypt(
    input_file: Path = ENCRYPTED_REPORT,
    output_file: Path = DECRYPTED_REPORT,
) -> Path:
    """
    Decrypt an encrypted report.

    Parameters
    ----------
    input_file : Path
        Path to the encrypted report.

    output_file : Path
        Destination decrypted report.

    Returns
    -------
    Path
        Path to the decrypted report.
    """

    initialize()

    if not input_file.exists():
        raise FileNotFoundError(
            f"Encrypted file not found: {input_file}"
        )

    decrypt_file(
        input_file,
        output_file,
    )

    return output_file