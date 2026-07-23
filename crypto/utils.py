"""
crypto/utils.py

Utility functions for packing and unpacking encrypted
report files.

Encrypted File Format

----------------------------------------------------
Magic Header

Version

Algorithm Name Length

Algorithm Name

KEM Ciphertext Length

Nonce Length

Authentication Tag Length

KEM Ciphertext

Nonce

Authentication Tag

AES Ciphertext
----------------------------------------------------
"""

import struct

from config import (
    MAGIC_HEADER,
    FILE_VERSION,
    TEXT_ENCODING,
    KEM_ALGORITHM,
)


def pack_encrypted_file(
    algorithm: str,
    kem_ciphertext: bytes,
    nonce: bytes,
    tag: bytes,
    aes_ciphertext: bytes,
) -> bytes:
    """
    Pack all encryption components into a single
    binary blob.

    Parameters
    ----------
    algorithm : str
        KEM algorithm used.

    kem_ciphertext : bytes
        ML-KEM encapsulated ciphertext.

    nonce : bytes
        AES-GCM nonce.

    tag : bytes
        AES-GCM authentication tag.

    aes_ciphertext : bytes
        AES-GCM encrypted payload.

    Returns
    -------
    bytes
        Serialized encrypted file.
    """

    header = bytearray()

    header += MAGIC_HEADER

    header += struct.pack(
        ">B",
        FILE_VERSION,
    )

    algorithm_bytes = algorithm.encode(TEXT_ENCODING)

    header += struct.pack(
        ">B",
        len(algorithm_bytes),
    )

    header += algorithm_bytes

    header += struct.pack(
        ">I",
        len(kem_ciphertext),
    )

    header += struct.pack(
        ">I",
        len(nonce),
    )

    header += struct.pack(
        ">I",
        len(tag),
    )

    return (
        bytes(header)
        + kem_ciphertext
        + nonce
        + tag
        + aes_ciphertext
    )


def unpack_encrypted_file(
    data: bytes,
) -> tuple[str, bytes, bytes, bytes, bytes]:
    """
    Unpack an encrypted report.

    Parameters
    ----------
    data : bytes
        Binary encrypted report.

    Returns
    -------
    tuple
        (
            algorithm,
            kem_ciphertext,
            nonce,
            tag,
            aes_ciphertext,
        )
    """

    offset = 0

    magic_length = len(MAGIC_HEADER)

    magic = data[offset:offset + magic_length]
    offset += magic_length

    if magic != MAGIC_HEADER:
        raise ValueError("Invalid encrypted file header.")

    version = struct.unpack(
        ">B",
        data[offset:offset + 1],
    )[0]

    offset += 1

    if version != FILE_VERSION:
        raise ValueError(
            f"Unsupported file version: {version}"
        )

    algorithm_length = struct.unpack(
        ">B",
        data[offset:offset + 1],
    )[0]

    offset += 1

    algorithm = data[
        offset:offset + algorithm_length
    ].decode(TEXT_ENCODING)

    offset += algorithm_length

    if algorithm != KEM_ALGORITHM:
        raise ValueError(
            f"Unsupported KEM algorithm: {algorithm}"
        )

    kem_len = struct.unpack(
        ">I",
        data[offset:offset + 4],
    )[0]

    offset += 4

    nonce_len = struct.unpack(
        ">I",
        data[offset:offset + 4],
    )[0]

    offset += 4

    tag_len = struct.unpack(
        ">I",
        data[offset:offset + 4],
    )[0]

    offset += 4

    if len(data) < offset + kem_len:
        raise ValueError(
            "Corrupted encrypted file (KEM ciphertext)."
        )

    kem_ciphertext = data[
        offset:offset + kem_len
    ]

    offset += kem_len

    if len(data) < offset + nonce_len:
        raise ValueError(
            "Corrupted encrypted file (nonce)."
        )

    nonce = data[
        offset:offset + nonce_len
    ]

    offset += nonce_len

    if len(data) < offset + tag_len:
        raise ValueError(
            "Corrupted encrypted file (authentication tag)."
        )

    tag = data[
        offset:offset + tag_len
    ]

    offset += tag_len

    aes_ciphertext = data[offset:]

    return (
        algorithm,
        kem_ciphertext,
        nonce,
        tag,
        aes_ciphertext,
    )
