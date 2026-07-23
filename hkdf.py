"""
crypto/hkdf.py

Derives AES keys from the ML-KEM shared secret
using HKDF-SHA256.
"""

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from config import (AES_KEY_SIZE, HKDF_INFO)

def derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Derive a 256-bit AES key from the shared secret.

    Parameters
    ----------
    shared_secret : bytes
        Shared secret obtained from ML-KEM.

    Returns
    -------
    bytes
        32-byte AES-256 key.
    """

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        # ML-KEM produces high-entropy shared secret, so additional salt not required
        salt=None,  
        info=HKDF_INFO,
    )

    aes_key = hkdf.derive(shared_secret)

    return aes_key


if __name__ == "__main__":

    test_secret = b"A" * 32

    key = derive_aes_key(test_secret)

    print("AES Key Length:", len(key))

    print("derived key", key.hex())