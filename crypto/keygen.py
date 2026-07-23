"""
crypto/keygen.py

Generates an ML-KEM-768 (Kyber) public/private key pair
using the Open Quantum Safe (liboqs) library.

Outputs:
    keys/public.key
    keys/private.key
"""

import oqs

from config import (
    KEY_DIR,
    PUBLIC_KEY_FILE,
    PRIVATE_KEY_FILE,
    KEM_ALGORITHM
)


def generate_keypair(overwrite: bool = False) -> bool:
    """
    Generate a Kyber (ML-KEM) key pair.

    Parameters
    ----------
    overwrite : bool
        If False, existing keys are preserved.

    Returns
    -------
    bool
        True if keys were generated.
    """

    KEY_DIR.mkdir(parents=True, exist_ok=True)

    if (
        PUBLIC_KEY_FILE.exists()
        and PRIVATE_KEY_FILE.exists()
        and not overwrite
    ):
        print("Keys already exist.")
        print("Skipping generation.")
        return False

    print(f"Generating {KEM_ALGORITHM} key pair...")

    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:

        public_key = kem.generate_keypair()

        secret_key = kem.export_secret_key()

    try:
        PUBLIC_KEY_FILE.write_bytes(public_key)
        PRIVATE_KEY_FILE.write_bytes(secret_key)

    except OSError as e:
        raise RuntimeError("Failed to save generated key pair.") from e

    print("Public key saved to:")
    print(PUBLIC_KEY_FILE)

    print()

    print("Private key saved to:")
    print(PRIVATE_KEY_FILE)

    print()

    print(f"Public Key Size : {len(public_key)} bytes")
    print(f"Private Key Size: {len(secret_key)} bytes")

    return True


if __name__ == "__main__":
    generate_keypair(overwrite=False)
