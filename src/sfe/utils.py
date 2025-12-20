"""
Utility functions for the Secure File Encryptor.
"""
import os
import hashlib
from typing import Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# Constants
PBKDF2_ITERATIONS = 100_000  # Minimum recommended iterations
SALT_SIZE = 16  # 16 bytes = 128 bits
KEY_SIZE = 32  # 32 bytes = 256 bits for AES-256


def generate_salt() -> bytes:
    """Generate a cryptographically secure random salt."""
    return os.urandom(SALT_SIZE)


def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """
    Derive a cryptographic key from a password using PBKDF2.
    
    Args:
        password: The user's password as a string
        salt: Random salt bytes
        iterations: Number of PBKDF2 iterations
        
    Returns:
        A 32-byte (256-bit) key suitable for AES-256
    """
    # Convert password to bytes
    password_bytes = password.encode('utf-8')
    
    # Create PBKDF2 key derivation function
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    
    # Derive the key
    key = kdf.derive(password_bytes)
    return key


def calculate_sha256(data: bytes) -> str:
    """Calculate SHA-256 hash of data and return as hex string."""
    sha256_hash = hashlib.sha256(data)
    return sha256_hash.hexdigest()


if __name__ == "__main__":
    # Test the functions
    test_salt = generate_salt()
    print(f"Test salt (hex): {test_salt.hex()}")
    print(f"Salt length: {len(test_salt)} bytes")
    
    test_key = derive_key("test_password", test_salt)
    print(f"Derived key (hex): {test_key.hex()}")
    print(f"Key length: {len(test_key)} bytes (AES-256 requires 32 bytes)")