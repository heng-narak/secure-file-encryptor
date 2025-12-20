#!/usr/bin/env python3
"""
Quick test of encryption functionality.
"""
import os
from src.sfe.utils import generate_salt, derive_key
from src.sfe.header import FileHeader


def test_basic_crypto():
    print("=== Testing Basic Cryptography ===")
    
    # 1. Generate salt
    salt = generate_salt()
    print(f"1. Generated salt: {salt.hex()[:32]}...")
    
    # 2. Derive key
    password = "MySecretPassword123!"
    key = derive_key(password, salt)
    print(f"2. Derived key: {key.hex()[:32]}...")
    
    # 3. Create header
    nonce = os.urandom(12)  # 12 bytes for GCM
    tag = b"D" * 16  # Simulated tag (real one comes from encryption)
    header = FileHeader.create_new(salt, nonce, tag, "test.txt")
    
    # 4. Convert to bytes
    header_bytes = header.to_bytes()
    print(f"3. Header size: {len(header_bytes)} bytes")
    
    # 5. Parse back
    parsed_header, _ = FileHeader.from_bytes(header_bytes)
    print(f"4. Parsed filename: {parsed_header.filename}")
    
    print("\n✓ Basic cryptography test passed!")


if __name__ == "__main__":
    test_basic_crypto()