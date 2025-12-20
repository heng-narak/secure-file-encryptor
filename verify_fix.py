#!/usr/bin/env python3
"""
Verify the header fix.
"""
import os
import sys

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.sfe.header import SimpleFileHeader

print("=== Verifying SimpleFileHeader Fix ===")

# Test the header size
print(f"1. SimpleFileHeader.HEADER_SIZE = {SimpleFileHeader.HEADER_SIZE}")
expected = 8 + 16 + 12 + 16 + 244
print(f"   Expected: 8 + 16 + 12 + 16 + 244 = {expected}")
print(f"   Match: {SimpleFileHeader.HEADER_SIZE == expected}")

# Test creating and parsing
import os
salt = os.urandom(16)
nonce = os.urandom(12)
tag = os.urandom(16)

header = SimpleFileHeader.create_new(salt, nonce, tag, "test.txt")
print(f"\n2. Created header: {header}")

header_bytes = header.to_bytes()
print(f"   Header bytes length: {len(header_bytes)}")
print(f"   Matches HEADER_SIZE: {len(header_bytes) == SimpleFileHeader.HEADER_SIZE}")

# Parse it back
parsed, size = SimpleFileHeader.from_bytes(header_bytes)
print(f"\n3. Parsed header: {parsed}")
print(f"   Parsed size: {size}")

# Verify
print(f"\n4. Verification:")
print(f"   Salt matches: {header.salt == parsed.salt}")
print(f"   Nonce matches: {header.nonce == parsed.nonce}")
print(f"   Tag matches: {header.tag == parsed.tag}")
print(f"   Filename matches: {header.filename == parsed.filename}")

if (header.salt == parsed.salt and 
    header.nonce == parsed.nonce and 
    header.tag == parsed.tag and 
    header.filename == parsed.filename):
    print("\n✓ All tests passed!")
else:
    print("\n✗ Tests failed!")


