#!/usr/bin/env python3
"""
Debug the encrypted file structure.
"""
import os

encrypted_file = "test_encrypt.txt.enc"

if not os.path.exists(encrypted_file):
    print(f"File not found: {encrypted_file}")
    exit(1)

# Read the file
with open(encrypted_file, 'rb') as f:
    data = f.read()

print(f"File size: {len(data)} bytes")
print(f"First 100 bytes (hex): {data[:100].hex()}")
print(f"First 100 bytes (ASCII): {data[:100]}")

# Try to parse as SimpleFileHeader (56 bytes)
print("\n=== Trying to parse as SimpleFileHeader (56 bytes) ===")
if len(data) >= 56:
    header_part = data[:56]
    print(f"First 56 bytes (magic): {header_part[:8]}")
    print(f"Magic as string: {header_part[:8].decode('ascii', errors='ignore')}")
    
    # Check if it starts with SFE_ENC
    if header_part.startswith(b'SFE_ENC'):
        print("✓ Magic bytes match SimpleFileHeader format")
    else:
        print("✗ Not SimpleFileHeader format")
else:
    print("✗ File too short for SimpleFileHeader")

# Try to parse as FileHeader (variable length)
print("\n=== Looking for variable length header ===")
# Check for SFEV1.0 magic
magic_target = b"SFEV1.0\0"
if data[:8] == magic_target:
    print("✓ Found FileHeader magic bytes (SFEV1.0)")
    
    # Try to parse manually
    version = data[8]
    salt_len = data[9]
    print(f"Version: {version}")
    print(f"Salt length byte: {salt_len}")
    
    if salt_len == 16:
        print("✓ Salt length is 16 (correct)")
    else:
        print(f"✗ Unexpected salt length: {salt_len}")
else:
    print("✗ Not FileHeader format either")

print("\n=== File Structure Analysis ===")
print(f"Total size: {len(data)} bytes")

# Original file was 8 bytes, encrypted is 304 bytes
# Overhead = 304 - 8 = 296 bytes
# If header is 56 bytes, then ciphertext should be 304 - 56 = 248 bytes
# But GCM adds 16 bytes tag, so actual ciphertext is 248 - 16 = 232 bytes
# This seems wrong...

# Let's check what SimpleFileHeader should produce
print("\n=== What SimpleFileHeader should produce ===")
print("SimpleFileHeader.HEADER_SIZE = 56 bytes")
print("Expected structure:")
print("  - Magic: 8 bytes (SFE_ENC + null)")
print("  - Salt: 16 bytes")
print("  - Nonce: 12 bytes")
print("  - Tag: 16 bytes")
print("  - Filename: 244 bytes (padded)")
print("Total: 8 + 16 + 12 + 16 + 244 = 296 bytes")

print("\nWait! 56 + 244 = 300, not 296...")
print("Actually: 8 + 16 + 12 + 16 = 52, plus 244 = 296")
print("So HEADER_SIZE should be 296, not 56!")

# That's the bug! HEADER_SIZE is wrong!