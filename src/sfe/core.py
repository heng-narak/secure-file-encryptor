"""
Core encryption and decryption logic for the Secure File Encryptor.
"""
import struct
import os
import sys
import getpass
from typing import Optional, Tuple
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from .utils import generate_salt, derive_key, PBKDF2_ITERATIONS
from .header import SimpleFileHeader as FileHeader


def encrypt_file(
    input_path: str, 
    password: str, 
    output_path: Optional[str] = None,
    iterations: int = PBKDF2_ITERATIONS
) -> str:
    """
    Encrypt a file using AES-256-GCM.
    
    Args:
        input_path: Path to the file to encrypt
        password: Encryption password
        output_path: Optional output path (default: input_path + '.enc')
        iterations: PBKDF2 iterations
        
    Returns:
        Path to the encrypted file
        
    Raises:
        FileNotFoundError: If input file doesn't exist
        ValueError: If password is empty
    """
    # Validate inputs
    if not password:
        raise ValueError("Password cannot be empty")
    
    input_path_obj = Path(input_path)
    if not input_path_obj.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    
    # Generate output path if not provided
    if output_path is None:
        output_path = str(input_path_obj) + ".enc"
    
    print(f"[INFO] Encrypting: {input_path}")
    print(f"[INFO] Output: {output_path}")
    
    # Generate random values
    salt = generate_salt()  # 16 bytes
    nonce = os.urandom(12)  # 12 bytes for GCM
    
    # Derive key from password
    print(f"[INFO] Deriving key with {iterations:,} PBKDF2 iterations...")
    key = derive_key(password, salt, iterations)
    
    # Read the input file
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    
    # Initialize AES-GCM cipher
    aesgcm = AESGCM(key)
    
    # Encrypt the data (this also generates the authentication tag)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
       # The last 16 bytes are the authentication tag
    # GCM returns ciphertext + tag concatenated
    tag = ciphertext[-16:]
    ciphertext_only = ciphertext[:-16]
    
    # Create file header
    original_filename = input_path_obj.name
    header = FileHeader.create_new(salt, nonce, tag, original_filename)
    header_bytes = header.to_bytes()
    
    # Write encrypted file (header + ciphertext)
    with open(output_path, 'wb') as f:
        f.write(header_bytes)
        f.write(ciphertext_only)
    
    # Calculate and display some stats
    file_size = input_path_obj.stat().st_size
    encrypted_size = len(header_bytes) + len(ciphertext_only)
    
    print(f"[INFO] Original size: {file_size:,} bytes")
    print(f"[INFO] Encrypted size: {encrypted_size:,} bytes")
    print(f"[INFO] Overhead: {encrypted_size - file_size:,} bytes (header + tag)")
    print(f"[INFO] Encryption successful!")
    print(f"[INFO] Salt: {salt.hex()[:16]}...")
    print(f"[INFO] Nonce: {nonce.hex()[:16]}...")
    print(f"[INFO] Tag: {tag.hex()[:16]}...")
    
    return output_path


def decrypt_file(
    input_path: str, 
    password: str, 
    output_path: Optional[str] = None,
    iterations: int = PBKDF2_ITERATIONS
) -> str:
    """
    Decrypt a file encrypted with encrypt_file().
    
    Args:
        input_path: Path to the encrypted file (.enc)
        password: Decryption password
        output_path: Optional output path
        iterations: PBKDF2 iterations (must match encryption)
        
    Returns:
        Path to the decrypted file
        
    Raises:
        FileNotFoundError: If input file doesn't exist
        ValueError: If password is wrong or file is corrupted
        InvalidTag: If authentication fails (wrong password or tampered file)
    """
    # Validate inputs
    if not password:
        raise ValueError("Password cannot be empty")
    
    input_path_obj = Path(input_path)
    if not input_path_obj.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    
    print(f"[INFO] Decrypting: {input_path}")
    
        # Read the entire encrypted file
    with open(input_path, 'rb') as f:
        file_data = f.read()
    
    # Parse the header
    try:
        header, header_size = FileHeader.from_bytes(file_data)
    except (ValueError, struct.error) as e:
        raise ValueError(f"Invalid file format: {e}")
    
    print(f"[INFO] File version: {header.version}")
    print(f"[INFO] Original filename: {header.filename or 'unknown'}")
    print(f"[INFO] Header size: {header_size:,} bytes")
    
    # Extract ciphertext (everything after the header)
    ciphertext_only = file_data[header_size:]
    
    # Derive key using the salt from header
    print(f"[INFO] Deriving key with {iterations:,} PBKDF2 iterations...")
    key = derive_key(password, header.salt, iterations)
    
    # Reconstruct ciphertext + tag for AES-GCM
    # GCM expects ciphertext and tag concatenated
    ciphertext_with_tag = ciphertext_only + header.tag
    
    # Initialize AES-GCM cipher
    aesgcm = AESGCM(key)
    
    # Decrypt (this also verifies the authentication tag)
    try:
        plaintext = aesgcm.decrypt(header.nonce, ciphertext_with_tag, None)
    except InvalidTag:
        raise InvalidTag("Decryption failed! Wrong password or file corrupted.")
    
    # Determine output path
    if output_path is None:
        if header.filename:
            output_path = header.filename
        else:
            # Remove .enc extension if present
            if input_path.lower().endswith('.enc'):
                output_path = input_path[:-4]
            else:
                output_path = input_path + ".decrypted"
    
    # Avoid overwriting original encrypted file
    output_path_obj = Path(output_path)
    counter = 1
    while output_path_obj.exists():
        stem = output_path_obj.stem
        suffix = output_path_obj.suffix
        output_path = f"{stem}_{counter}{suffix}"
        output_path_obj = Path(output_path)
        counter += 1
    
    # Write decrypted file
    with open(output_path, 'wb') as f:
        f.write(plaintext)
    
    print(f"[INFO] Output: {output_path}")
    print(f"[INFO] Decrypted size: {len(plaintext):,} bytes")
    print(f"[INFO] Decryption successful!")
    print(f"[INFO] Integrity verified ✓")
    
    return output_path


def get_file_info(input_path: str) -> dict:
    """
    Get information about an encrypted file without decrypting it.
    
    Args:
        input_path: Path to the encrypted file
        
    Returns:
        Dictionary with file information
    """
    input_path_obj = Path(input_path)
    if not input_path_obj.exists():
        raise FileNotFoundError(f"File not found: {input_path}")
    
    with open(input_path, 'rb') as f:
        file_data = f.read()
    
    try:
        header, header_size = FileHeader.from_bytes(file_data)
    except (ValueError, struct.error) as e:
        return {"error": f"Not a valid encrypted file: {e}"}
    
    file_size = input_path_obj.stat().st_size
    ciphertext_size = file_size - header_size
    
    # Get version (handle both header types)
    version = getattr(header, 'version', 1)  # Default to 1 if not present
    
    return {
        "is_valid": True,
        "version": version,
        "original_filename": header.filename,
        "salt_length": len(header.salt),
        "nonce_length": len(header.nonce),
        "tag_length": len(header.tag),
        "header_size": header_size,
        "file_size": file_size,
        "ciphertext_size": ciphertext_size,
        "salt_hex": header.salt.hex()[:32] + "..." if len(header.salt.hex()) > 32 else header.salt.hex(),
        "nonce_hex": header.nonce.hex()[:24] + "..." if len(header.nonce.hex()) > 24 else header.nonce.hex(),
        "tag_hex": header.tag.hex()[:32] + "..." if len(header.tag.hex()) > 32 else header.tag.hex(),
    }


def prompt_password(confirm: bool = False) -> str:
    """
    Securely prompt user for password.
    
    Args:
        confirm: If True, prompt twice to confirm password
        
    Returns:
        The entered password
    """
    password = getpass.getpass("Enter password: ")
    
    if confirm:
        confirm_pw = getpass.getpass("Confirm password: ")
        if password != confirm_pw:
            print("[ERROR] Passwords do not match!")
            sys.exit(1)
    
    return password


def test_encryption_decryption():
    """Test the full encryption/decryption cycle."""
    print("=== Testing Full Encryption/Decryption Cycle ===\n")
    
    # Create a test file
    test_content = b"This is a secret message for testing encryption.\n" + b"A" * 1000
    test_file = "test_original.txt"
    
    with open(test_file, 'wb') as f:
        f.write(test_content)
    
    print(f"1. Created test file: {test_file} ({len(test_content)} bytes)")
    
    # Encrypt
    password = "TestPassword123!"
    encrypted_file = None
    
    try:
        encrypted_file = encrypt_file(test_file, password)
        print(f"\n2. Encrypted to: {encrypted_file}")
        
        # Get info
        info = get_file_info(encrypted_file)
        print(f"\n3. File info:")
        for key, value in info.items():
            print(f"   {key}: {value}")
        
        # Decrypt
        decrypted_file = decrypt_file(encrypted_file, password)
        print(f"\n4. Decrypted to: {decrypted_file}")
        
        # Verify content
        with open(decrypted_file, 'rb') as f:
            decrypted_content = f.read()
        
        if decrypted_content == test_content:
            print("\n✓ SUCCESS: Decrypted content matches original!")
        else:
            print("\n✗ FAIL: Decrypted content does not match!")
        
        # Test with wrong password
        print("\n5. Testing wrong password (should fail):")
        try:
            decrypt_file(encrypted_file, "WrongPassword!")
            print("✗ FAIL: Should have raised an error with wrong password")
        except InvalidTag:
            print("✓ CORRECT: Wrong password correctly rejected")
        
    finally:
        # Cleanup
        for file in [test_file, encrypted_file, "test_original.txt.decrypted"]:
            if file and Path(file).exists():
                Path(file).unlink()
                print(f"Cleaned up: {file}")
    
    print("\n=== Test Complete ===")


if __name__ == "__main__":
    test_encryption_decryption()