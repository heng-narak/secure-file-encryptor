#!/usr/bin/env python3
"""
Demo script for Secure File Encryptor.
Run this to showcase all features.
"""
import os
import time
import subprocess
import sys
from pathlib import Path

def print_header(text):
    """Print a formatted header."""
    print("\n" + "="*60)
    print(f" {text}")
    print("="*60)

def run_command(cmd, capture=False):
    """Run a command and print it."""
    print(f"\n$ {cmd}")
    if capture:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout
    else:
        subprocess.run(cmd, shell=True)

def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    """Main demo function."""
    clear_screen()
    
    print_header("SECURE FILE ENCRYPTOR - DEMONSTRATION")
    print("Author: Heng Narak")
    print("AES-256-GCM File Encryption System")
    print("\nPress Enter to continue...")
    input()
    
    # Clean up from previous demos
    print_header("CLEANING UP OLD FILES")
    files_to_remove = [
        "secret_doc.txt", "secret_doc.txt.enc", "secret_doc.decrypted.txt",
        "finance.xlsx.txt", "finance.xlsx.txt.enc", "finance.xlsx.decrypted.txt",
        "demo_output.txt", "wrong_password_test.txt"
    ]
    for file in files_to_remove:
        if os.path.exists(file):
            os.remove(file)
            print(f"Removed: {file}")
    
    # Create demo files
    print_header("CREATING DEMO FILES")
    with open("secret_doc.txt", "w") as f:
        f.write("TOP SECRET: Launch codes = 1234-5678-9012\n")
        f.write("CEO Password: Admin@2025!\n")
        f.write("Project Budget: $2,500,000\n")
    
    with open("finance.xlsx.txt", "w") as f:
        f.write("Q4 2025 Financial Report\n")
        f.write("Revenue: $1,250,000\n")
        f.write("Profit: $350,000\n")
        f.write("Expenses: $900,000\n")
    
    print("Created: secret_doc.txt (contains sensitive data)")
    print("Created: finance.xlsx.txt (financial report)")
    print("\nFile contents:")
    run_command("type secret_doc.txt")
    time.sleep(2)
    
    # Show help
    print_header("1. SHOWING HELP AND USAGE")
    run_command("python run.py --help")
    time.sleep(1)
    
    # Show version
    print_header("2. VERSION INFORMATION")
    run_command("python run.py version")
    time.sleep(1)
    
    # Demo 1: Basic Encryption
    print_header("3. BASIC FILE ENCRYPTION")
    print("Encrypting 'secret_doc.txt' with password 'MySecurePass123!'")
    run_command('python run.py encrypt secret_doc.txt -p "MySecurePass123!"')
    time.sleep(2)
    
    # Show encrypted file
    print("\nEncrypted file created: secret_doc.txt.enc")
    print("Let's examine the encrypted file (first 100 bytes):")
    if os.path.exists("secret_doc.txt.enc"):
        with open("secret_doc.txt.enc", "rb") as f:
            data = f.read(100)
            print(f"Hex: {data.hex()}")
            print(f"ASCII (unreadable): {data}")
    time.sleep(2)
    
    # Demo 2: File Information
    print_header("4. EXAMINING ENCRYPTED FILE")
    run_command("python run.py info secret_doc.txt.enc")
    time.sleep(2)
    
    # Demo 3: Decryption
    print_header("5. FILE DECRYPTION")
    print("Decrypting with correct password...")
    run_command('python run.py decrypt secret_doc.txt.enc -p "MySecurePass123!" -o secret_doc.decrypted.txt')
    time.sleep(1)
    
    print("\nVerifying decrypted content:")
    run_command("type secret_doc.decrypted.txt")
    time.sleep(2)
    
    # Demo 4: Wrong Password
    print_header("6. SECURITY FEATURE: WRONG PASSWORD REJECTION")
    print("Attempting to decrypt with wrong password...")
    run_command('python run.py decrypt secret_doc.txt.enc -p "WrongPassword123"')
    time.sleep(2)
    
    # Demo 5: Another file with different password
    print_header("7. ENCRYPTING ANOTHER FILE")
    print("Encrypting financial report with different password...")
    run_command('python run.py encrypt finance.xlsx.txt -p "Finance@Secure456"')
    time.sleep(2)
    
    # Demo 6: Show both encrypted files
    print_header("8. COMPARING ENCRYPTED FILES")
    print("Both files are encrypted but look completely different:")
    print("\nsecret_doc.txt.enc:")
    if os.path.exists("secret_doc.txt.enc"):
        size1 = os.path.getsize("secret_doc.txt.enc")
        print(f"  Size: {size1} bytes")
    
    print("\nfinance.xlsx.txt.enc:")
    if os.path.exists("finance.xlsx.txt.enc"):
        size2 = os.path.getsize("finance.xlsx.txt.enc")
        print(f"  Size: {size2} bytes")
    
    # Demo 7: Show technical details
    print_header("9. TECHNICAL DETAILS")
    print("Key Features Demonstrated:")
    print("1. AES-256-GCM encryption (confidentiality + integrity)")
    print("2. PBKDF2 key derivation (100,000 iterations)")
    print("3. Random salt per file (prevents rainbow table attacks)")
    print("4. Random nonce per encryption (ensures uniqueness)")
    print("5. Authentication tag (detects tampering)")
    print("6. File header with metadata")
    print("7. Password verification (rejects wrong passwords)")
    time.sleep(3)
    
    # Demo 8: Cleanup
    print_header("10. CLEANUP")
    print("Removing demo files...")
    for file in files_to_remove:
        if os.path.exists(file):
            os.remove(file)
            print(f"  Removed: {file}")
    
    print_header("DEMONSTRATION COMPLETE")
    print("\nSummary of features demonstrated:")
    print("✓ File encryption with AES-256-GCM")
    print("✓ Secure key derivation with PBKDF2")
    print("✓ File integrity verification")
    print("✓ Wrong password detection")
    print("✓ Encrypted file metadata inspection")
    print("✓ Command-line interface")
    print("\nThe system provides military-grade encryption for files!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user.")
        sys.exit(0)