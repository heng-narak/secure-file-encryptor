"""
Command-line interface for the Secure File Encryptor.
FIXED: Removed Unicode characters for Windows compatibility.
"""
import argparse
import sys
import os
from pathlib import Path

from .core import encrypt_file, decrypt_file, get_file_info, prompt_password
from . import __version__


# Cross-platform status symbols
if os.name == 'nt':  # Windows
    SUCCESS = "[+]"
    ERROR = "[-]"
    INFO = "[*]"
else:  # Unix/Linux/Mac
    SUCCESS = "✅"
    ERROR = "❌"
    INFO = "📄"


def create_parser():
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Secure File Encryption System using AES-256-GCM",
        prog="sfe"
    )
    
    parser.add_argument(
        "--iterations", 
        type=int, 
        default=100000,
        help="PBKDF2 iterations (default: 100,000)"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt_parser.add_argument("input_file", help="Path to the file to encrypt")
    encrypt_parser.add_argument("-o", "--output", help="Output file path (default: input_file.enc)")
    encrypt_parser.add_argument("-p", "--password", help="Encryption password (will prompt if not provided)")
    encrypt_parser.add_argument("--confirm", action="store_true", help="Confirm password by typing twice")
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    decrypt_parser.add_argument("input_file", help="Path to the .enc file to decrypt")
    decrypt_parser.add_argument("-o", "--output", help="Output file path (default: original filename)")
    decrypt_parser.add_argument("-p", "--password", help="Decryption password (will prompt if not provided)")
    
    # Info command
    info_parser = subparsers.add_parser("info", help="Show information about encrypted file")
    info_parser.add_argument("input_file", help="Path to the .enc file")
    
    # Version command
    subparsers.add_parser("version", help="Show version information")

    # GUI command
    subparsers.add_parser("gui", help="Launch graphical user interface")
    
    return parser


def handle_encrypt(args):
    """Handle the encrypt command."""
    # Get password
    if args.password:
        password = args.password
    else:
        print(f"Encrypting: {args.input_file}")
        password = prompt_password(args.confirm)
    
    # Encrypt the file
    try:
        output_file = encrypt_file(
            args.input_file, 
            password, 
            args.output,
            args.iterations
        )
        print(f"\n{SUCCESS} File successfully encrypted: {output_file}")
        
    except Exception as e:
        print(f"\n{ERROR} Encryption failed: {e}")
        sys.exit(1)


def handle_decrypt(args):
    """Handle the decrypt command."""
    # Get password
    if args.password:
        password = args.password
    else:
        print(f"Decrypting: {args.input_file}")
        password = prompt_password()
    
    # Decrypt the file
    try:
        output_file = decrypt_file(
            args.input_file, 
            password, 
            args.output,
            args.iterations
        )
        print(f"\n{SUCCESS} File successfully decrypted: {output_file}")
        
    except Exception as e:
        print(f"\n{ERROR} Decryption failed: {e}")
        sys.exit(1)


def handle_info(args):
    """Handle the info command."""
    try:
        info = get_file_info(args.input_file)
        
        if "error" in info:
            print(f"{ERROR} {info['error']}")
            return
        
        print(f"\n{INFO} File Information: {args.input_file}")
        print("=" * 50)
        
        print(f"Valid encrypted file: {'Yes' if info['is_valid'] else 'No'}")
        print(f"Version: {info['version']}")
        print(f"Original filename: {info['original_filename'] or 'Unknown'}")
        print(f"\nSizes:")
        print(f"  Header: {info['header_size']:,} bytes")
        print(f"  Ciphertext: {info['ciphertext_size']:,} bytes")
        print(f"  Total: {info['file_size']:,} bytes")
        print(f"\nCryptographic parameters:")
        print(f"  Salt: {info['salt_length']} bytes ({info['salt_hex']})")
        print(f"  Nonce: {info['nonce_length']} bytes ({info['nonce_hex']})")
        print(f"  Auth Tag: {info['tag_length']} bytes ({info['tag_hex']})")
        
    except Exception as e:
        print(f"{ERROR} Error: {e}")


def main():
    """Main entry point for the CLI."""
    parser = create_parser()
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        sys.exit(1)
    
    if args.command == "encrypt":
        handle_encrypt(args)
    elif args.command == "decrypt":
        handle_decrypt(args)
    elif args.command == "info":
        handle_info(args)
    elif args.command == "version":
        print(f"Secure File Encryptor v{__version__}")
        print("AES-256-GCM file encryption tool")
    elif args.command == "gui":
        try:
            from .gui import main as gui_main
            gui_main()
        except ImportError as e:
            print(f"Error launching GUI: {e}")
            print("Make sure Tkinter is installed.")
            if os.name == 'nt':  # Windows
                print("Tkinter should be included with Python on Windows.")
            else:  # Linux/Mac
                print("On Linux, install with: sudo apt-get install python3-tk")
            sys.exit(1)

if __name__ == "__main__":
    main()