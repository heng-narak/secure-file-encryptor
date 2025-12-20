#!/usr/bin/env python3
"""
GUI launcher for Secure File Encryptor.
"""
import sys
import os

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from src.sfe.gui import main
    print("Launching Secure File Encryptor GUI...")
    main()
except ImportError as e:
    print(f"Error: {e}")
    print("\nMake sure you have installed the required dependencies:")
    print("  pip install -r requirements.txt")
    input("\nPress Enter to exit...")
except Exception as e:
    print(f"Unexpected error: {e}")
    import traceback
    traceback.print_exc()
    input("\nPress Enter to exit...")