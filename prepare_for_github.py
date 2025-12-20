#!/usr/bin/env python3
"""
Prepare project for GitHub push.
"""
import os
import shutil
from pathlib import Path

def clean_project():
    """Remove files that shouldn't be on GitHub."""
    print("Cleaning project for GitHub...")
    
    # Files to remove
    files_to_remove = [
        "*.enc",
        "*.decrypted",
        "test_*.txt",
        "secret*.txt",
        "*.pyc",
        "*.pyo"
    ]
    
    # Folders to remove
    folders_to_remove = [
        "__pycache__",
        ".vscode",
        ".idea"
    ]
    
    # Remove files
    for pattern in files_to_remove:
        for file in Path(".").glob(pattern):
            if file.exists():
                file.unlink()
                print(f"  Removed file: {file}")
    
    # Remove folders
    for folder in folders_to_remove:
        folder_path = Path(folder)
        if folder_path.exists():
            shutil.rmtree(folder_path)
            print(f"  Removed folder: {folder_path}")
    
    # Create .gitignore if not exists
    gitignore = Path(".gitignore")
    if not gitignore.exists():
        gitignore_content = """# Python
__pycache__/
*.pyc
*.pyo
*.pyd

# Virtual environments
venv/
env/

# IDE
.vscode/
.idea/

# OS
.DS_Store

# Project
*.enc
*.decrypted
test_*.txt
secret*.txt
"""
        gitignore.write_text(gitignore_content)
        print("  Created: .gitignore")
    
    print("\n✅ Project cleaned and ready for GitHub!")

def check_structure():
    """Check if essential files exist."""
    print("\nChecking project structure...")
    
    essential_files = [
        "src/sfe/__init__.py",
        "src/sfe/cli.py", 
        "src/sfe/core.py",
        "src/sfe/header.py",
        "src/sfe/utils.py",
        "requirements.txt",
        "README.md",
        "run.py"
    ]
    
    missing = []
    for file in essential_files:
        if not Path(file).exists():
            missing.append(file)
    
    if missing:
        print("❌ Missing files:")
        for file in missing:
            print(f"  - {file}")
        return False
    else:
        print("✅ All essential files present!")
        return True

if __name__ == "__main__":
    clean_project()
    if check_structure():
        print("\n🎉 Project is ready for GitHub!")
        print("\nNext steps:")
        print("1. git add .")
        print("2. git commit -m 'Secure File Encryptor v1.0'")
        print("3. git push origin main")
    else:
        print("\n⚠️  Fix missing files before pushing to GitHub.")