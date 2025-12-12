import argparse

def main():
    parser = argparse.ArgumentParser(description="Secure File Encryptor")
    parser.add_argument("command", choices=["encrypt", "decrypt", "info"])
    args = parser.parse_args()
    
    if args.command == "encrypt":
        print("Encrypt command selected")
    elif args.command == "decrypt":
        print("Decrypt command selected")
    elif args.command == "info":
        print("Secure File Encryptor v0.1")

if __name__ == "__main__":
    main()