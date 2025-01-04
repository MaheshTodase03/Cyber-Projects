import hashlib
import os
import json

# Configuration file to store hash values
HASH_FILE = "file_hashes.json"

def calculate_hash(file_path, algorithm='sha256'):
    """Calculate the hash value of a file."""
    hash_func = hashlib.new(algorithm)
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None

def load_hashes():
    """Load stored hashes from the JSON file."""
    if os.path.exists(HASH_FILE):
        with open(HASH_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_hashes(hashes):
    """Save the current hashes to the JSON file."""
    with open(HASH_FILE, 'w') as f:
        json.dump(hashes, f, indent=4)

def monitor_directory(directory, algorithm='sha256'):
    """Monitor a directory for changes in file integrity."""
    current_hashes = load_hashes()
    new_hashes = {}

    print(f"Scanning directory: {directory}")
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = calculate_hash(file_path, algorithm)
            if file_hash:
                new_hashes[file_path] = file_hash
                if file_path in current_hashes:
                    if current_hashes[file_path] != file_hash:
                        print(f"WARNING: File modified: {file_path}")
                else:
                    print(f"New file detected: {file_path}")

    # Detect deleted files
    for file_path in current_hashes:
        if file_path not in new_hashes:
            print(f"WARNING: File deleted: {file_path}")

    # Save the new hash values
    save_hashes(new_hashes)

def main():
    directory_to_monitor = input("Enter the directory to monitor: ").strip()
    algorithm = input("Enter the hash algorithm (default sha256): ").strip() or "sha256"
    monitor_directory(directory_to_monitor, algorithm)

if __name__ == "__main__":
    main()