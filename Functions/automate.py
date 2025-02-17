import os, time

ENCRYPTED_DIR = "ProcessedFiles/encrypted"
KEYS_DIR = "ProcessedFiles/keys"

wait_time = 2  # 2 minutes

def delete_encrypted_files():
    print("Deleting key and encrypted files function has been called ...")
    
    # Get the list of key files and encrypted files
    key_files = os.listdir(KEYS_DIR)
    encrypted_files = os.listdir(ENCRYPTED_DIR)
    
    print(f"Key files: {key_files}")
    print(f"Encrypted files: {encrypted_files}")
    
    # First loop: Remove key files
    for key_file in key_files:
        key_path = os.path.join(KEYS_DIR, key_file)
        try:
            if os.path.isfile(key_path):
                os.remove(key_path)
                print(f"Deleted key file: {key_path}")
        except Exception as e:
            print(f"Failed to delete {key_path}. Reason: {e}")
        
        time.sleep(wait_time)
    
    # Second loop: Remove encrypted PDF files
    for encrypted_file in encrypted_files:
        file_path = os.path.join(ENCRYPTED_DIR, encrypted_file)
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
                print(f"Deleted encrypted file: {file_path}")
        except Exception as e:
            print(f"Failed to delete {file_path}. Reason: {e}")
        
        time.sleep(wait_time)
    
    return "Key and encrypted files deleted successfully"

