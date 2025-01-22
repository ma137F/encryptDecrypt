# File decryptor 
import os
import sys
import hashlib
import base64
import json 
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def get_file_list(folder_path):
    return os.listdir()

# Testing json open
def open_json(file_path,folder_path):
    os.chdir(folder_path) # file not found bug,when passing list elementin dir and not abs path,
    with open(file_path, 'r') as rf:
        json_data = json.load(rf)

    return json_data

def decode_and_decrypt_string(b64_string):
    # Converting b64_string to "utf-8"
    decoded_b64 = str(base64.b64decode(b64_string),"utf-8")
    (decoded_b64)
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
    decrypted = f.decrypt(decoded_b64)

    return str(decrypted,"utf-8")

def create_folder_and_files(file_path,decrypted):
    
    if (os.path.exists("decrypted")):
        os.chdir("decrypted")
    else:
        os.mkdir("decrypted")
        os.chdir("decrypted")

    if (file_path.endswith(".calcs")):
        new_file_path=file_path[:-6] # removing .calcs 
    else: 
        new_file_path=file_path
    
    # Recreating the file with with decrypted data 
    with open(new_file_path, 'w', encoding='utf-8') as w:
        w.write(decrypted)
        
    return new_file_path

def get_new_file_hash(new_file_path,hash_string):
    # Generating md5 hash of the new files 
    with open(new_file_path, 'rb') as f:
        b_data = f.read()
        if not b_data:
            pass
    # Generating the hashs from data         
    md5 = hashlib.md5(b_data)
    md5 = md5.hexdigest()
    # Comparing with the original json hash            
    # Creating a log file with md5 hashes
    with open("md5.log", 'a', encoding='utf-8') as wf:
        if (md5==hash_string):
            wf.write(f'{new_file_path}:md5:{md5}:Verified:OK'+"\n")
        else:
            wf.write(f'{new_file_path}:md5:{md5}:Verified:ERROR'+"\n")

def main():

    # Accepting the folder's path as the first argument,       
    try:
        # sys.argv = ['decrypt.py', r'C:\Users\Mark\Desktop\Python\HDE\5\dev\folder']
        
        # argc represents the argument count - script name and file path 
        argc = len(sys.argv)
        if (argc !=2 ):
            print("Usage: decrypttFile.py [DIR_PATH]")
            sys.exit(1)
        
        folder_path = sys.argv[1]        

        if os.path.isabs(folder_path):
            os.chdir(folder_path)

        else:
            curr_dir = os.getcwd()
            folder_path = curr_dir + '\\' + folder_path
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
 
    file_list = get_file_list(folder_path)

    for file_path in file_list:
        if (os.path.isdir(file_path)):
            continue
        if not file_path.endswith(".calcs"): 
            continue

        else:
            json_data = open_json(file_path,folder_path)

            hash_string = json_data['filehash:'] # optional to add a .log with the hashes 
            b64_string = json_data['filecontents:']

            decrypted_b64 = decode_and_decrypt_string(b64_string) 
            new_file = create_folder_and_files(file_path,decrypted_b64)
            get_new_file_hash(new_file,hash_string)

# Calling main function 
if __name__=='__main__':
    main()
