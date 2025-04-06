import os

def generate_key():
    return os.urandom(16)

def xor_encrypt(data, key):
    encrypted_data = bytearray(data)
    key_len = len(key)
    
    for i in range(len(encrypted_data)):
        encrypted_data[i] ^= key[i % key_len] 

    return encrypted_data

def save_to_file(file_path, key, encrypted_data):
    with open(file_path, 'wb') as file:
        file.write(key)  
        file.write(encrypted_data)  

if __name__ == "__main__":
    file_path = "payload.ini"
    bin_path = "loader.bin"
    with open(bin_path, "rb") as f:
        binary_data = f.read()
    aes_key = generate_key()
    encrypted_data = xor_encrypt(binary_data, aes_key)
    save_to_file(file_path, aes_key, encrypted_data)

