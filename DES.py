from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def des3_encrypt(plaintext): 
    plaintext = plaintext.encode('utf-8')

    # DES3 uses 3 keys, each key is 8-bytes, total 24-byte
    key = get_random_bytes(24)
  
    # Create DES3 cipher object with key in ECB mode
    # ECB mode is weaker operation mode, but offers more data integrity
    des3 = DES3.new(key, DES3.MODE_ECB)
    
    # Turn plaintext to be a multiple of 8 bytes (Fit block boundary in ECB)
    padded_plaintext = pad(plaintext, des3.block_size)
    ciphertext = des3.encrypt(padded_plaintext)
    return ciphertext, key

def des3_decrypt(ciphertext, key):
    des3 = DES3.new(key, DES3.MODE_ECB)
    decryptedtext = des3.decrypt(ciphertext)
    
    # Unpad plaintext to original block size
    plaintext = unpad(decryptedtext, des3.block_size)
    return plaintext.decode('utf-8')

if __name__ == "__main__":
    text = "1191103341 Violette Lai"

    ciphertext, key = des3_encrypt(text)
    print(f"Encrypted text: {ciphertext}")
    plaintext = des3_decrypt(ciphertext, key)
    print(f"Decrypted text: {plaintext}")