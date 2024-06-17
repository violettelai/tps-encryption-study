from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import timeit


def des3_encrypt(plaintext): 
    plaintext = plaintext.encode('utf-8')

    # DES3 uses 3 keys, each key is 8-bytes, total 24-byte
    key = get_random_bytes(24)
    
    # Key gen time
    keygen_start = timeit.default_timer()
    keygen_time = (timeit.default_timer() - keygen_start) * 1000
    print(f"DES key generation time: {keygen_time:.4f} ms")
  
    # Create DES3 cipher object with key in ECB mode
    # ECB mode is weaker operation mode, but offers more data integrity
    des3 = DES3.new(key, DES3.MODE_ECB)
    
    # Turn plaintext to be a multiple of 8 bytes (Fit block boundary in ECB)
    padded_plaintext = pad(plaintext, des3.block_size)
    
    encrypt_start = timeit.default_timer()
    ciphertext = des3.encrypt(padded_plaintext)
    encrypt_time = (timeit.default_timer() - encrypt_start) * 1000
    print(f"DES encryption time: {encrypt_time:.4f} ms")
    
    return ciphertext, key

def des3_decrypt(ciphertext, key):
    des3 = DES3.new(key, DES3.MODE_ECB)
    
    decrypt_start = timeit.default_timer()
    decryptedtext = des3.decrypt(ciphertext)
    decrypt_time = (timeit.default_timer() - decrypt_start) * 1000
    print(f"DES decryption time: {decrypt_time:.4f} ms")
    
    # Unpad plaintext to original block size
    plaintext = unpad(decryptedtext, des3.block_size)
    
    return plaintext.decode('utf-8')

if __name__ == "__main__":
    text = "1191103341 Violette Lai"

    ciphertext, key = des3_encrypt(text)
    print(f"Encrypted text: {ciphertext}")
    plaintext = des3_decrypt(ciphertext, key)
    print(f"Decrypted text: {plaintext}")