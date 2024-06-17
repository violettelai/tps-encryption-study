from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import timeit

def aes_encrypt(header, data):
    # Encode header and data to bytes
    header = header.encode('utf-8')
    data = data.encode('utf-8')

    # Generate a random 256-bit (32-byte) key
    keygen_start = timeit.default_timer()
    key = get_random_bytes(32)
    keygen_time = (timeit.default_timer() - keygen_start) * 1000
    print(f"AES key generation time: {keygen_time:.4f} ms")

    # Create a new AES cipher object in GCM mode
    aes = AES.new(key, AES.MODE_GCM)

    # Include header in the encryption process
    aes.update(header)

    # Encrypt the data and generate a tag for authentication
    encrypt_start = timeit.default_timer()
    ciphertext, tag = aes.encrypt_and_digest(data)
    encryption_time = (timeit.default_timer() - encrypt_start) * 1000
    print(f"AES encryption time: {encryption_time:.4f} ms")

    return key, aes.nonce, header, tag, ciphertext

def aes_decrypt(key, nonce, header, tag, ciphertext):
    # Create a new AES cipher object in GCM mode with the nonce
    c = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Include the header in the decryption process
    c.update(header)

    # Decrypt the ciphertext and verify the tag
    decryption_start = timeit.default_timer()
    data = c.decrypt_and_verify(ciphertext, tag)
    decryption_time = (timeit.default_timer() - decryption_start) * 1000
    print(f"AES decryption time: {decryption_time:.4f} ms")

    # Decode the decrypted data from bytes to string and return it
    return data.decode('utf-8')

if __name__ == "__main__":
    aes_key, aes_nonce, aes_header, aes_tag, aes_ciphertext = aes_encrypt("1191103300", "Hi, my name is Evon Ng.")
    print("AES encrypted ciphertext:", aes_ciphertext)
    data = aes_decrypt(aes_key, aes_nonce, aes_header, aes_tag, aes_ciphertext)
    print("AES decrypted data:",data)