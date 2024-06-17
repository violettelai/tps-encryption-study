from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def aes_encrypt(header, data):
    # Encode header and data to bytes
    header = header.encode('UTF-8')
    data = data.encode('UTF-8')

    # Generate a random 256-bit (32-byte) key
    key = get_random_bytes(32)

    # Create a new AES cipher object in GCM mode
    aes = AES.new(key, AES.MODE_GCM)

    # Include header in the encryption process
    aes.update(header)

    # Encrypt the data and generate a tag for authentication
    ciphertext, tag = aes.encrypt_and_digest(data)

    # Store the nonce, header, ciphertext, and tag in a dictionary
    # Encode each part to base64 string for easier handling
    aes_ciphertext = {
      'nonce': base64.b64encode(aes.nonce).decode('utf-8'),
      'header': base64.b64encode(header).decode('utf-8'),
      'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
      'tag': base64.b64encode(tag).decode('utf-8')
    }

    return aes_ciphertext, key

def aes_decrypt(aes_ciphertext, key):
    # Create a new AES cipher object in GCM mode with the nonce decoded from base64
    c = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(aes_ciphertext['nonce']))

    # Decode and include the header in the decryption process
    c.update(base64.b64decode(aes_ciphertext['header']))

    # Decrypt the ciphertext and verify the tag
    data = c.decrypt_and_verify(base64.b64decode(aes_ciphertext['ciphertext']), base64.b64decode(aes_ciphertext['tag']))

    # Decode the decrypted data from bytes to string and return it
    return data.decode('utf-8')

if __name__ == "__main__":
    aes_ciphertext, aes_key = aes_encrypt("1191103300", "Hi, my name is Evon Ng.")
    print("AES encrypted ciphertext:", aes_ciphertext)
    data = aes_decrypt(aes_ciphertext, aes_key)
    print("AES decrypted data:",data)