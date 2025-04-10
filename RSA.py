from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import timeit

def generateKeys():
    # Create an RSA key pair with a key size of 1024 bits
    keygen_start = timeit.default_timer()
    key = RSA.generate(1024)
    keygen_time = (timeit.default_timer() - keygen_start) * 1000
    print(f"RSA key generation time: {keygen_time:.4f} ms")
    
    # Set the private_key variable to the generated key and convert to byte
    privateKey = key.export_key(format='PEM')
    
    # Derive the public key from the generated key and convert to byte
    publicKey = key.publickey().export_key(format='PEM')
    
    return privateKey, publicKey, keygen_time

def rsa_encrypt(text, publicKey):
    # Convert byte public key to RSA class object
    publicKey = RSA.import_key(publicKey)
    
    # Create a PKCS1_OAEP cipher object with the public key for encryption
    cipher_rsa = PKCS1_OAEP.new(publicKey)
    
    # Encrypt the provided data using the public key
    encrypt_start = timeit.default_timer()
    ciphertext = cipher_rsa.encrypt(text.encode('utf-8'))
    encrypt_time = (timeit.default_timer() - encrypt_start) * 1000
    print(f"RSA encryption time: {encrypt_time:.4f} ms")
    
    return ciphertext, encrypt_time

def rsa_decrypt(ciphertext, privateKey):
    # Convert byte private key to RSA class object
    privateKey = RSA.import_key(privateKey)
    
    # Create a PKCS1_OAEP cipher object with the private key for decryption    
    cipher_rsa = PKCS1_OAEP.new(privateKey)
    
    decrypt_start = timeit.default_timer()
    plaintext = cipher_rsa.decrypt(ciphertext)
    decrypt_time = (timeit.default_timer() - decrypt_start) * 1000
    print(f"RSA decryption time: {decrypt_time:.4f} ms")
    
    return plaintext.decode('utf-8'), decrypt_time

if __name__ == "__main__":
    privateKey, publicKey = generateKeys()

    text = 'Hello, Lee Chee Ann (1191103098)!'

    ciphertext = rsa_encrypt(text, publicKey)
    print("Ciphertext: {}".format(ciphertext))

    plaintext = rsa_decrypt(ciphertext, privateKey)
    print("Plaintext: {}".format(plaintext))