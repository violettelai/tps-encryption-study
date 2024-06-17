from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64, timeit

def generateKeys():
    # Create an RSA key pair with a key size of 1024 bits
    keygen_start = timeit.default_timer()
    key = RSA.generate(1024)
    keygen_time = (timeit.default_timer() - keygen_start) * 1000
    print(f"Key generation time: {keygen_time:.4f} ms")
    
    # Set the private_key variable to the generated key and convert to byte
    privateKey = key.export_key(format='PEM')
    
    # Derive the public key from the generated key and convert to byte
    publicKey = key.publickey().export_key(format='PEM')
    
    return privateKey, publicKey 

def rsa_encrypt(text, publicKey):
    # Convert byte public key to RSA class object
    publicKey = RSA.import_key(publicKey)
    
    # Create a PKCS1_OAEP cipher object with the public key for encryption
    cipher_rsa = PKCS1_OAEP.new(publicKey)
    
    # Encrypt the provided data using the public key
    encrypt_start = timeit.default_timer()
    ciphertext = cipher_rsa.encrypt(text.encode('utf-8'))
    encrypt_time = (timeit.default_timer() - encrypt_start) * 1000
    print(f"Encryption time: {encrypt_time:.4f} ms")
    
    return ciphertext

def rsa_decrypt(ciphertext, privateKey):
    # Convert byte private key to RSA class object
    privateKey = RSA.import_key(privateKey)
    
    # Create a PKCS1_OAEP cipher object with the private key for decryption    
    cipher_rsa = PKCS1_OAEP.new(privateKey)
    
    decrypt_start = timeit.default_timer()
    plaintext = cipher_rsa.decrypt(ciphertext)
    decrypt_time = (timeit.default_timer() - decrypt_start) * 1000
    print(f"Decryption time: {decrypt_time:.4f} ms")
    
    return plaintext.decode('utf-8')

if __name__ == "__main__":
    privateKey, publicKey = generateKeys()
    print(f"byte: privatekey: {type(privateKey)}, {privateKey}\npublickey: {type(publicKey)}, {publicKey}")

    #convert to byte to string to store in db
    # privateKey, publicKey = privateKey.export_key(format='PEM').decode('utf-8'), publicKey.export_key(format='PEM').decode('utf-8')
    # print(f"db: privatekey: {type(privateKey)}, {privateKey}\npublickey: {type(publicKey)}, {publicKey}")

    #retreive from db convert back to byte to RSA key object
    # privateKey, publicKey = privateKey.encode('utf-8'), publicKey.encode('utf-8')
    # privateKey, publicKey = RSA.import_key(privateKey), RSA.import_key(publicKey)
    # print(f"aft class: privatekey: {type(privateKey)}, {privateKey}\npublickey: {type(publicKey)}, {publicKey}")

    text = 'Hello, Lee Chee Ann (1191103098)!'

    ciphertext = rsa_encrypt(text, publicKey)
    print("Ciphertext: {}".format(ciphertext))
    # print(f"c: {type(base64.b64encode(ciphertext).decode('utf-8'))}, {base64.b64encode(ciphertext).decode('utf-8')}")
    # ciphertext = base64.b64encode(ciphertext).decode('utf-8')
    # ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
    # print(f"cc: {type(ciphertext)}, {ciphertext}")

    plaintext = rsa_decrypt(ciphertext, privateKey)
    print("Plaintext: {}".format(plaintext))