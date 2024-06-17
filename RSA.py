from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generateKeys():
    # Create an RSA key pair with a key size of 1024 bits
    key = RSA.generate(1024)
    # Set the private_key variable to the generated key
    privateKey = key
    # Derive the public key from the generated key
    publicKey = key.publickey()
    return privateKey, publicKey 

def rsa_encrypt(text, publicKey):
    # Create a PKCS1_OAEP cipher object with the public key for encryption
    cipher_rsa = PKCS1_OAEP.new(publicKey)
    # Encrypt the provided data using the public key
    ciphertext = cipher_rsa.encrypt(text.encode('utf-8'))
    return ciphertext

def rsa_decrypt(ciphertext, privateKey):
    # Create a PKCS1_OAEP cipher object with the private key for decryption    
    cipher_rsa = PKCS1_OAEP.new(privateKey)
    plaintext = cipher_rsa.decrypt(ciphertext)
    return plaintext.decode('utf-8')

privateKey, publicKey = generateKeys()

text = 'Hello, Lee Chee Ann (1191103098)!'

ciphertext = rsa_encrypt(text, publicKey)
print("Ciphertext: {}".format(ciphertext))

plaintext = rsa_decrypt(ciphertext, privateKey)
print("Plaintext: {}".format(plaintext))