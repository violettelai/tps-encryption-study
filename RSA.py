from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

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

if __name__ == "__main__":
    privateKey, publicKey = generateKeys()
    print(f"ori: privatekey: {type(privateKey)}, {privateKey}\npublickey: {type(publicKey)}, {publicKey}")

    #convert to byte to string to store in db
    privateKey, publicKey = privateKey.export_key(format='PEM').decode('utf-8'), publicKey.export_key(format='PEM').decode('utf-8')
    print(f"db: privatekey: {type(privateKey)}, {privateKey}\npublickey: {type(publicKey)}, {publicKey}")

    #retreive from db convert back to byte to RSA key object
    privateKey, publicKey = privateKey.encode('utf-8'), publicKey.encode('utf-8')
    privateKey, publicKey = RSA.import_key(privateKey), RSA.import_key(publicKey)
    print(f"aft: privatekey: {type(privateKey)}, {privateKey}\npublickey: {type(publicKey)}, {publicKey}")

    text = 'Hello, Lee Chee Ann (1191103098)!'

    ciphertext = rsa_encrypt(text, publicKey)
    print("Ciphertext: {}".format(ciphertext))
    print(f"c: {type(base64.b64encode(ciphertext).decode('utf-8'))}, {base64.b64encode(ciphertext).decode('utf-8')}")
    # print(f"c2: {type(bytes(str(ciphertext), 'utf-8'))}, {bytes(str(ciphertext), 'utf-8')}")
    ciphertext = base64.b64encode(ciphertext).decode('utf-8')
    ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
    print(f"cc: {type(ciphertext)}, {ciphertext}")

    plaintext = rsa_decrypt(ciphertext, privateKey)
    print("Plaintext: {}".format(plaintext))