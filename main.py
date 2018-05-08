#https://stuvel.eu/python-rsa-doc/usage.html
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import socket
import select
import struct
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as paddingrsa
from cryptography.hazmat.primitives import hashes

port = 52103
address = "pets.ewi.utwente.nl"

plaintext = "Bob,test message to Bob"

aes_blocksize = 16
aes_keysize = 128

# return key, iv, ciphercode
def aes_encrypt(bytes):
    iv = os.urandom(aes_blocksize)
    key = os.urandom(int(aes_keysize / 8))
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(bytes) + padder.finalize()
    bytes = encryptor.update(padded_data) + encryptor.finalize()
    return key, iv, bytes

# returns bytes with 4 bit big endian integer representing length of bytes prepended
def prepend_length(bytes):
    out = bytearray(struct.pack('>I', len(bytes)))
    out.extend(bytes)
    return out

# returns bytes encrypted with rsa, using provided public key file
def rsa_encrypt(keyfile, bytes):
    with open(keyfile, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
        
        ciphertext = public_key.encrypt(
            bytes,
            paddingrsa.OAEP(
                mgf=paddingrsa.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        '''
        with open("testkeys/test.ppk", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
            
            plaintext = private_key.decrypt(
                ciphertext,
                paddingrsa.OAEP(
                    mgf=paddingrsa.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print((iv+key).hex())
            print(plaintext.hex())
        '''
            
        return ciphertext
    
outmsg = plaintext.encode()
key, iv, outmsg = aes_encrypt(outmsg)
#print((key + iv).hex())
#print("---")
encrypted_info = rsa_encrypt("keys/public-key-mix-1.pem", iv + key) #rsa_encrypt("testkeys/test.pem", iv, key) #"keys/public-key-mix-1.pem"
#print(encrypted_info.hex())

outmsg = encrypted_info + outmsg;
outmsg = prepend_length(outmsg)

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((address, port))
socket.send(outmsg)

ready = select.select([socket], [], [], 2)
if not ready[0]:
    print("No response")
    quit()
data = socket.recv(4096)

print(data)