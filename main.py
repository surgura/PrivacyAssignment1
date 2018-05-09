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

port = 55897      
address = "pets.ewi.utwente.nl"

pk_mix1 = "keys/public-key-mix-1.pem"
pk_mix2 = "keys/public-key-mix-2.pem"
pk_mix3 = "keys/public-key-mix-3.pem"

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
                mgf=paddingrsa.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        return ciphertext

def mix_encrypt(mix_file, bytes):
    key, iv, cipherdata = aes_encrypt(bytes)
    cipherkeys = rsa_encrypt(mix_file, iv + key)
    return cipherkeys + cipherdata
    
# returns bytes with 4 bit big endian integer representing length of bytes prepended
def prepend_length(bytes):
    out = struct.pack('>I', len(bytes))
    return out + bytes
    
def make_mixnet_message(plain_bytes):
    cipher3 = mix_encrypt(pk_mix3, plain_bytes)
    cipher2 = mix_encrypt(pk_mix2, cipher3)
    cipher1 = mix_encrypt(pk_mix1, cipher2)
    return prepend_length(cipher1)
    
message = make_mixnet_message("Bob,test message to Bob".encode())

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((address, port))
socket.send(message)

ready = select.select([socket], [], [], 2)
if not ready[0]:
    print("No response")
    quit()
data = socket.recv(4096)

print(data)