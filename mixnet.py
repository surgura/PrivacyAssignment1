from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as paddingrsa
from cryptography.hazmat.primitives import hashes
import struct
import os

class Mixnet:
    pk_mix1 = "keys/public-key-mix-1.pem"
    pk_mix2 = "keys/public-key-mix-2.pem"
    pk_mix3 = "keys/public-key-mix-3.pem"

    aes_blocksize = 16
    aes_keysize = 128

    # return key, iv, ciphercode
    @staticmethod
    def aes_encrypt(bytes):
        iv = os.urandom(Mixnet.aes_blocksize)
        key = os.urandom(int(Mixnet.aes_keysize / 8))
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(bytes) + padder.finalize()
        bytes = encryptor.update(padded_data) + encryptor.finalize()
        return key, iv, bytes

    # returns bytes encrypted with rsa, using provided public key file
    @staticmethod
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

    @staticmethod
    def mix_encrypt(mix_file, bytes):
        key, iv, cipherdata = Mixnet.aes_encrypt(bytes)
        cipherkeys = Mixnet.rsa_encrypt(mix_file, iv + key)
        return cipherkeys + cipherdata
        
    # returns bytes with 4 bit big endian integer representing length of bytes prepended
    @staticmethod
    def prepend_length(bytes):
        out = struct.pack('>I', len(bytes))
        return out + bytes

    @staticmethod
    def make_message(plain_bytes):
        cipher3 = Mixnet.mix_encrypt(Mixnet.pk_mix3, plain_bytes)
        cipher2 = Mixnet.mix_encrypt(Mixnet.pk_mix2, cipher3)
        cipher1 = Mixnet.mix_encrypt(Mixnet.pk_mix1, cipher2)
        return Mixnet.prepend_length(cipher1)