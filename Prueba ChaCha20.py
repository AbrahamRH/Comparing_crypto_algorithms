from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from time import process_time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from Crypto.Signature import pss
from Crypto.Hash import SHA256

import rsa
import os
import base64
import hashlib #Used for SHA2 and SHA3 Algorithms 
import binascii
import vectores
#pip install pycryptodome
#pip install rsa

def generate_key(length):
    return os.urandom(length)

KEY_256 = generate_key(32)
KEY_512 = generate_key(64)
NONCE = os.urandom(16)

def testChacha2(vectores):
    test_vectors = vectores.generate_test_vectors(6, 100000)
    for i, vector in enumerate(test_vectors):
        print(f"Vector de prueba #{i+1}:")
        encryption_times = []
        decryption_times = []
        for j in range(len(vector["nonces"])):
            key = vector["key"][j]
            plaintext = vector["plaintexts"][j]
            nonce = vector["nonces"][j]
            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
            encryptor = cipher.encryptor()
            decryptor = cipher.decryptor()

            encryption_time_start = process_time()
            cipherText = encryptor.update(plaintext) + encryptor.finalize()
            encryption_time_end = process_time()
            encryption_time = encryption_time_end - encryption_time_start 
            encryption_times.append(encryption_time)

            decryption_time_start = process_time()
            decryptedText = decryptor.update(cipherText) + decryptor.finalize()
            decryption_time_end = process_time()
            decryption_time = decryption_time_end - decryption_time_start
            decryption_times.append(decryption_time)

            # print(f"Elemento #{j+1}:")
            # print(f"Tiempo de cifrado: {encryption_time:.6f} segundos")
            # print(f"Tiempo de descifrado: {decryption_time:.6f} segundos")
            # print()

        print(f"Tiempo promedio de cifrado del vector de prueba #{i+1}: {sum(encryption_times)/len(encryption_times):.6f} segundos")
        print(f"Tiempo promedio de descifrado del vector de prueba #{i+1}: {sum(decryption_times)/len(decryption_times):.6f} segundos")


if __name__ == "__main__":
    testChacha2(vectores)


