#! /usr/bin/env python3

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


key = os.urandom(32) #256-bit
nonce = os.urandom(16)

cipher = Cipher(algorithms.ChaCha20(key,nonce), mode=None, backend=default_backend())

encryptor = cipher.encryptor()
decryptor = cipher.decryptor()


message = b"HOLAAA este es un test para el funcionamiento de la libreria"


cipherText = encryptor.update(message) + encryptor.finalize()
plaintext = decryptor.update(cipherText) + decryptor.finalize()


print(message)
print(cipherText)
print(plaintext)
