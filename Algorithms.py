#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2023 AbrahamRH <abrahamrzhz@gmail.com>
#
# Distributed under terms of the MIT license.

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from time import process_time
import os
import base64

KEY_256 = os.urandom(32)
KEY_512 = os.urandom(64)
NONCE = os.urandom(16)


def testAlgorithm(cipher, vector):
    #TODO: Obtener vectores de prueba y aplicar el for aqui
    msg = b"Just a test, continue with random text xD: adkfjasfda0ehfaoif9212839182312u31o2hjkhvk"

    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()

    encryption_time_start = process_time()
    cipherText = encryptor.update(msg) + encryptor.finalize()
    encryption_time_end = process_time()
    encryption_time = encryption_time_end - encryption_time_start 


    decryption_time_start = process_time()
    plaintext = decryptor.update(cipherText) + decryptor.finalize()
    decryption_time_end = process_time()

    decryption_time = decryption_time_end - decryption_time_start

    return (encryption_time,decryption_time)




def getData():
    chacha20 = Cipher(algorithms.ChaCha20(KEY_256,NONCE), mode=None, backend=default_backend())
    AES_ECB = Cipher(algorithms.AES(KEY_256), mode=modes.ECB(), backend=default_backend())
    AES_GCM = Cipher(algorithms.AES(KEY_256), mode=modes.GCM(NONCE), backend=default_backend())

    chachaTime = testAlgorithm(chacha20, "hola") # Esto deberia ser una lista con muchos tiempos(?
    print(chachaTime)


if __name__ == "__main__":
    getData()
    print("hola")



