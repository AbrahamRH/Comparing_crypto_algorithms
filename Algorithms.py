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
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import rsa
import os
import base64
import hashlib #Used for SHA2 and SHA3 Algorithms 
import binascii
#pip install pycryptodome
#pip install rsa


KEY_256 = os.urandom(32)
KEY_512 = os.urandom(64)
NONCE = os.urandom(16)

def RSA_PSS(vectores):
    msg = vectores
    encryption_time_start = process_time()
    key = RSA.generate(2048)
    h = SHA256.new(msg)
    signature = pss.new(key).sign(h)
    encryption_time_end = process_time()
    encryption_time = encryption_time_end - encryption_time_start

    decryption_time_start = process_time()
    #key = RSA.import_key(open('pubkey.der').read())
    h = SHA256.new(msg)
    verifier = pss.new(key)
    try:
      verifier.verify(h, signature)
      print ("The signature is authentic.")
    except (ValueError, TypeError):
      print ("The signature is not authentic.")
    decryption_time_end = process_time()
    decryption_time = decryption_time_end - decryption_time_start
    return (encryption_time,decryption_time)


def RSA_OAEP(vectores):
    msg = vectores
    #Encryption
    encryption_time_start = process_time()
    key = RSA.generate(2048)
    private_key = key.export_key('PEM')
    public_key = key.publickey().exportKey('PEM')
    #msg = str.encode(msg)
    rsa_public_key = RSA.importKey(public_key)
    rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
    cypherText = rsa_public_key.encrypt(msg)
    encryption_time_end = process_time()
    encryption_time = encryption_time_end - encryption_time_start 
    #Decryption
    decryption_time_start = process_time()
    rsa_private_key = RSA.importKey(private_key)
    rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
    decrypted_text = rsa_private_key.decrypt(cypherText)
    decryption_time_end = process_time()
    decryption_time = decryption_time_end - decryption_time_start
    return (encryption_time,decryption_time)

def testSHA3(vectores):
    msg = vectores
    encryption_time_start = process_time()
    #msg = bytes(msg, 'utf-8')
    cypherText = hashlib.sha3_512()
    cypherText = cypherText.update(msg)
    encryption_time_end = process_time()
    encryption_time = encryption_time_end - encryption_time_start 
    decryption_time_start = process_time()
    #It is not possible to decrypt a message crphered with SHA3
    #cypherText = cypherText.hexdigest()
    decryption_time = 0
    return (encryption_time,decryption_time)

def testSHA2(vectores):
    msg = vectores
    #msg = bytes(msg, encoding='UTF-8')
    encryption_time_start = process_time()
    cypherText = hashlib.sha512()
    cypherText = cypherText.update(msg)
    encryption_time_end = process_time()
    encryption_time = encryption_time_end - encryption_time_start 
    decryption_time_start = process_time()
    #It is not possible to decrypt a message crphered with SHA2
    #cypherText = cypherText.hexdigest()
    decryption_time = 0
    return (encryption_time,decryption_time)


def testChacha(vectores):
    msg = vectores
    cipher = Cipher(algorithms.ChaCha20(KEY_256,NONCE), mode=None, backend=default_backend())
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
    print(plaintext)
    return (encryption_time,decryption_time)
    
def testECB(vectores):
    msg = vectores
    padding_length = 16 - (len(msg) % 16)
    msg += bytes([padding_length]) * padding_length
    cipher = Cipher(algorithms.AES(KEY_256), mode=modes.ECB(), backend=default_backend())
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

    padding_length = plaintext[-1]
    print(plaintext[:-padding_length])
    return (encryption_time,decryption_time)

def testGCM(vectores):
    msg = vectores
    cipher = AES.new(KEY_256, AES.MODE_GCM,NONCE)

    encryption_time_start = process_time()
    cipherText, tag = cipher.encrypt_and_digest(msg)
    encryption_time_end = process_time()
    encryption_time = encryption_time_end - encryption_time_start 

    cipher = AES.new(KEY_256, AES.MODE_GCM,NONCE)
    decryption_time_start = process_time()
    plaintext = cipher.decrypt(cipherText)
    decryption_time_end = process_time()
    decryption_time = decryption_time_end - decryption_time_start
    print(plaintext)
    return (encryption_time,decryption_time)


def getData():
    #TODO: tomar los vectores
    #v1 = []
    v1 = b"Vectores de prueba xd, ahora pura basurasjfaoi 231,123 123 123 "
    data = []
    data.append(testChacha(v1))
    data.append(testECB(v1))
    data.append(testGCM(v1))
    data.append(testSHA2(v1))
    data.append(testSHA3(v1))
    data.append(testSHA2(v1))
    data.append(RSA_PSS(v1))
    data.append(RSA_OAEP(v1))
  
    print(data)





if __name__ == "__main__":
    getData()
