#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2023 AbrahamRH <abrahamrzhz@gmail.com>
#
# Distributed under terms of the MIT license.

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from time import process_time, process_time_ns
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from Crypto.Signature import pss
from Crypto.Hash import SHA256

# ECDSA
from hashlib import sha256
from ecdsa import SigningKey
from ecdsa.util import sigencode_der, sigdecode_der
from ecdsa import BRAINPOOLP512r1
from ecdsa import BadSignatureError

# EdDSA
import ed25519

import rsa
import os
import base64
import hashlib #Used for SHA2 and SHA3 Algorithms 
import binascii
import vectores
#pip install pycryptodome
#pip install rsa


KEY_256 = os.urandom(32)
KEY_512 = os.urandom(64)
NONCE = os.urandom(16)


# Vectores debe venir serializado
def testECDSA(vectores):
    print("="*23)   
    print("--- Prueba ECDSA ---")
    print("="*23)
    print("Generando vectores de prueba...")
    test_vectors = vectores.generate_test_vectors(6, 100000)

    ## Generación de llaves
    PRIVKEY_ECDSA = SigningKey.generate(curve=BRAINPOOLP512r1)
    PUBKEY_ECDSA = PRIVKEY_ECDSA.verifying_key
    
    promedio_signing = {}
    promedio_verifying = {}

    
    for i, vector in enumerate(test_vectors):
        print(f"Vector de prueba #{i+1}:")
        sig_times = []
        ver_times = []
        for j in range(len(vector["nonces"])):
            pt = vector["plaintexts"][j]

            sig_time_start = process_time()
    
            # Signing
            sig = PRIVKEY_ECDSA.sign_deterministic(
                pt,
                hashfunc=sha256,
                sigencode=sigencode_der
                )

            sig_time_end = process_time()
            sig_time = sig_time_end - sig_time_start

            sig_times.append(sig_time)

            # Verifying
            ver_time_start = process_time()
            
            ret = PUBKEY_ECDSA.verify(sig, pt, sha256, sigdecode=sigdecode_der)

            ver_time_end = process_time()
            ver_time = ver_time_end - sig_time_start
            ver_times.append(ver_time)

        promedio_signing[i+1] = sum(sig_times)/len(sig_times)
        promedio_verifying[i+1] = sum(ver_times)/len(ver_times)
        print(f"Tiempo promedio de firmado del vector de prueba #{i+1}: {promedio_signing[i+1]} nano segundos")
        print(f"Tiempo promedio de verificación del vector de prueba #{i+1}: {promedio_verifying[i+1]} nano segundos")


    return(promedio_signing, promedio_verifying)

# Vectores debe venir serializado
def testEdDSA(vectores):
    print("="*23)   
    print("--- Prueba EdDSA ---")
    print("="*23)
    print("Generando vectores de prueba...")
    test_vectors = vectores.generate_test_vectors(6, 100000)

    PRIVKEY_EDDSA, PUBKEY_EDDSA = ed25519.create_keypair()
  
    promedio_signing = {}
    promedio_verifying = {}

    for i, vector in enumerate(test_vectors):
        print(f"Vector de prueba #{i+1}:")
        sig_times = []
        ver_times = []
        for j in range(len(vector["nonces"])):
            pt = vector["plaintexts"][j]

            sig_time_start = process_time()


            # Signing
            sig = PRIVKEY_EDDSA.sign(pt, encoding='hex')

            sig_time_end = process_time()
            sig_time = sig_time_end - sig_time_start
            sig_times.append(sig_time)

            # Verifying
            ver_time_start = process_time()
            PUBKEY_EDDSA.verify(sig, pt, encoding='hex')
            ver_time_end = process_time()
            ver_time = ver_time_end - sig_time_start
            ver_times.append(ver_time)

        promedio_signing[i+1] = sum(sig_times)/len(sig_times)
        promedio_verifying[i+1] = sum(ver_times)/len(ver_times)
        print(f"Tiempo promedio de firmado del vector de prueba #{i+1}: {promedio_signing[i+1]} nano segundos")
        print(f"Tiempo promedio de verificación del vector de prueba #{i+1}: {promedio_verifying[i+1]} nano segundos")

    return(promedio_signing, promedio_verifying)


def RSA_PSS(vectores):
    print("="*23)
    print("--- Prueba RSA_PSS ---")
    print("="*23)
    test_vectors = vectores.generate_test_vectors(6, 100000)
    promedio_encryption = {}
    promedio_decryption = {}
    for i, vector in enumerate(test_vectors):
        print(f"Vector de prueba #{i+1}:")
        encryption_times = []
        decryption_times = []
        for j in range(len(vector["nonces"])):
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
        promedio_encryption[i+1] = sum(encryption_times)/len(encryption_times)
        promedio_decryption[i+1] = sum(decryption_times)/len(decryption_times)
        print(f"Tiempo promedio de cifrado del vector de prueba #{i+1}: {promedio_encryption[i+1]:.6f} segundos")
        print(f"Tiempo promedio de descifrado del vector de prueba #{i+1}: {promedio_decryption[i+1]:.6f} segundos")
    return (promedio_encryption,promedio_decryption)


def RSA_OAEP(vectores):
    print("="*23)
    print("--- Prueba RSA_OAEP ---")
    print("="*23)
    test_vectors = vectores.generate_test_vectors(6, 100000)
    promedio_encryption = {}
    promedio_decryption = {}
    for i, vector in enumerate(test_vectors):
        print(f"Vector de prueba #{i+1}:")
        encryption_times = []
        decryption_times = []
        for j in range(len(vector["nonces"])):
            msg = vector["plaintexts"][j]
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
            encryption_times.append(encryption_time)
            decryption_times.append(decryption_time)
        promedio_encryption[i+1] = sum(encryption_times)/len(encryption_times)
        promedio_decryption[i+1] = sum(decryption_times)/len(decryption_times)
        print(f"Tiempo promedio de cifrado del vector de prueba #{i+1}: {promedio_encryption[i+1]:.6f} segundos")
        print(f"Tiempo promedio de descifrado del vector de prueba #{i+1}: {promedio_decryption[i+1]:.6f} segundos")
    return (promedio_encryption,promedio_decryption)

def testSHA2(vectores):
    encryption_times = []
    for vector in vectores:
        msg = b''.join(vector['data'])
        encryption_time_start = process_time()
        cypherText = hashlib.sha512(msg).hexdigest()
        encryption_time_end = process_time()
        encryption_time = encryption_time_end - encryption_time_start
        decryption_time = 0
        encryption_times.append(encryption_time)
    print(f"Tiempos de hashing de SHA-512 por vector: {encryption_times}")
    return encryption_times, [0] * len(vectores)


def testSHA3(vectores):
    encryption_times = []

    for vector in vectores:
        msg = b''.join(vector['data'])
        encryption_time_start = process_time()
        cypherText = hashlib.sha3_512(msg).hexdigest()
        encryption_time_end = process_time()
        encryption_time = encryption_time_end - encryption_time_start
        decryption_time = 0
        encryption_times.append(encryption_time)
    print(f"Tiempos de hashing de Scrypt SHA3-512 por vector: {encryption_times}")
    return encryption_times, [0] * len(vectores)

def testScrypt(vectores):
    encryption_times = []
    decryption_times = []
    for vector in vectores:
        msg = b''.join(vector['data'])
        salt = os.urandom(16)
        n = 512
        r = 8
        p = 1
        maxmem = 0
        dklen = 32
        encryption_time_start = process_time()
        cypherText = hashlib.scrypt(msg, salt=salt, n=n, r=r, p=p, maxmem=maxmem, dklen=dklen)
        encryption_time_end = process_time()
        encryption_time = encryption_time_end - encryption_time_start
        decryption_time_start = process_time()
        # It is not possible to decrypt a message encrypted with scrypt
        decryption_time = 0
        decryption_times.append(decryption_time)
        encryption_times.append(encryption_time)
    print(f"Tiempos de hashing de Scrypt por vector: {encryption_times}")
    return encryption_times, decryption_times

def testChacha(vectores):
    print("="*23)
    print("--- Prueba ChaCha20 ---")
    print("="*23)
    test_vectors = vectores.generate_test_vectors(6, 100000)
    promedio_encryption = {}
    promedio_decryption = {}
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

            encryption_time_start = process_time_ns()
            cipherText = encryptor.update(plaintext) + encryptor.finalize()
            encryption_time_end = process_time_ns()
            encryption_time = encryption_time_end - encryption_time_start 
            encryption_times.append(encryption_time)

            decryption_time_start = process_time_ns()
            decryptedText = decryptor.update(cipherText) + decryptor.finalize()
            decryption_time_end = process_time_ns()
            decryption_time = decryption_time_end - decryption_time_start
            decryption_times.append(decryption_time)

        promedio_encryption[i+1] = sum(encryption_times)/len(encryption_times)
        promedio_decryption[i+1] = sum(decryption_times)/len(decryption_times)
        print(f"Tiempo promedio de cifrado del vector de prueba #{i+1}: {promedio_encryption[i+1]} nano segundos")
        print(f"Tiempo promedio de descifrado del vector de prueba #{i+1}: {promedio_decryption[i+1]} nano segundos")
    return (promedio_encryption,promedio_decryption)
    
def testECB(vectores):
    print("="*23)
    print("--- Prueba AES ECB ---")
    print("="*23)
    test_vectors = vectores.generate_test_vectors(6, 100000)
    promedio_encryption = {}
    promedio_decryption = {}
    for i, vector in enumerate(test_vectors):
        print(f"Vector de prueba #{i+1}:")
        encryption_times = []
        decryption_times = []
        for j in range(len(vector["nonces"])):
            key = vector["key"][j]
            plaintext = vector["plaintexts"][j]
            cipher = Cipher(algorithms.AES(key), mode=modes.ECB(), backend=default_backend())
            encryptor = cipher.encryptor()
            decryptor = cipher.decryptor()

            encryption_time_start = process_time_ns()
            cipherText = encryptor.update(plaintext) + encryptor.finalize()
            encryption_time_end = process_time_ns()
            encryption_time = encryption_time_end - encryption_time_start 
            encryption_times.append(encryption_time)


            decryption_time_start = process_time_ns()
            plaintext = decryptor.update(cipherText) + decryptor.finalize()
            decryption_time_end = process_time_ns()
            decryption_time = decryption_time_end - decryption_time_start
            decryption_times.append(decryption_time)

        promedio_encryption[i+1] = sum(encryption_times)/len(encryption_times)
        promedio_decryption[i+1] = sum(decryption_times)/len(decryption_times)
        print(f"Tiempo promedio de cifrado del vector de prueba #{i+1}: {promedio_encryption[i+1]} nano segundos")
        print(f"Tiempo promedio de descifrado del vector de prueba #{i+1}: {promedio_decryption[i+1]} nano segundos")
    return (promedio_encryption,promedio_decryption)

def testGCM(vectores):
    print("="*23)
    print("--- Prueba AES ECB ---")
    print("="*23)
    test_vectors = vectores.generate_test_vectors(6, 100000)
    promedio_encryption = {}
    promedio_decryption = {}
    for i, vector in enumerate(test_vectors):
        print(f"Vector de prueba #{i+1}:")
        encryption_times = []
        decryption_times = []
        for j in range(len(vector["nonces"])):
            key = vector["key"][j]
            nonce = vector["nonces"][j]
            plaintext = vector["plaintexts"][j]
            cipher = AES.new(key, AES.MODE_GCM,NONCE)    
            encryption_time_start = process_time_ns()
            cipherText, tag = cipher.encrypt_and_digest(plaintext)
            encryption_time_end = process_time_ns()
            encryption_time = encryption_time_end - encryption_time_start 
            encryption_times.append(encryption_time)

            cipher = AES.new(KEY_256, AES.MODE_GCM,nonce)
            decryption_time_start = process_time_ns()
            plaintext = cipher.decrypt(cipherText)
            decryption_time_end = process_time_ns()
            decryption_time = decryption_time_end - decryption_time_start
            decryption_times.append(decryption_time)
        promedio_encryption[i+1] = sum(encryption_times)/len(encryption_times)
        promedio_decryption[i+1] = sum(decryption_times)/len(decryption_times)
        print(f"Tiempo promedio de cifrado del vector de prueba #{i+1}: {promedio_encryption[i+1]} nano segundos")
        print(f"Tiempo promedio de descifrado del vector de prueba #{i+1}: {promedio_decryption[i+1]} nano segundos")
    return (promedio_encryption,promedio_decryption)


def getData():
    data_encryption, data_decryption = testChacha(vectores)
    print("")
    data_encryption, data_decryption = testECB(vectores)
    print("")
    data_encryption, data_decryption = testGCM(vectores)
    print("")
    data_encryption, data_decryption = testSHA2(vectores)
    print("")
    data_encryption, data_decryption = testSHA3(vectores)
    print("")
    data_encryption, data_decryption = RSA_OAEP(vectores)
    print("")
    data_encryption, data_decryption = RSA_PSS(vectores)
    print("")
    data_encryption, data_decryption = testECDSA(vectores)
    print("")
    data_encryption, data_decryption = testEdDSA(vectores)
    test_vectors = vectores.generate_hash_vectors(6, 100000)
    print("")
    sha3_encryption_times, sha3_decryption_times = testSHA3(test_vectors)
    print("")
    sha2_encryption_times, sha2_decryption_times = testSHA2(test_vectors)
    print("")
    scrypt_encryption_times, scrypt_decryption_times = testScrypt(test_vectors)


if __name__ == "__main__":
    getData()
