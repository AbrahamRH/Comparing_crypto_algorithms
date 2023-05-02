import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generate_test_vectors(num_vectors, num_elements):
    print("Generando vectores de prueba... ")
    test_vectors = []
    
    # Generar vectores de prueba
    for i in range(num_vectors):
        vector = {}
        # Generar una clave de 256 bits para cada elemento
        keys = [os.urandom(32) for _ in range(num_elements)]
    
        # Generar un nonce aleatorio de 128 bits para cada elemento
        nonces = [os.urandom(16) for _ in range(num_elements)]
        
        # Crear un objeto Cipher con el algoritmo ChaCha20 y el modo de cifrado para cada elemento
        ciphers = [Cipher(algorithms.ChaCha20(keys[i], nonce), mode=None, backend=default_backend()) for nonce in nonces]
        
        # Generar textos sin formato aleatorios de longitud 32 bytes para cada elemento
        plaintexts = [os.urandom(32) for _ in range(num_elements)]
        
        # Cifrar los textos sin formato utilizando los objetos Cipher
        ciphertexts = [cipher.encryptor().update(plaintext) + cipher.encryptor().finalize() for cipher, plaintext in zip(ciphers, plaintexts)]
        
        # Agregar los vectores de prueba a la lista de resultados
        vector["key"] = keys
        vector["nonces"] = nonces
        vector["plaintexts"] = plaintexts
        vector["ciphertexts"] = ciphertexts
        test_vectors.append(vector)
    
    return test_vectors

def generate_hash_vectors(num_vectors, num_elements):
    test_vectors = []
    
    # Generar vectores de prueba
    for i in range(num_vectors):
        vector = {}
        # Generar datos aleatorios de entrada para cada elemento
        data = [os.urandom(32) for _ in range(num_elements)]
        
        # Agregar los vectores de prueba a la lista de resultados
        vector["data"] = data

        test_vectors.append(vector)
    
    return test_vectors

def imprimir_test_vectors():
    test_vectors = generate_test_vectors(3, 100)
    for i, vector in enumerate(test_vectors):
        print(f"Vector de prueba #{i+1}:")
        for j in range(100):
            print(f"Elemento #{j+1}:")
            print(f"Key: {vector['key'][j].hex()}")
            print(f"Nonce: {vector['nonces'][j].hex()}")
            print(f"Plaintext: {vector['plaintexts'][j].hex()}")
            print(f"Ciphertext: {vector['ciphertexts'][j].hex()}")

def imprimir_hash_vectors():
    test_vectors = generate_test_vectors(3, 10)
    for i, vector in enumerate(test_vectors):
        print(f"Vector de prueba #{i+1}:")
        for j in range(10):
            print(f"Elemento #{j+1}:")
            print(f"Data: {vector['data'][j].hex()}")
