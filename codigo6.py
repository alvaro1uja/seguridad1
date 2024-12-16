from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import time


# Lista de tamaños de clave DSA
key_sizes = [1024, 2048, 3072]


# Mensaje a firmar
message = b"Este es un mensaje para firmar"
h = SHA256.new(message)


# Medir tiempos para cada tamaño de clave
for size in key_sizes:
    print(f"\n--- Tamaño de clave: {size} bits ---")
   
    # Generar clave DSA
    start = time.time()
    key = DSA.generate(size)
    end = time.time()
    print(f"Tiempo de generación de clave: {end - start:.6f} segundos")
   
    # Crear firmante
    signer = DSS.new(key, 'fips-186-3')
   
    # Firma del mensaje
    start = time.time()
    signature = signer.sign(h)
    end = time.time()
    print(f"Tiempo de firma DSA: {end - start:.6f} segundos")
   
    # Crear verificador
    verifier = DSS.new(key.publickey(), 'fips-186-3')
   
    # Verificación de la firma
    start = time.time()
    try:
        verifier.verify(h, signature)
        print("La firma es válida.")
    except ValueError:
        print("La firma no es válida.")
    end = time.time()
    print(f"Tiempo de verificación DSA: {end - start:.6f} segundos")
