from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import time


# Lista de curvas ECC
curves = ['P-256', 'P-384', 'P-521']


# Mensaje a firmar
message = b"Este es un mensaje para firmar con ECC"
h = SHA256.new(message)


# Medir tiempos para cada curva ECC
for curve in curves:
    print(f"\n--- Curva ECC: {curve} ---")
   
    # Generar clave ECC
    start = time.time()
    key = ECC.generate(curve=curve)
    end = time.time()
    print(f"Tiempo de generación de clave: {end - start:.6f} segundos")
   
    # Crear firmante
    signer = DSS.new(key, 'fips-186-3')
   
    # Firma del mensaje
    start = time.time()
    signature = signer.sign(h)
    end = time.time()
    print(f"Tiempo de firma ECC: {end - start:.6f} segundos")
   
    # Crear verificador
    verifier = DSS.new(key.public_key(), 'fips-186-3')
   
    # Verificación de la firma
    start = time.time()
    try:
        verifier.verify(h, signature)
        print("La firma es válida.")
    except ValueError:
        print("La firma no es válida.")
    end = time.time()
    print(f"Tiempo de verificación ECC: {end - start:.6f} segundos")
