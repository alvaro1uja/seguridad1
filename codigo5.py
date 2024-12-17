import math
from Crypto.PublicKey import RSA, ECC, DSA

def calcular_entropia_rsa(tamano_clave):
    entropia = tamano_clave
    if tamano_clave >= 15360:
        seguridad = 256
    elif tamano_clave >= 7680:
        seguridad = 192
    elif tamano_clave >= 3072:
        seguridad = 128
    elif tamano_clave >= 2048:
        seguridad = 112
    elif tamano_clave >= 1024:
        seguridad = 80
    else:
        seguridad = 'Inseguro'
    return entropia, seguridad

def calcular_entropia_ecc(curva):
    curvas_tamano = {
        'P-192': 192,
        'P-224': 224,
        'P-256': 256,
        'P-384': 384,
        'P-521': 521
    }
    tamano_clave = curvas_tamano.get(curva, None)
    if tamano_clave is None:
        return None, None
    entropia = tamano_clave
    if tamano_clave >= 512:
        seguridad = 256
    elif tamano_clave >= 384:
        seguridad = 192
    elif tamano_clave >= 256:
        seguridad = 128
    elif tamano_clave >= 224:
        seguridad = 112
    elif tamano_clave >= 192:
        seguridad = 80
    else:
        seguridad = 'Inseguro'
    return entropia, seguridad

def calcular_entropia_dsa(tamano_clave):
    entropia = tamano_clave
    if tamano_clave >= 15360:
        seguridad = 256
    elif tamano_clave >= 7680:
        seguridad = 192
    elif tamano_clave >= 3072:
        seguridad = 128
    elif tamano_clave >= 2048:
        seguridad = 112
    elif tamano_clave >= 1024:
        seguridad = 80
    else:
        seguridad = 'Inseguro'
    return entropia, seguridad

tamanos_clave_rsa = [1024, 2048, 3072, 4096, 7680, 15360]
curvas_ecc = ['P-192', 'P-224', 'P-256', 'P-384', 'P-521']
tamanos_clave_dsa = [1024, 2048, 3072, 7680, 15360]

print("=== RSA ===")
for tamano in tamanos_clave_rsa:
    entropia, seguridad = calcular_entropia_rsa(tamano)
    print(f"Clave RSA de {tamano} bits: Entropía = {entropia} bits, Nivel de Seguridad = {seguridad} bits")

print("\n=== ECC ===")
for curva in curvas_ecc:
    entropia, seguridad = calcular_entropia_ecc(curva)
    print(f"Clave ECC usando {curva}: Entropía = {entropia} bits, Nivel de Seguridad = {seguridad} bits")

print("\n=== DSA ===")
for tamano in tamanos_clave_dsa:
    entropia, seguridad = calcular_entropia_dsa(tamano)
    print(f"Clave DSA de {tamano} bits: Entropía = {entropia} bits, Nivel de Seguridad = {seguridad} bits")
