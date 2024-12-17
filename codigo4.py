import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Generación de claves RSA
def generar_claves_rsa(tamano_clave):
    inicio = time.time()
    key = RSA.generate(tamano_clave)
    fin = time.time()
    tiempo = fin - inicio
    return key, tiempo

# Cifrado y descifrado con RSA
def cifrar_rsa(mensaje, clave_publica):
    cipher = PKCS1_OAEP.new(clave_publica)
    inicio = time.time()
    mensaje_cifrado = cipher.encrypt(mensaje)
    fin = time.time()
    tiempo = fin - inicio
    return mensaje_cifrado, tiempo

def descifrar_rsa(mensaje_cifrado, clave_privada):
    cipher = PKCS1_OAEP.new(clave_privada)
    inicio = time.time()
    mensaje_descifrado = cipher.decrypt(mensaje_cifrado)
    fin = time.time()
    tiempo = fin - inicio
    return mensaje_descifrado, tiempo

# Firma y verificación con RSA
def firmar_rsa(mensaje, clave_privada):
    h = SHA256.new(mensaje)
    inicio = time.time()
    firma = pkcs1_15.new(clave_privada).sign(h)
    fin = time.time()
    tiempo = fin - inicio
    return firma, tiempo

def verificar_rsa(mensaje, firma, clave_publica):
    h = SHA256.new(mensaje)
    inicio = time.time()
    try:
        pkcs1_15.new(clave_publica).verify(h, firma)
        fin = time.time()
        tiempo = fin - inicio
        resultado = True
    except (ValueError, TypeError):
        fin = time.time()
        tiempo = fin - inicio
        resultado = False
    return resultado, tiempo

# Función principal para ejecutar las pruebas
def ejecutar_pruebas_rsa():
    mensaje = b'Este es un mensaje de prueba.'  # Mensaje de ejemplo
    resultados = []

    # Tamaños de clave RSA a probar
    tamanos_clave = [1024, 2048, 3072]

    for tamano in tamanos_clave:
        # Generación de claves
        clave_privada, tiempo_gen = generar_claves_rsa(tamano)
        clave_publica = clave_privada.publickey()

        # Cifrado y descifrado
        mensaje_cifrado, tiempo_cifrado = cifrar_rsa(mensaje, clave_publica)
        mensaje_descifrado, tiempo_descifrado = descifrar_rsa(mensaje_cifrado, clave_privada)

        # Firma y verificación
        firma, tiempo_firma = firmar_rsa(mensaje, clave_privada)
        verificado, tiempo_verificacion = verificar_rsa(mensaje, firma, clave_publica)

        # Verificar que el mensaje descifrado coincide con el original
        assert mensaje == mensaje_descifrado, "El mensaje descifrado no coincide con el original."

        # Verificar que la firma es válida
        assert verificado, "La firma no pudo ser verificada."

        # Almacenar resultados
        resultados.append({
            'Tamaño de Clave': tamano,
            'Tiempo Generación Claves (s)': tiempo_gen,
            'Tiempo Cifrado (s)': tiempo_cifrado,
            'Tiempo Descifrado (s)': tiempo_descifrado,
            'Tiempo Firma (s)': tiempo_firma,
            'Tiempo Verificación (s)': tiempo_verificacion
        })

    # Imprimir resultados
    for res in resultados:
        print(f"\n--- RSA con clave de {res['Tamaño de Clave']} bits ---")
        print(f"Tiempo de generación de claves: {res['Tiempo Generación Claves (s)']:.6f} s")
        print(f"Tiempo de cifrado: {res['Tiempo Cifrado (s)']:.6f} s")
        print(f"Tiempo de descifrado: {res['Tiempo Descifrado (s)']:.6f} s")
        print(f"Tiempo de firma: {res['Tiempo Firma (s)']:.6f} s")
        print(f"Tiempo de verificación: {res['Tiempo Verificación (s)']:.6f} s")

if __name__ == '__main__':
    ejecutar_pruebas_rsa()
