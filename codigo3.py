import time
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

# Generación de claves ECC
def generar_claves_ecc(curva):
    inicio = time.time()
    key = ECC.generate(curve=curva)
    fin = time.time()
    tiempo = fin - inicio
    return key, tiempo

# Firma y verificación con ECC
def firmar_ecc(mensaje, clave_privada):
    h = SHA256.new(mensaje)
    signer = DSS.new(clave_privada, 'fips-186-3')
    inicio = time.time()
    firma = signer.sign(h)
    fin = time.time()
    tiempo = fin - inicio
    return firma, tiempo

def verificar_ecc(mensaje, firma, clave_publica):
    h = SHA256.new(mensaje)
    verifier = DSS.new(clave_publica, 'fips-186-3')
    inicio = time.time()
    try:
        verifier.verify(h, firma)
        fin = time.time()
        tiempo = fin - inicio
        resultado = True
    except ValueError:
        fin = time.time()
        tiempo = fin - inicio
        resultado = False
    return resultado, tiempo

# Función principal para ejecutar las pruebas de ECC
def ejecutar_pruebas_ecc():
    mensaje = b'Este es un mensaje de prueba.'  # Mensaje de ejemplo
    resultados = []

    # Curvas ECC a probar
    curvas = ['P-256', 'P-384', 'P-521']

    for curva in curvas:
        # Generación de claves
        clave_privada, tiempo_gen = generar_claves_ecc(curva)
        clave_publica = clave_privada.public_key()

        # Firma y verificación
        firma, tiempo_firma = firmar_ecc(mensaje, clave_privada)
        verificado, tiempo_verificacion = verificar_ecc(mensaje, firma, clave_publica)

        # Verificar que la firma es válida
        assert verificado, "La firma no pudo ser verificada."

        # Almacenar resultados
        resultados.append({
            'Curva': curva,
            'Tiempo Generación Claves (s)': tiempo_gen,
            'Tiempo Firma (s)': tiempo_firma,
            'Tiempo Verificación (s)': tiempo_verificacion
        })

    # Imprimir resultados
    for res in resultados:
        print(f"\n--- ECC usando la curva {res['Curva']} ---")
        print(f"Tiempo de generación de claves: {res['Tiempo Generación Claves (s)']:.6f} s")
        print(f"Tiempo de firma: {res['Tiempo Firma (s)']:.6f} s")
        print(f"Tiempo de verificación: {res['Tiempo Verificación (s)']:.6f} s")

if __name__ == '__main__':
    ejecutar_pruebas_ecc()
