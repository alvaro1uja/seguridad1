import time
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

# Generación de claves DSA
def generar_claves_dsa(tamano_clave):
	inicio = time.time()
	key = DSA.generate(tamano_clave)
	fin = time.time()
	tiempo = fin - inicio
	return key, tiempo

# Firma y verificación con DSA
def firmar_dsa(mensaje, clave_privada):
	h = SHA256.new(mensaje)
	signer = DSS.new(clave_privada, 'fips-186-3')
	inicio = time.time()
	firma = signer.sign(h)
	fin = time.time()
	tiempo = fin - inicio
	return firma, tiempo

def verificar_dsa(mensaje, firma, clave_publica):
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

# Función principal para ejecutar las pruebas de DSA
def ejecutar_pruebas_dsa():
	mensaje = b'Este es un mensaje de prueba.'  # Mensaje de ejemplo
	resultados = []

	# Tamaños de clave DSA a probar
	tamanos_clave = [1024, 2048, 3072]

	for tamano in tamanos_clave:
    	# Generación de claves
    	clave_privada, tiempo_gen = generar_claves_dsa(tamano)
    	clave_publica = clave_privada.publickey()

    	# Firma y verificación
    	firma, tiempo_firma = firmar_dsa(mensaje, clave_privada)
    	verificado, tiempo_verificacion = verificar_dsa(mensaje, firma, clave_publica)

    	# Verificar que la firma es válida
    	assert verificado, "La firma no pudo ser verificada."

    	# Almacenar resultados
    	resultados.append({
        	'Tamaño de Clave': tamano,
        	'Tiempo Generación Claves (s)': tiempo_gen,
        	'Tiempo Firma (s)': tiempo_firma,
        	'Tiempo Verificación (s)': tiempo_verificacion
    	})

	# Imprimir resultados
	for res in resultados:
    	print(f"\n--- DSA con clave de {res['Tamaño de Clave']} bits ---")
    	print(f"Tiempo de generación de claves: {res['Tiempo Generación Claves (s)']:.6f} s")
    	print(f"Tiempo de firma: {res['Tiempo Firma (s)']:.6f} s")
    	print(f"Tiempo de verificación: {res['Tiempo Verificación (s)']:.6f} s")

if __name__ == '__main__':
	ejecutar_pruebas_dsa()
