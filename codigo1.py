from Crypto.PublicKey import RSA, ECC, DSA
from Crypto.Signature import pkcs1_15, DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Mensaje a firmar
message = b"Este es un mensaje seguro para firmar."

# RSA
def rsa_demo():
	print("\n--- RSA ---")
	# Generar claves RSA
	key = RSA.generate(2048)
	private_key = key.export_key()
	public_key = key.publickey().export_key()

	# Firma digital
	rsa_key = RSA.import_key(private_key)
	hash_message = SHA256.new(message)
	signature = pkcs1_15.new(rsa_key).sign(hash_message)

	# Verificación de la firma
	public_rsa_key = RSA.import_key(public_key)
	try:
    	pkcs1_15.new(public_rsa_key).verify(hash_message, signature)
    	print("Firma RSA verificada correctamente.")
	except (ValueError, TypeError):
    	print("La verificación de la firma RSA falló.")

# ECC
def ecc_demo():
	print("\n--- ECC ---")
	# Generar claves ECC
	key = ECC.generate(curve="P-256")
	private_key = key.export_key(format="PEM")
	public_key = key.public_key().export_key(format="PEM")

	# Firma digital
	ecc_key = ECC.import_key(private_key)
	hash_message = SHA256.new(message)
	signer = DSS.new(ecc_key, "fips-186-3")
	signature = signer.sign(hash_message)

	# Verificación de la firma
	public_ecc_key = ECC.import_key(public_key)
	verifier = DSS.new(public_ecc_key, "fips-186-3")
	try:
    	verifier.verify(hash_message, signature)
    	print("Firma ECC verificada correctamente.")
	except (ValueError, TypeError):
    	print("La verificación de la firma ECC falló.")

# DSA
def dsa_demo():
	print("\n--- DSA ---")
	# Generar claves DSA
	key = DSA.generate(2048)
	private_key = key.export_key()
	public_key = key.publickey().export_key()

	# Firma digital
	dsa_key = DSA.import_key(private_key)
	hash_message = SHA256.new(message)
	signer = DSS.new(dsa_key, "fips-186-3")
	signature = signer.sign(hash_message)

	# Verificación de la firma
	public_dsa_key = DSA.import_key(public_key)
	verifier = DSS.new(public_dsa_key, "fips-186-3")
	try:
    	verifier.verify(hash_message, signature)
    	print("Firma DSA verificada correctamente.")
	except (ValueError, TypeError):
    	print("La verificación de la firma DSA falló.")

# Ejecutar demostraciones
rsa_demo()
ecc_demo()
dsa_demo()
