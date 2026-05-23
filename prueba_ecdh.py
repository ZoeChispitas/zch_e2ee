import zch_e2ee
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def main():
    print("=" * 70)
    print(" ACUERDO DE CLAVES POR CURVAS ELIPTICAS (ECDH) - zch_e2ee v0.3.0")
    print("=" * 70)

    # 1. Alice y Bob generan sus pares de llaves elipticas
    print("\n[Paso 1] Generando llaves elipticas X25519 para Alice y Bob...")
    privada_alice, publica_alice = zch_e2ee.generar_llaves_ec()
    privada_bob, publica_bob = zch_e2ee.generar_llaves_ec()
    print("[OK] Llaves generadas con exito.")

    # 2. Simulación de intercambio y derivación
    print("\n[Paso 2] Derivando clave secreta compartida (Acuerdo Diffie-Hellman)...")
    
    # Alice deriva usando su privada y la publica de Bob
    clave_compartida_alice = zch_e2ee.derivar_clave_compartida(privada_alice, publica_bob)
    
    # Bob deriva usando su privada y la publica de Alice
    clave_compartida_bob = zch_e2ee.derivar_clave_compartida(privada_bob, publica_alice)
    
    print(f"  Clave derivada por Alice: {clave_compartida_alice.hex()}")
    print(f"  Clave derivada por Bob:   {clave_compartida_bob.hex()}")

    # 3. Verificar que ambas claves sean iguales
    if clave_compartida_alice == clave_compartida_bob:
        print("\n[OK] EXITO! Las claves derivadas son IDENTICAS en ambos extremos sin transmitirla.")
    else:
        print("\n[ERROR] Las claves derivadas no coinciden.")
        return

    # 4. Usar la clave derivada para cifrar con AES-GCM
    print("\n[Paso 4] Alice cifra un mensaje usando la clave derivada (AES-GCM)...")
    mensaje_original = "Este mensaje viaja cifrado con la clave acordada por curvas elipticas de Zoe."
    
    # Cifrado simétrico directo usando la clave acordada
    aesgcm = AESGCM(clave_compartida_alice)
    nonce = os.urandom(12)
    texto_cifrado = aesgcm.encrypt(nonce, mensaje_original.encode('utf-8'), None)
    
    print(f"  Texto cifrado enviado: {texto_cifrado.hex()[:50]}...")

    # 5. Bob descifra usando su clave derivada
    print("\n[Paso 5] Bob recibe el mensaje y lo descifra usando su clave derivada...")
    aesgcm_bob = AESGCM(clave_compartida_bob)
    mensaje_descifrado = aesgcm_bob.decrypt(nonce, texto_cifrado, None).decode('utf-8')
    
    print(f"  Mensaje descifrado por Bob: '{mensaje_descifrado}'")

    if mensaje_original == mensaje_descifrado:
        print("\n[OK] EXITO! Comunicacion segura cifrada establecida mediante curvas elipticas.")
    else:
        print("\n[ERROR] Fallo al descifrar el mensaje.")

    print("\n" + "=" * 70)

if __name__ == "__main__":
    main()
