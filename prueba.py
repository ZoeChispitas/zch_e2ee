import os
import zch_e2ee

def test_cifrado_password():
    print("\n--- TEST: Cifrado con Contrasena (Scrypt + AES-GCM) ---")
    mensaje = "Mi nota super secreta guardada con una contrasena simple."
    contrasena = "ZchPasswordSegura99"
    
    print(f"  Texto original: '{mensaje}'")
    cifrado = zch_e2ee.encriptar_con_password(mensaje, contrasena)
    print(f"  Cifrado (Base64): {cifrado[:50]}...")
    
    descifrado = zch_e2ee.desencriptar_con_password(cifrado, contrasena)
    print(f"  Descifrado: '{descifrado}'")
    
    assert mensaje == descifrado, "El mensaje descifrado con contrasena no coincide."
    print("  [OK] Test completado con exito.")

def test_encriptacion_firmada():
    print("\n--- TEST: Cifrado + Firma Combinados (RSA) ---")
    privada_alice, publica_alice = zch_e2ee.generar_llaves()
    privada_bob, publica_bob = zch_e2ee.generar_llaves()
    
    mensaje = "Hola Bob, este es un mensaje autenticado de Alice."
    print(f"  Texto original: '{mensaje}'")
    
    payload = zch_e2ee.encriptar_y_firmar_e2ee(mensaje, publica_bob, privada_alice)
    print(f"  Payload firmado y cifrado (Base64): {payload[:50]}...")
    
    descifrado, firma_valida = zch_e2ee.desencriptar_y_verificar_e2ee(payload, privada_bob, publica_alice)
    print(f"  Descifrado: '{descifrado}'")
    print(f"  Firma valida: {firma_valida}")
    
    assert mensaje == descifrado, "El mensaje no coincide al descifrar."
    assert firma_valida, "La firma digital debio ser valida."
    print("  [OK] Test completado con exito.")

def test_archivos():
    print("\n--- TEST: Cifrado de Archivos y Llaves en Disco ---")
    privada, publica = zch_e2ee.generar_llaves()
    
    archivo_secreto = "secreto_v4.txt"
    archivo_cifrado = "secreto_v4.enc"
    archivo_descifrado = "secreto_v4_descifrado.txt"
    
    # Crear archivo
    contenido = "Datos sensibles de Zoe CH para test de archivos."
    with open(archivo_secreto, "w", encoding="utf-8") as f:
        f.write(contenido)
        
    # Cifrar archivo
    zch_e2ee.encriptar_archivo_e2ee(archivo_secreto, archivo_cifrado, publica)
    print(f"  Archivo cifrado creado: '{archivo_cifrado}'")
    
    # Descifrar archivo
    zch_e2ee.desencriptar_archivo_e2ee(archivo_cifrado, archivo_descifrado, privada)
    with open(archivo_descifrado, "r", encoding="utf-8") as f:
        descifrado = f.read()
    print(f"  Archivo descifrado recuperado: '{descifrado}'")
    
    assert contenido == descifrado, "El archivo descifrado no coincide."
    
    # Limpiar archivos generados en test
    for archivo in [archivo_secreto, archivo_cifrado, archivo_descifrado]:
        if os.path.exists(archivo):
            os.remove(archivo)
    print("  [OK] Test de archivos completado con exito.")

def test_archivo_password():
    print("\n--- TEST: Cifrado de Archivos con Contrasena (Scrypt + AES-GCM + Zlib) ---")
    archivo_secreto = "archivo_secreto.txt"
    archivo_cifrado = "archivo_secreto.enc"
    archivo_descifrado = "archivo_secreto_descifrado.txt"
    password = "ClaveDeArchivo99"
    
    contenido = "Este es un documento protegido unicamente con una contrasena tradicional y comprimido con zlib."
    with open(archivo_secreto, "w", encoding="utf-8") as f:
        f.write(contenido)
        
    # Encriptar
    zch_e2ee.encriptar_archivo_con_password(archivo_secreto, archivo_cifrado, password)
    print(f"  Archivo cifrado creado con contrasena: '{archivo_cifrado}'")
    
    # Descifrar
    zch_e2ee.desencriptar_archivo_con_password(archivo_cifrado, archivo_descifrado, password)
    with open(archivo_descifrado, "r", encoding="utf-8") as f:
        descifrado = f.read()
    print(f"  Archivo descifrado recuperado: '{descifrado}'")
    
    assert contenido == descifrado, "El archivo descifrado con contrasena no coincide."
    
    # Limpiar
    for archivo in [archivo_secreto, archivo_cifrado, archivo_descifrado]:
        if os.path.exists(archivo):
            os.remove(archivo)
    print("  [OK] Test completado con exito.")

def main():
    print("=" * 70)
    print(" PRUEBAS UNITARIAS DE SISTEMA - zch_e2ee v0.5.0")
    print("=" * 70)
    
    try:
        test_cifrado_password()
        test_encriptacion_firmada()
        test_archivos()
        test_archivo_password()
        print("\n[OK] ¡TODOS LOS TESTS PASARON EXITOSAMENTE!")
    except AssertionError as e:
        print(f"\n[ERROR] Fallo en la validacion: {e}")
    except Exception as e:
        print(f"\n[ERROR] Error inesperado en ejecucion: {e}")
    
    print("=" * 70)

if __name__ == "__main__":
    main()