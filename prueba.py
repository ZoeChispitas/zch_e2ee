import os
import zch_e2ee

def main():
    print("=" * 70)
    print(" DEMOSTRACION DE NUEVAS FUNCIONES - zch_e2ee v0.2.0")
    print("=" * 70)

    password_llave = "mi-secreto-zch-123"
    archivo_privada = "bob_privada.pem"
    archivo_publica = "bob_publica.pem"
    archivo_secreto = "secreto.txt"
    archivo_cifrado = "secreto.enc"
    archivo_descifrado = "secreto_descifrado.txt"

    # 1. Generar llaves para Bob
    print("\n[Paso 1] Generando llaves criptograficas para Bob...")
    privada_bob, publica_bob = zch_e2ee.generar_llaves()

    # 2. Guardar las llaves en el disco duro (la privada va encriptada con contraseña)
    print(f"\n[Paso 2] Guardando llaves en disco...")
    print(f"  -> Guardando llave privada en '{archivo_privada}' (encriptada con password)...")
    zch_e2ee.guardar_llave_privada_en_archivo(privada_bob, archivo_privada, password=password_llave)
    
    print(f"  -> Guardando llave publica en '{archivo_publica}'...")
    zch_e2ee.guardar_llave_publica_en_archivo(publica_bob, archivo_publica)
    print("[OK] Llaves almacenadas de forma segura.")

    # 3. Crear un archivo de texto confidencial
    print(f"\n[Paso 3] Creando archivo confidencial '{archivo_secreto}'...")
    contenido_secreto = "ESTE ES UN DOCUMENTO FINANCIERO CONFIDENCIAL DE ZOE CH. NIVEL DE SEGURIDAD: MAXIMO."
    with open(archivo_secreto, "w", encoding="utf-8") as f:
        f.write(contenido_secreto)
    print(f"  Contenido original: '{contenido_secreto}'")

    # 4. Encriptar el archivo usando la llave publica cargada desde el disco
    print(f"\n[Paso 4] Cargando llave publica y encriptando el archivo...")
    publica_cargada = zch_e2ee.cargar_llave_publica_desde_archivo(archivo_publica)
    
    print(f"  -> Cifrando '{archivo_secreto}' en '{archivo_cifrado}'...")
    zch_e2ee.encriptar_archivo_e2ee(archivo_secreto, archivo_cifrado, publica_cargada)
    print("[OK] Archivo encriptado con exito.")

    # Mostrar que el archivo cifrado es binario e ilegible
    print("\n  [Muestra] Contenido del archivo cifrado (primeros 40 bytes en hexadecimal):")
    with open(archivo_cifrado, "rb") as f:
        datos_cifrados = f.read(40)
        print(f"  {datos_cifrados.hex()}")

    # 5. Cargar la llave privada usando la contraseña y descifrar el archivo
    print(f"\n[Paso 5] Desencriptando el archivo...")
    print(f"  -> Cargando llave privada desde '{archivo_privada}' con contraseña...")
    try:
        privada_cargada = zch_e2ee.cargar_llave_privada_desde_archivo(archivo_privada, password=password_llave)
        print("  -> Descifrando el archivo encriptado...")
        zch_e2ee.desencriptar_archivo_e2ee(archivo_cifrado, archivo_descifrado, privada_cargada)
        print("[OK] Archivo desencriptado con exito.")
    except Exception as e:
        print(f"  [ERROR] No se pudo cargar la llave privada o descifrar el archivo: {e}")
        return

    # 6. Leer y validar el archivo desencriptado
    print(f"\n[Paso 6] Verificando contenido del archivo desencriptado...")
    with open(archivo_descifrado, "r", encoding="utf-8") as f:
        contenido_recuperado = f.read()
    print(f"  Contenido recuperado: '{contenido_recuperado}'")

    if contenido_secreto == contenido_recuperado:
        print("\n[OK] EXITO! El archivo recuperado coincide exactamente con el original.")
    else:
        print("\n[ERROR] Los contenidos no coinciden.")

    print("\n" + "=" * 70)

if __name__ == "__main__":
    main()