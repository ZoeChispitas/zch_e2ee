import os
import time
import shutil
import zch_e2ee

def main():
    print("=" * 80)
    print(" SIMULADOR DE CURVAS ELÍPTICAS Y SEGURIDAD AVANZADA - zch_e2ee v0.8.0")
    print("=" * 80)
    
    # 1. Generación de llaves EC (X25519 para cifrado, Ed25519 para firmas)
    print("\n[Paso 1] Generando llaves de curvas elípticas para Alice y Bob...")
    time.sleep(0.5)
    
    # Llaves X25519 para E2EE
    priv_x_alice, pub_x_alice = zch_e2ee.generar_llaves_ec()
    priv_x_bob, pub_x_bob = zch_e2ee.generar_llaves_ec()
    
    # Llaves Ed25519 para firmas
    priv_ed_alice, pub_ed_alice = zch_e2ee.generar_llaves_ed25519()
    priv_ed_bob, pub_ed_bob = zch_e2ee.generar_llaves_ed25519()
    
    print("[OK] Llaves X25519 (cifrado) y Ed25519 (firma) generadas con éxito.")
    
    # Mostrar llaves públicas serializadas
    pem_pub_x_alice = zch_e2ee.serializar_llave_publica_ec(pub_x_alice)
    pem_pub_ed_alice = zch_e2ee.serializar_llave_publica_ec(pub_ed_alice)
    
    print("\n--- Muestra de Llave Pública X25519 (Alice) ---")
    print(pem_pub_x_alice.strip())
    print("\n--- Muestra de Llave Pública Ed25519 (Alice) ---")
    print(pem_pub_ed_alice.strip())
    print("-" * 80)
    
    # 2. Cifrado Híbrido EC (X25519 + AES-GCM)
    mensaje = "Hola Bob, este mensaje se cifró usando curvas elípticas X25519 efímeras."
    print(f"\n[Paso 2] Alice cifra un mensaje usando la pública X25519 de Bob:")
    print(f"  [Original] '{mensaje}'")
    
    payload_cifrado = zch_e2ee.encriptar_e2ee_ec(mensaje, pub_x_bob)
    print(f"  [Cifrado Base64] {payload_cifrado[:80]}...")
    
    # Bob descifra
    mensaje_descifrado = zch_e2ee.desencriptar_e2ee_ec(payload_cifrado, priv_x_bob)
    print(f"  [Descifrado Bob] '{mensaje_descifrado}'")
    
    # 3. Cifrado y Firma combinados con curvas elípticas (X25519 + Ed25519)
    print("\n[Paso 3] Alice cifra para Bob (X25519) y firma con su clave privada (Ed25519):")
    mensaje_autenticado = "Confirma recepción de coordenadas: 40.7128° N, 74.0060° W."
    print(f"  [Original] '{mensaje_autenticado}'")
    
    payload_firmado = zch_e2ee.encriptar_y_firmar_e2ee_ec(mensaje_autenticado, pub_x_bob, priv_ed_alice)
    print(f"  [Payload Base64] {payload_firmado[:80]}...")
    
    # Bob recibe, verifica y descifra
    msg_recuperado, firma_valida = zch_e2ee.desencriptar_y_verificar_e2ee_ec(payload_firmado, priv_x_bob, pub_ed_alice)
    print(f"  [Firma Válida] {firma_valida}")
    print(f"  [Descifrado Bob] '{msg_recuperado}'")
    
    # 4. Demostración de Control de Errores con excepciones personalizadas
    print("\n[Paso 4] Simulando errores para verificar excepciones personalizadas:")
    
    print("  a) Bob intenta descifrar con la clave equivocada...")
    try:
        # Intentamos descifrar el mensaje de Bob usando la clave de Alice
        zch_e2ee.desencriptar_e2ee_ec(payload_cifrado, priv_x_alice)
    except zch_e2ee.ErrorDescifrado as e:
        print(f"     [OK - Capturado] Lanzó ErrorDescifrado: {e}")
    except Exception as e:
        print(f"     [ERROR] Se esperaba ErrorDescifrado pero lanzó {type(e)}: {e}")
        
    print("  b) Bob intenta verificar una firma inválida...")
    # Alterar un byte de la firma decodificando y recodificando
    import base64
    paquete_firmado_bytes = base64.b64decode(payload_firmado.encode('utf-8'))
    paquete_alterado_bytes = bytes([paquete_firmado_bytes[0] ^ 0xFF]) + paquete_firmado_bytes[1:]
    payload_alterado = base64.b64encode(paquete_alterado_bytes).decode('utf-8')
    
    msg_fail, firma_fail_valida = zch_e2ee.desencriptar_y_verificar_e2ee_ec(payload_alterado, priv_x_bob, pub_ed_alice)
    print(f"     [Firma Válida para datos alterados] {firma_fail_valida} (Debe ser False)")
    
    # 5. Cifrado de Directorios con Contraseña
    print("\n[Paso 5] Probando cifrado de directorios completo con contraseña simétrica...")
    dir_test = "dir_test_demo"
    dir_test_dest = "dir_test_demo_descifrado"
    archivo_cifrado = "carpeta_protegida.enc"
    password = "SuperPasswordSegura123"
    
    # Crear carpeta de prueba
    os.makedirs(dir_test, exist_ok=True)
    with open(os.path.join(dir_test, "secreto1.txt"), "w") as f:
        f.write("Este es un secreto en el archivo 1 de la carpeta.")
    os.makedirs(os.path.join(dir_test, "sub"), exist_ok=True)
    with open(os.path.join(dir_test, "sub", "secreto2.txt"), "w") as f:
        f.write("Este es un secreto en una subcarpeta.")
        
    print(f"  Carpeta de origen '{dir_test}' configurada con archivos.")
    
    # Encriptar carpeta
    zch_e2ee.encriptar_directorio_con_password(dir_test, archivo_cifrado, password)
    print(f"  [OK] Carpeta cifrada y guardada como '{archivo_cifrado}'.")
    
    # Desencriptar carpeta
    zch_e2ee.desencriptar_directorio_con_password(archivo_cifrado, dir_test_dest, password)
    print(f"  [OK] Carpeta descifrada en '{dir_test_dest}'.")
    
    # Verificar archivos descifrados
    file1 = os.path.join(dir_test_dest, "secreto1.txt")
    file2 = os.path.join(dir_test_dest, "sub", "secreto2.txt")
    if os.path.exists(file1) and os.path.exists(file2):
        with open(file1, "r") as f:
            print(f"  [Contenido Archivo 1] '{f.read()}'")
        with open(file2, "r") as f:
            print(f"  [Contenido Archivo 2] '{f.read()}'")
    
    # Limpiar directorios creados
    for d in [dir_test, dir_test_dest]:
        if os.path.exists(d):
            shutil.rmtree(d)
    if os.path.exists(archivo_cifrado):
        os.remove(archivo_cifrado)
        
    print("\n" + "=" * 80)
    print(" ¡SIMULACIÓN COMPLETADA EXITOSAMENTE CON CURVAS ELÍPTICAS!")
    print("=" * 80)

if __name__ == "__main__":
    main()
