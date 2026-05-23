import time
import zch_e2ee

def main():
    print("=" * 70)
    print(" SIMULADOR DE ENCRIPTACION EXTREMO A EXTREMO (E2EE) - Firma: ZCH")
    print("=" * 70)
    
    # 1. Generacion de claves para Alice y Bob
    print("\n[Paso 1] Generando llaves criptograficas para Alice y Bob...")
    time.sleep(1)
    
    privada_alice, publica_alice = zch_e2ee.generar_llaves()
    privada_bob, publica_bob = zch_e2ee.generar_llaves()
    
    print("[OK] Llaves generadas con exito.")
    
    # Mostrar una muestra de como se ven las llaves publicas
    pem_publica_alice = zch_e2ee.serializar_llave_publica(publica_alice)
    print("\n--- Muestra de la Llave Publica de Alice (PEM) ---")
    # Mostrar solo las primeras y ultimas lineas para no inundar la pantalla
    lineas = pem_publica_alice.strip().split("\n")
    print("\n".join(lineas[:2]) + "\n... [lineas intermedias ocultas] ...\n" + "\n".join(lineas[-2:]))
    print("-------------------------------------------------")
    
    # 2. El mensaje original de Alice
    mensaje_original = "Hola Bob, este es un mensaje super confidencial de ZCH. Nos vemos a las 9 PM en el punto acordado."
    print(f"\n[Paso 2] Alice redacta el mensaje original:")
    print(f"  [Msg] '{mensaje_original}'")
    
    # 3. Alice firma el mensaje para asegurar autenticidad
    print("\n[Paso 3] Alice firma el mensaje con su Llave Privada...")
    firma_alice = zch_e2ee.firmar_mensaje(mensaje_original, privada_alice)
    print(f"  [Sig] Firma digital generada (Base64):\n  {firma_alice[:64]}...")
    
    # 4. Alice encripta el mensaje con la llave publica de Bob
    print("\n[Paso 4] Alice encripta el mensaje con la Llave Publica de Bob...")
    payload_cifrado = zch_e2ee.encriptar_e2ee(mensaje_original, publica_bob)
    print("\n  [Cipher] Mensaje cifrado (Payload E2EE en Base64):")
    print(f"  {payload_cifrado[:80]}...\n  ...{payload_cifrado[-80:]}")
    print("\n  [INFO] Si un espia en la red intercepta este mensaje, no podra leer nada.")
    
    # 5. El canal de comunicacion (simulando envio)
    print("\n[Paso 5] Transmitiendo el mensaje y la firma digital por internet...")
    time.sleep(1)
    
    # 6. Bob recibe y verifica la autenticidad
    print("\n[Paso 6] Bob recibe el mensaje. Primero, verifica la firma usando la Llave Publica de Alice...")
    es_valida = zch_e2ee.verificar_firma(mensaje_original, firma_alice, publica_alice)
    
    if es_valida:
        print("  [OK] Firma VERIFICADA. El mensaje fue enviado realmente por Alice y no ha sido modificado.")
    else:
        print("  [ERROR] ¡La firma no coincide!")
        
    # 7. Bob desencripta el mensaje usando su llave privada
    print("\n[Paso 7] Bob desencripta el mensaje usando su propia Llave Privada...")
    mensaje_desencriptado = zch_e2ee.desencriptar_e2ee(payload_cifrado, privada_bob)
    
    print("\n  [Plain] Mensaje desencriptado por Bob:")
    print(f"  [OK] '{mensaje_desencriptado}'")
    
    # 8. Demostracion de seguridad: ¿Que pasa si alguien altera el texto cifrado?
    print("\n" + "=" * 70)
    print(" DEMOSTRACION DE SEGURIDAD CONTRA ATAQUES (Alteracion de datos)")
    print("=" * 70)
    print("\n[Simulacion] Un hacker intercepta el mensaje y cambia un caracter en el texto cifrado...")
    
    # Alterar un caracter del payload
    payload_alterado = payload_cifrado[:-10] + "A" + payload_cifrado[-9:]
    
    print("Intentando desencriptar el mensaje alterado...")
    try:
        zch_e2ee.desencriptar_e2ee(payload_alterado, privada_bob)
    except Exception as e:
        print(f"  [OK] Exito en la defensa: La desencriptacion fallo como se esperaba.")
        print(f"  [Shield] Detalle del error de seguridad: {str(e)}")
        print("  [Explicacion] Al usar encriptacion hibrida con AES-GCM, cualquier alteracion en el")
        print("  mensaje hace que el descifrado falle inmediatamente, evitando ataques de inyeccion.")

    print("\n" + "=" * 70)
    print(" ¡Simulacion completada con exito! Puedes usar 'import zch_e2ee' en cualquier script.")
    print("=" * 70)

if __name__ == "__main__":
    main()
