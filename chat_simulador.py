import sys
import time
import zch_e2ee

def main():
    print("=" * 80)
    print(" SIMULADOR DE CHAT INTERACTIVO E2EE (CIFRADO + FIRMA) - zch_e2ee v0.4.0")
    print("=" * 80)
    print("Esta herramienta simula una comunicacion segura entre Alice y Bob.")
    print("Cada mensaje enviado sera cifrado para el receptor y firmado por el emisor.")
    print("Escribe tu mensaje en la terminal. Escribe 'salir' para finalizar.\n")

    # 1. Generar llaves RSA de prueba
    print("[1/2] Generando llaves criptograficas para Alice...")
    privada_alice, publica_alice = zch_e2ee.generar_llaves()
    
    print("[2/2] Generando llaves criptograficas para Bob...")
    privada_bob, publica_bob = zch_e2ee.generar_llaves()
    
    print("\n[OK] Entorno seguro inicializado. ¡Comencemos el chat!")
    print("-" * 80)

    try:
        while True:
            # Entrada de usuario (Alice escribe a Bob)
            print("\nAlice escribe un mensaje para Bob:")
            mensaje = input(">> ").strip()
            
            if not mensaje:
                continue
                
            if mensaje.lower() == 'salir':
                print("\nSaliendo del simulador de chat...")
                break
                
            print("\n--- PROCESANDO ENVIO (Alice) ---")
            print(f"  [Texto Plano] '{mensaje}'")
            
            # Cifrar y firmar
            time.sleep(0.5)
            payload_seguro = zch_e2ee.encriptar_y_firmar_e2ee(mensaje, publica_bob, privada_alice)
            
            print("  [Cifrando + Firmando] Encrypt-then-Sign completado.")
            print(f"  [Payload Transmitido (Base64)]:\n  {payload_seguro[:100]}...\n  ...{payload_seguro[-100:]}")
            
            # Simular tránsito
            print("\n--- PROCESANDO RECEPCION (Bob) ---")
            time.sleep(0.5)
            
            # Bob recibe, descifra y verifica la firma
            mensaje_recuperado, firma_valida = zch_e2ee.desencriptar_y_verificar_e2ee(
                payload_seguro, 
                privada_bob, 
                publica_alice
            )
            
            if firma_valida:
                print("  [Firma] VERIFICADA: El mensaje realmente proviene de Alice y no fue alterado.")
            else:
                print("  [Firma] ALERTA: ¡La firma digital no es valida!")
                
            print(f"  [Bob Lee] '{mensaje_recuperado}'")
            print("-" * 80)
            
    except KeyboardInterrupt:
        print("\n\nSimulador interrumpido por teclado. ¡Hasta luego!")

if __name__ == "__main__":
    main()
