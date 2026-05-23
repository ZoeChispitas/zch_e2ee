import os
import sys
import argparse
import zch_e2ee

def imprimir_exito(mensaje):
    print(f"\n✨ [ÉXITO] {mensaje}")

def imprimir_error(mensaje):
    print(f"\n❌ [ERROR] {mensaje}", file=sys.stderr)

def menu_interactivo():
    while True:
        print("\n" + "=" * 70)
        print(" 🔒 zch-e2ee — MENÚ CRIPTOGRÁFICO INTERACTIVO (v0.9.0)")
        print("=" * 70)
        print("  1. 🔑 Generar pares de llaves (RSA, X25519 o Ed25519)")
        print("  2. 📝 Cifrar un archivo (Contraseña o Clave Pública)")
        print("  3. 🔓 Descifrar un archivo (Contraseña o Clave Privada)")
        print("  4. 📁 Cifrar un directorio completo (ZIP cifrado)")
        print("  5. 📂 Descifrar un directorio completo (ZIP descifrado)")
        print("  6. ✍️  Firmar un archivo digitalmente (RSA o Ed25519)")
        print("  7. 🔍 Verificar firma digital de un archivo")
        print("  8. 🚪 Salir")
        print("=" * 70)
        
        opcion = input("Selecciona una opción (1-8): ").strip()
        
        if opcion == "1":
            print("\n--- Generar Llaves ---")
            print("  a. RSA (E2EE clásico y firmas)")
            print("  b. X25519 (E2EE elíptico veloz)")
            print("  c. Ed25519 (Firmas elípticas veloces)")
            tipo = input("Selecciona el tipo de llave (a/b/c): ").strip().lower()
            
            if tipo == "a":
                bits_str = input("Tamaño de clave RSA (2048 o 4096, default 2048): ").strip()
                bits = int(bits_str) if bits_str.isdigit() else 2048
                ruta_priv = input("Archivo destino para Llave Privada (default: rsa_privada.pem): ").strip() or "rsa_privada.pem"
                ruta_pub = input("Archivo destino para Llave Pública (default: rsa_publica.pem): ").strip() or "rsa_publica.pem"
                pwd = input("Contraseña para cifrar la clave privada (opcional, Enter para omitir): ").strip() or None
                
                try:
                    priv, pub = zch_e2ee.generar_llaves(bits)
                    zch_e2ee.guardar_llave_privada_en_archivo(priv, ruta_priv, pwd)
                    zch_e2ee.guardar_llave_publica_en_archivo(pub, ruta_pub)
                    imprimir_exito(f"Llaves RSA de {bits} bits generadas y guardadas.")
                except Exception as e:
                    imprimir_error(f"Fallo al generar llaves RSA: {e}")
                    
            elif tipo in ("b", "c"):
                ruta_priv = input("Archivo destino para Llave Privada (default: ec_privada.pem): ").strip() or "ec_privada.pem"
                ruta_pub = input("Archivo destino para Llave Pública (default: ec_publica.pem): ").strip() or "ec_publica.pem"
                pwd = input("Contraseña para cifrar la clave privada (opcional, Enter para omitir): ").strip() or None
                
                try:
                    if tipo == "b":
                        priv, pub = zch_e2ee.generar_llaves_ec()
                    else:
                        priv, pub = zch_e2ee.generar_llaves_ed25519()
                    zch_e2ee.guardar_llave_privada_ec_en_archivo(priv, ruta_priv, pwd)
                    zch_e2ee.guardar_llave_publica_ec_en_archivo(pub, ruta_pub)
                    imprimir_exito("Llaves de curvas elípticas generadas y guardadas.")
                except Exception as e:
                    imprimir_error(f"Fallo al generar llaves EC: {e}")
            else:
                imprimir_error("Opción de llave inválida.")
                
        elif opcion == "2":
            print("\n--- Cifrar Archivo ---")
            ruta_orig = input("Ruta del archivo a cifrar: ").strip()
            if not os.path.exists(ruta_orig):
                imprimir_error("El archivo de origen no existe.")
                continue
            ruta_dest = input("Ruta del archivo cifrado resultante: ").strip()
            
            print("  a. Contraseña simétrica (Scrypt)")
            print("  b. Llave pública RSA del destinatario")
            print("  c. Llave pública X25519 (EC) del destinatario")
            metodo = input("Selecciona método de cifrado (a/b/c): ").strip().lower()
            
            try:
                if metodo == "a":
                    pwd = input("Contraseña de cifrado: ").strip()
                    zch_e2ee.encriptar_archivo_con_password(ruta_orig, ruta_dest, pwd)
                    imprimir_exito(f"Archivo cifrado con contraseña en '{ruta_dest}'")
                elif metodo == "b":
                    ruta_pub = input("Ruta de la llave pública RSA (.pem): ").strip()
                    pub = zch_e2ee.cargar_llave_publica_desde_archivo(ruta_pub)
                    zch_e2ee.encriptar_archivo_e2ee(ruta_orig, ruta_dest, pub)
                    imprimir_exito(f"Archivo cifrado con RSA en '{ruta_dest}'")
                elif metodo == "c":
                    ruta_pub = input("Ruta de la llave pública X25519 (.pem): ").strip()
                    pub = zch_e2ee.cargar_llave_publica_ec_desde_archivo(ruta_pub)
                    zch_e2ee.encriptar_archivo_e2ee_ec(ruta_orig, ruta_dest, pub)
                    imprimir_exito(f"Archivo cifrado con X25519 en '{ruta_dest}'")
                else:
                    imprimir_error("Método inválido.")
            except Exception as e:
                imprimir_error(f"Error al cifrar archivo: {e}")
                
        elif opcion == "3":
            print("\n--- Descifrar Archivo ---")
            ruta_orig = input("Ruta del archivo cifrado: ").strip()
            if not os.path.exists(ruta_orig):
                imprimir_error("El archivo cifrado no existe.")
                continue
            ruta_dest = input("Ruta de destino del archivo descifrado: ").strip()
            
            print("  a. Contraseña simétrica")
            print("  b. Llave privada RSA")
            print("  c. Llave privada X25519 (EC)")
            metodo = input("Selecciona método de descifrado (a/b/c): ").strip().lower()
            
            try:
                if metodo == "a":
                    pwd = input("Contraseña: ").strip()
                    zch_e2ee.desencriptar_archivo_con_password(ruta_orig, ruta_dest, pwd)
                    imprimir_exito(f"Archivo descifrado exitosamente en '{ruta_dest}'")
                elif metodo == "b":
                    ruta_priv = input("Ruta de la llave privada RSA (.pem): ").strip()
                    pwd = input("Contraseña de la llave privada (Enter si no tiene): ").strip() or None
                    priv = zch_e2ee.cargar_llave_privada_desde_archivo(ruta_priv, pwd)
                    zch_e2ee.desencriptar_archivo_e2ee(ruta_orig, ruta_dest, priv)
                    imprimir_exito(f"Archivo descifrado con RSA en '{ruta_dest}'")
                elif metodo == "c":
                    ruta_priv = input("Ruta de la llave privada X25519 (.pem): ").strip()
                    pwd = input("Contraseña de la llave privada (Enter si no tiene): ").strip() or None
                    priv = zch_e2ee.cargar_llave_privada_ec_desde_archivo(ruta_priv, pwd)
                    zch_e2ee.desencriptar_archivo_e2ee_ec(ruta_orig, ruta_dest, priv)
                    imprimir_exito(f"Archivo descifrado con X25519 en '{ruta_dest}'")
                else:
                    imprimir_error("Método inválido.")
            except Exception as e:
                imprimir_error(f"Error al descifrar archivo: {e}")
                
        elif opcion == "4":
            print("\n--- Cifrar Carpeta ---")
            ruta_orig = input("Ruta del directorio a cifrar: ").strip()
            if not os.path.exists(ruta_orig) or not os.path.isdir(ruta_orig):
                imprimir_error("El directorio no existe.")
                continue
            ruta_dest = input("Ruta del archivo cifrado resultante (.enc): ").strip()
            
            print("  a. Contraseña simétrica (Scrypt)")
            print("  b. Llave pública RSA del destinatario")
            print("  c. Llave pública X25519 (EC) del destinatario")
            metodo = input("Selecciona método de cifrado (a/b/c): ").strip().lower()
            
            try:
                if metodo == "a":
                    pwd = input("Contraseña de cifrado: ").strip()
                    zch_e2ee.encriptar_directorio_con_password(ruta_orig, ruta_dest, pwd)
                    imprimir_exito(f"Directorio cifrado en '{ruta_dest}'")
                elif metodo == "b":
                    ruta_pub = input("Ruta de la llave pública RSA (.pem): ").strip()
                    pub = zch_e2ee.cargar_llave_publica_desde_archivo(ruta_pub)
                    zch_e2ee.encriptar_directorio_e2ee(ruta_orig, ruta_dest, pub)
                    imprimir_exito(f"Directorio cifrado con RSA en '{ruta_dest}'")
                elif metodo == "c":
                    ruta_pub = input("Ruta de la llave pública X25519 (.pem): ").strip()
                    pub = zch_e2ee.cargar_llave_publica_ec_desde_archivo(ruta_pub)
                    zch_e2ee.encriptar_directorio_e2ee_ec(ruta_orig, ruta_dest, pub)
                    imprimir_exito(f"Directorio cifrado con X25519 en '{ruta_dest}'")
                else:
                    imprimir_error("Método inválido.")
            except Exception as e:
                imprimir_error(f"Error al cifrar directorio: {e}")
                
        elif opcion == "5":
            print("\n--- Descifrar Carpeta ---")
            ruta_orig = input("Ruta del archivo cifrado (.enc): ").strip()
            if not os.path.exists(ruta_orig):
                imprimir_error("El archivo cifrado no existe.")
                continue
            ruta_dest = input("Ruta del directorio de destino final: ").strip()
            
            print("  a. Contraseña simétrica")
            print("  b. Llave privada RSA")
            print("  c. Llave privada X25519 (EC)")
            metodo = input("Selecciona método de descifrado (a/b/c): ").strip().lower()
            
            try:
                if metodo == "a":
                    pwd = input("Contraseña: ").strip()
                    zch_e2ee.desencriptar_directorio_con_password(ruta_orig, ruta_dest, pwd)
                    imprimir_exito(f"Carpeta restaurada exitosamente en '{ruta_dest}'")
                elif metodo == "b":
                    ruta_priv = input("Ruta de la llave privada RSA (.pem): ").strip()
                    pwd = input("Contraseña de la llave privada (Enter si no tiene): ").strip() or None
                    priv = zch_e2ee.cargar_llave_privada_desde_archivo(ruta_priv, pwd)
                    zch_e2ee.desencriptar_directorio_e2ee(ruta_orig, ruta_dest, priv)
                    imprimir_exito(f"Carpeta restaurada con RSA en '{ruta_dest}'")
                elif metodo == "c":
                    ruta_priv = input("Ruta de la llave privada X25519 (.pem): ").strip()
                    pwd = input("Contraseña de la llave privada (Enter si no tiene): ").strip() or None
                    priv = zch_e2ee.cargar_llave_privada_ec_desde_archivo(ruta_priv, pwd)
                    zch_e2ee.desencriptar_directorio_e2ee_ec(ruta_orig, ruta_dest, priv)
                    imprimir_exito(f"Carpeta restaurada con X25519 en '{ruta_dest}'")
                else:
                    imprimir_error("Método inválido.")
            except Exception as e:
                imprimir_error(f"Error al descifrar carpeta: {e}")
                
        elif opcion == "6":
            print("\n--- Firmar Archivo ---")
            ruta_orig = input("Ruta del archivo a firmar: ").strip()
            if not os.path.exists(ruta_orig):
                imprimir_error("El archivo no existe.")
                continue
            
            print("  a. Llave privada RSA (Firma RSA-PSS)")
            print("  b. Llave privada Ed25519 (Firma EC rápida)")
            tipo = input("Selecciona tipo de firma (a/b): ").strip().lower()
            
            try:
                if tipo == "a":
                    ruta_priv = input("Ruta de la llave privada RSA (.pem): ").strip()
                    pwd = input("Contraseña de la llave privada (Enter si no tiene): ").strip() or None
                    priv = zch_e2ee.cargar_llave_privada_desde_archivo(ruta_priv, pwd)
                    firma = zch_e2ee.firmar_archivo(ruta_orig, priv)
                    print(f"\n📝 Firma digital RSA (Base64):\n{firma}")
                    imprimir_exito("Firma generada correctamente.")
                elif tipo == "b":
                    ruta_priv = input("Ruta de la llave privada Ed25519 (.pem): ").strip()
                    pwd = input("Contraseña de la llave privada (Enter si no tiene): ").strip() or None
                    priv = zch_e2ee.cargar_llave_privada_ec_desde_archivo(ruta_priv, pwd)
                    
                    # Leemos el archivo completo para firmar
                    with open(ruta_orig, 'rb') as f:
                        datos = f.read()
                    firma = zch_e2ee.firmar_mensaje_ed25519(datos.decode('utf-8', errors='ignore'), priv)
                    print(f"\n📝 Firma digital Ed25519 (Base64):\n{firma}")
                    imprimir_exito("Firma Ed25519 generada correctamente.")
                else:
                    imprimir_error("Opción inválida.")
            except Exception as e:
                imprimir_error(f"Error al firmar: {e}")
                
        elif opcion == "7":
            print("\n--- Verificar Firma de Archivo ---")
            ruta_orig = input("Ruta del archivo original: ").strip()
            if not os.path.exists(ruta_orig):
                imprimir_error("El archivo no existe.")
                continue
            firma_b64 = input("Firma digital del archivo (Base64): ").strip()
            
            print("  a. Llave pública RSA")
            print("  b. Llave pública Ed25519 (EC)")
            tipo = input("Selecciona tipo de llave pública (a/b): ").strip().lower()
            
            try:
                if tipo == "a":
                    ruta_pub = input("Ruta de la llave pública RSA (.pem): ").strip()
                    pub = zch_e2ee.cargar_llave_publica_desde_archivo(ruta_pub)
                    es_valido = zch_e2ee.verificar_firma_archivo(ruta_orig, firma_b64, pub)
                elif tipo == "b":
                    ruta_pub = input("Ruta de la llave pública Ed25519 (.pem): ").strip()
                    pub = zch_e2ee.cargar_llave_publica_ec_desde_archivo(ruta_pub)
                    with open(ruta_orig, 'rb') as f:
                        datos = f.read()
                    es_valido = zch_e2ee.verificar_firma_ed25519(datos.decode('utf-8', errors='ignore'), firma_b64, pub)
                else:
                    imprimir_error("Opción inválida.")
                    continue
                
                if es_valido:
                    imprimir_exito("¡LA FIRMA ES VÁLIDA! El archivo es auténtico y no fue modificado.")
                else:
                    imprimir_error("¡LA FIRMA NO ES VÁLIDA! El archivo fue modificado o la firma no corresponde.")
            except Exception as e:
                imprimir_error(f"Error al verificar la firma: {e}")
                
        elif opcion == "8":
            print("\n¡Hasta luego! Mantente seguro. 🔒")
            break
        else:
            imprimir_error("Opción no válida. Ingresa un número del 1 al 8.")

def main():
    parser = argparse.ArgumentParser(description="zch-e2ee CLI — Herramienta de criptografía híbrida y firma digital.")
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")
    
    # Comando gen-keys
    sub_keys = subparsers.add_parser("gen-keys", help="Generar un par de llaves públicas/privadas")
    sub_keys.add_argument("--type", choices=["rsa", "x25519", "ed25519"], required=True, help="Tipo de llave")
    sub_keys.add_argument("--bits", type=int, default=2048, help="Número de bits para llave RSA (default: 2048)")
    sub_keys.add_argument("--out-private", required=True, help="Ruta de guardado de clave privada (.pem)")
    sub_keys.add_argument("--out-public", required=True, help="Ruta de guardado de clave pública (.pem)")
    sub_keys.add_argument("--password", help="Contraseña opcional para cifrar la clave privada")

    # Comando encrypt
    sub_enc = subparsers.add_parser("encrypt", help="Cifrar un archivo")
    sub_enc.add_argument("--in-file", required=True, help="Archivo original a cifrar")
    sub_enc.add_argument("--out-file", required=True, help="Archivo cifrado de salida")
    sub_enc.add_argument("--password", help="Cifrar con contraseña simétrica")
    sub_enc.add_argument("--key-rsa", help="Ruta a clave pública RSA para cifrar")
    sub_enc.add_argument("--key-ec", help="Ruta a clave pública X25519 para cifrar")

    # Comando decrypt
    sub_dec = subparsers.add_parser("decrypt", help="Descifrar un archivo")
    sub_dec.add_argument("--in-file", required=True, help="Archivo cifrado a descifrar")
    sub_dec.add_argument("--out-file", required=True, help="Archivo descifrado de salida")
    sub_dec.add_argument("--password", help="Descifrar usando contraseña")
    sub_dec.add_argument("--key-rsa", help="Ruta a clave privada RSA para descifrar")
    sub_dec.add_argument("--key-ec", help="Ruta a clave privada X25519 para descifrar")
    sub_dec.add_argument("--key-password", help="Contraseña de la clave privada pem si corresponde")

    # Comando interactive
    subparsers.add_parser("interactive", help="Lanza el menú interactivo con formato de consola")

    args = parser.parse_args()
    
    if args.command is None or args.command == "interactive":
        menu_interactivo()
    elif args.command == "gen-keys":
        try:
            if args.type == "rsa":
                priv, pub = zch_e2ee.generar_llaves(args.bits)
                zch_e2ee.guardar_llave_privada_en_archivo(priv, args.out_private, args.password)
                zch_e2ee.guardar_llave_publica_en_archivo(pub, args.out_public)
            elif args.type == "x25519":
                priv, pub = zch_e2ee.generar_llaves_ec()
                zch_e2ee.guardar_llave_privada_ec_en_archivo(priv, args.out_private, args.password)
                zch_e2ee.guardar_llave_publica_ec_en_archivo(pub, args.out_public)
            elif args.type == "ed25519":
                priv, pub = zch_e2ee.generar_llaves_ed25519()
                zch_e2ee.guardar_llave_privada_ec_en_archivo(priv, args.out_private, args.password)
                zch_e2ee.guardar_llave_publica_ec_en_archivo(pub, args.out_public)
            imprimir_exito(f"Par de llaves {args.type} generado exitosamente.")
        except Exception as e:
            imprimir_error(f"Fallo al generar llaves: {e}")
            sys.exit(1)
            
    elif args.command == "encrypt":
        try:
            if args.password:
                zch_e2ee.encriptar_archivo_con_password(args.in_file, args.out_file, args.password)
            elif args.key_rsa:
                pub = zch_e2ee.cargar_llave_publica_desde_archivo(args.key_rsa)
                zch_e2ee.encriptar_archivo_e2ee(args.in_file, args.out_file, pub)
            elif args.key_ec:
                pub = zch_e2ee.cargar_llave_publica_ec_desde_archivo(args.key_ec)
                zch_e2ee.encriptar_archivo_e2ee_ec(args.in_file, args.out_file, pub)
            else:
                imprimir_error("Debe especificar --password, --key-rsa o --key-ec para cifrar.")
                sys.exit(1)
            imprimir_exito(f"Archivo cifrado correctamente guardado en '{args.out_file}'.")
        except Exception as e:
            imprimir_error(f"Fallo al encriptar: {e}")
            sys.exit(1)
            
    elif args.command == "decrypt":
        try:
            if args.password:
                zch_e2ee.desencriptar_archivo_con_password(args.in_file, args.out_file, args.password)
            elif args.key_rsa:
                priv = zch_e2ee.cargar_llave_privada_desde_archivo(args.key_rsa, args.key_password)
                zch_e2ee.desencriptar_archivo_e2ee(args.in_file, args.out_file, priv)
            elif args.key_ec:
                priv = zch_e2ee.cargar_llave_privada_ec_desde_archivo(args.key_ec, args.key_password)
                zch_e2ee.desencriptar_archivo_e2ee_ec(args.in_file, args.out_file, priv)
            else:
                imprimir_error("Debe especificar --password, --key-rsa o --key-ec para descifrar.")
                sys.exit(1)
            imprimir_exito(f"Archivo descifrado correctamente guardado en '{args.out_file}'.")
        except Exception as e:
            imprimir_error(f"Fallo al descifrar: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
