import os
import sys
import json
import argparse
import base64
import zch_e2ee

def imprimir_exito(mensaje, json_mode=False, data_dict=None):
    if json_mode:
        res = {"status": "success", "message": mensaje}
        if data_dict:
            res.update(data_dict)
        print(json.dumps(res))
    else:
        print(f"\n✨ [ÉXITO] {mensaje}")

def imprimir_error(mensaje, json_mode=False):
    if json_mode:
        print(json.dumps({"status": "error", "message": mensaje}), file=sys.stderr)
    else:
        print(f"\n❌ [ERROR] {mensaje}", file=sys.stderr)

def menu_interactivo():
    while True:
        print("\n" + "=" * 70)
        print(" 🔒 zch-e2ee — MENÚ CRIPTOGRÁFICO INTERACTIVO (v1.0.1)")
        print("=" * 70)
        print("  1. 🔑 Generar pares de llaves (RSA, X25519 o Ed25519)")
        print("  2. 📝 Cifrar un archivo (Contraseña o Clave Pública)")
        print("  3. 🔓 Descifrar un archivo (Contraseña o Clave Privada)")
        print("  4. 📁 Cifrar un directorio completo (ZIP cifrado)")
        print("  5. 📂 Descifrar un directorio completo (ZIP descifrado)")
        print("  6. ✍️  Firmar un archivo digitalmente")
        print("  7. 🔍 Verificar firma digital de un archivo")
        print("  8. 🧩 Dividir un secreto (Esquema de Shamir)")
        print("  9. 🤝 Reconstruir un secreto desde sus partes")
        print("  10.🛡️  Cifrar un módulo Python (.py -> .py.enc)")
        print("  11.🚪 Salir")
        print("=" * 70)
        
        opcion = input("Selecciona una opción (1-11): ").strip()
        
        if opcion == "1":
            print("\n--- Generar Llaves ---")
            print("  a. RSA (E2EE clásico y firmas)")
            print("  b. X25519 (E2EE elíptico veloz)")
            print("  c. Ed25519 (Firmas elípticas veloces)")
            tipo = input("Selecciona el tipo de llave (a/b/c): ").strip().lower()
            
            ruta_priv = input("Archivo destino para Llave Privada (default: privada.pem): ").strip() or "privada.pem"
            ruta_pub = input("Archivo destino para Llave Pública (default: publica.pem): ").strip() or "publica.pem"
            pwd = input("Contraseña para cifrar privada (opcional, Enter para omitir): ").strip() or None
            
            try:
                if tipo == "a":
                    bits_str = input("Tamaño de clave RSA (2048 o 4096, default 2048): ").strip()
                    bits = int(bits_str) if bits_str.isdigit() else 2048
                    priv, pub = zch_e2ee.generar_llaves(bits)
                    zch_e2ee.guardar_llave_privada_en_archivo(priv, ruta_priv, pwd)
                    zch_e2ee.guardar_llave_publica_en_archivo(pub, ruta_pub)
                elif tipo == "b":
                    priv, pub = zch_e2ee.generar_llaves_ec()
                    zch_e2ee.guardar_llave_privada_ec_en_archivo(priv, ruta_priv, pwd)
                    zch_e2ee.guardar_llave_publica_ec_en_archivo(pub, ruta_pub)
                elif tipo == "c":
                    priv, pub = zch_e2ee.generar_llaves_ed25519()
                    zch_e2ee.guardar_llave_privada_ec_en_archivo(priv, ruta_priv, pwd)
                    zch_e2ee.guardar_llave_publica_ec_en_archivo(pub, ruta_pub)
                else:
                    imprimir_error("Opción de llave inválida.")
                    continue
                imprimir_exito("Llaves generadas y guardadas correctamente.")
            except Exception as e:
                imprimir_error(f"Fallo al generar llaves: {e}")
                
        elif opcion == "2":
            print("\n--- Cifrar Archivo ---")
            ruta_orig = input("Ruta del archivo a cifrar: ").strip()
            if not os.path.exists(ruta_orig):
                imprimir_error("El archivo de origen no existe.")
                continue
            ruta_dest = input("Ruta del archivo cifrado de salida: ").strip()
            
            print("  a. Contraseña simétrica (Scrypt)")
            print("  b. Llave pública RSA")
            print("  c. Llave pública X25519 (EC)")
            metodo = input("Selecciona método de cifrado (a/b/c): ").strip().lower()
            
            try:
                if metodo == "a":
                    pwd = input("Contraseña de cifrado: ").strip()
                    zch_e2ee.encriptar_archivo_con_password(ruta_orig, ruta_dest, pwd)
                    imprimir_exito(f"Archivo cifrado con contraseña en '{ruta_dest}'")
                elif metodo == "b":
                    ruta_pub = input("Ruta de llave pública RSA (.pem): ").strip()
                    pub = zch_e2ee.cargar_llave_publica_desde_archivo(ruta_pub)
                    zch_e2ee.encriptar_archivo_e2ee(ruta_orig, ruta_dest, pub)
                    imprimir_exito(f"Archivo cifrado con RSA en '{ruta_dest}'")
                elif metodo == "c":
                    ruta_pub = input("Ruta de llave pública X25519 (.pem): ").strip()
                    pub = zch_e2ee.cargar_llave_publica_ec_desde_archivo(ruta_pub)
                    zch_e2ee.encriptar_archivo_e2ee_ec(ruta_orig, ruta_dest, pub)
                    imprimir_exito(f"Archivo cifrado con X25519 en '{ruta_dest}'")
                else:
                    imprimir_error("Método inválido.")
            except Exception as e:
                imprimir_error(f"Error al cifrar: {e}")
                
        elif opcion == "3":
            print("\n--- Descifrar Archivo ---")
            ruta_orig = input("Ruta del archivo cifrado: ").strip()
            if not os.path.exists(ruta_orig):
                imprimir_error("El archivo cifrado no existe.")
                continue
            ruta_dest = input("Ruta del archivo descifrado de salida: ").strip()
            
            print("  a. Contraseña simétrica")
            print("  b. Llave privada RSA")
            print("  c. Llave privada X25519 (EC)")
            metodo = input("Selecciona método de descifrado (a/b/c): ").strip().lower()
            
            try:
                if metodo == "a":
                    pwd = input("Contraseña: ").strip()
                    zch_e2ee.desencriptar_archivo_con_password(ruta_orig, ruta_dest, pwd)
                    imprimir_exito(f"Archivo descifrado en '{ruta_dest}'")
                elif metodo == "b":
                    ruta_priv = input("Ruta de llave privada RSA (.pem): ").strip()
                    pwd = input("Contraseña de la llave pem (Enter si no tiene): ").strip() or None
                    priv = zch_e2ee.cargar_llave_privada_desde_archivo(ruta_priv, pwd)
                    zch_e2ee.desencriptar_archivo_e2ee(ruta_orig, ruta_dest, priv)
                    imprimir_exito(f"Archivo descifrado en '{ruta_dest}'")
                elif metodo == "c":
                    ruta_priv = input("Ruta de llave privada X25519 (.pem): ").strip()
                    pwd = input("Contraseña de la llave pem (Enter si no tiene): ").strip() or None
                    priv = zch_e2ee.cargar_llave_privada_ec_desde_archivo(ruta_priv, pwd)
                    zch_e2ee.desencriptar_archivo_e2ee_ec(ruta_orig, ruta_dest, priv)
                    imprimir_exito(f"Archivo descifrado en '{ruta_dest}'")
                else:
                    imprimir_error("Método inválido.")
            except Exception as e:
                imprimir_error(f"Error al descifrar: {e}")
                
        elif opcion in ("4", "5"):
            print("\n--- Cifrar/Descifrar Directorios ---")
            ruta_orig = input("Ruta de origen (carpeta o archivo .enc): ").strip()
            ruta_dest = input("Ruta de destino: ").strip()
            metodo = input("¿Usar Contraseña (c) o Llaves Asimétricas (l)?: ").strip().lower()
            
            try:
                if opcion == "4":  # Cifrar
                    if metodo == "c":
                        pwd = input("Contraseña de cifrado: ").strip()
                        zch_e2ee.encriptar_directorio_con_password(ruta_orig, ruta_dest, pwd)
                    else:
                        ruta_pub = input("Ruta a clave pública (.pem): ").strip()
                        try:
                            pub = zch_e2ee.cargar_llave_publica_ec_desde_archivo(ruta_pub)
                            zch_e2ee.encriptar_directorio_e2ee_ec(ruta_orig, ruta_dest, pub)
                        except Exception:
                            pub = zch_e2ee.cargar_llave_publica_desde_archivo(ruta_pub)
                            zch_e2ee.encriptar_directorio_e2ee(ruta_orig, ruta_dest, pub)
                    imprimir_exito("Directorio cifrado con éxito.")
                else:  # Descifrar
                    if metodo == "c":
                        pwd = input("Contraseña: ").strip()
                        zch_e2ee.desencriptar_directorio_con_password(ruta_orig, ruta_dest, pwd)
                    else:
                        ruta_priv = input("Ruta a clave privada (.pem): ").strip()
                        pwd = input("Contraseña de la clave pem (Enter si no tiene): ").strip() or None
                        try:
                            priv = zch_e2ee.cargar_llave_privada_ec_desde_archivo(ruta_priv, pwd)
                            zch_e2ee.desencriptar_directorio_e2ee_ec(ruta_orig, ruta_dest, priv)
                        except Exception:
                            priv = zch_e2ee.cargar_llave_privada_desde_archivo(ruta_priv, pwd)
                            zch_e2ee.desencriptar_directorio_e2ee(ruta_orig, ruta_dest, priv)
                    imprimir_exito("Directorio restaurado con éxito.")
            except Exception as e:
                imprimir_error(f"Fallo en directorio: {e}")
                
        elif opcion == "6":
            print("\n--- Firmar Archivo ---")
            ruta_orig = input("Ruta del archivo a firmar: ").strip()
            ruta_priv = input("Ruta de la llave privada (.pem): ").strip()
            pwd = input("Contraseña de la llave pem (Enter si no tiene): ").strip() or None
            
            try:
                try:
                    priv = zch_e2ee.cargar_llave_privada_ec_desde_archivo(ruta_priv, pwd)
                    with open(ruta_orig, 'rb') as f:
                        datos = f.read()
                    firma = zch_e2ee.firmar_mensaje_ed25519(datos.decode('utf-8', errors='ignore'), priv)
                except Exception:
                    priv = zch_e2ee.cargar_llave_privada_desde_archivo(ruta_priv, pwd)
                    firma = zch_e2ee.firmar_archivo(ruta_orig, priv)
                print(f"\n📝 Firma digital (Base64):\n{firma}")
                imprimir_exito("Firma generada correctamente.")
            except Exception as e:
                imprimir_error(f"Fallo al firmar: {e}")
                
        elif opcion == "7":
            print("\n--- Verificar Firma ---")
            ruta_orig = input("Ruta del archivo original: ").strip()
            firma_b64 = input("Firma digital (Base64): ").strip()
            ruta_pub = input("Ruta de la llave pública (.pem): ").strip()
            
            try:
                try:
                    pub = zch_e2ee.cargar_llave_publica_ec_desde_archivo(ruta_pub)
                    with open(ruta_orig, 'rb') as f:
                        datos = f.read()
                    es_valido = zch_e2ee.verificar_firma_ed25519(datos.decode('utf-8', errors='ignore'), firma_b64, pub)
                except Exception:
                    pub = zch_e2ee.cargar_llave_publica_desde_archivo(ruta_pub)
                    es_valido = zch_e2ee.verificar_firma_archivo(ruta_orig, firma_b64, pub)
                
                if es_valido:
                    imprimir_exito("¡LA FIRMA ES TOTALMENTE VÁLIDA!")
                else:
                    imprimir_error("¡LA FIRMA ES INVÁLIDA O EL ARCHIVO FUE ALTERADO!")
            except Exception as e:
                imprimir_error(f"Fallo al verificar: {e}")
                
        elif opcion == "8":
            print("\n--- Dividir Secreto (Shamir) ---")
            secreto = input("Ingresa el secreto de texto a dividir: ").strip().encode('utf-8')
            n = int(input("Número total de partes (N): "))
            t = int(input("Umbral mínimo requerido (T): "))
            
            try:
                partes = zch_e2ee.dividir_secreto_shamir(secreto, n, t)
                print("\n🧩 Partes Generadas (compártelas de forma segura):")
                for idx, datos in partes:
                    parte_b64 = base64.b64encode(datos).decode('utf-8')
                    print(f"  Parte {idx}: {idx}-{parte_b64}")
                imprimir_exito("Secreto dividido correctamente.")
            except Exception as e:
                imprimir_error(f"Fallo al dividir secreto: {e}")
                
        elif opcion == "9":
            print("\n--- Reconstruir Secreto (Shamir) ---")
            print("Ingresa las partes una a una (formato 'X-Base64' o solo pulsa Enter para finalizar):")
            partes = []
            while True:
                entrada = input(f"Parte {len(partes) + 1} (o Enter para terminar): ").strip()
                if not entrada:
                    break
                try:
                    idx_str, parte_b64 = entrada.split("-", 1)
                    idx = int(idx_str)
                    datos = base64.b64decode(parte_b64.encode('utf-8'))
                    partes.append((idx, datos))
                except Exception:
                    print("Formato inválido. Debe ser 'Indice-Base64' (ej: '1-oW4X3r...')")
                    
            if not partes:
                imprimir_error("No ingresaste ninguna parte.")
                continue
            
            try:
                secreto = zch_e2ee.reconstruir_secreto_shamir(partes)
                print(f"\n🔑 Secreto Reconstruido: '{secreto.decode('utf-8', errors='ignore')}'")
                imprimir_exito("Secreto recuperado correctamente.")
            except Exception as e:
                imprimir_error(f"Fallo al reconstruir el secreto: {e}")
                
        elif opcion == "10":
            print("\n--- Cifrar Módulo Python ---")
            ruta_py = input("Ruta del archivo de código .py: ").strip()
            if not os.path.exists(ruta_py):
                imprimir_error("El archivo de código no existe.")
                continue
            ruta_dest = input("Ruta de salida (default: [nombre].py.enc): ").strip()
            if not ruta_dest:
                ruta_dest = ruta_py + ".enc"
            pwd = input("Contraseña del importador: ").strip()
            
            try:
                zch_e2ee.encriptar_modulo_python(ruta_py, ruta_dest, pwd)
                imprimir_exito(f"Módulo Python cifrado guardado en '{ruta_dest}'.")
            except Exception as e:
                imprimir_error(f"Fallo al cifrar módulo: {e}")
                
        elif opcion == "11":
            print("\n¡Hasta luego! Mantente seguro. 🔒")
            break
        else:
            imprimir_error("Opción inválida.")

def main():
    parser = argparse.ArgumentParser(description="zch-e2ee CLI v1.0.1 — Herramienta de criptografía de nivel industrial.")
    parser.add_argument("--json", action="store_true", help="Retorna la salida estructurada en formato JSON.")
    parser.add_argument("--stdin", action="store_true", help="Lee los datos del archivo de entrada desde la entrada estándar (piping).")
    parser.add_argument("--stdout", action="store_true", help="Escribe los datos cifrados o descifrados en la salida estándar.")
    
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")
    
    # gen-keys
    sub_keys = subparsers.add_parser("gen-keys", help="Generar un par de llaves públicas/privadas")
    sub_keys.add_argument("--type", choices=["rsa", "x25519", "ed25519"], required=True, help="Tipo de llave")
    sub_keys.add_argument("--bits", type=int, default=2048, help="Número de bits para RSA (default: 2048)")
    sub_keys.add_argument("--out-private", required=True, help="Ruta de guardado de clave privada (.pem)")
    sub_keys.add_argument("--out-public", required=True, help="Ruta de guardado de clave pública (.pem)")
    sub_keys.add_argument("--password", help="Contraseña opcional para cifrar la clave privada")

    # encrypt
    sub_enc = subparsers.add_parser("encrypt", help="Cifrar un archivo")
    sub_enc.add_argument("--in-file", help="Archivo original a cifrar (omitir si se usa --stdin)")
    sub_enc.add_argument("--out-file", help="Archivo cifrado de salida (omitir si se usa --stdout)")
    sub_enc.add_argument("--password", help="Cifrar con contraseña simétrica")
    sub_enc.add_argument("--key-rsa", help="Llave pública RSA para cifrar")
    sub_enc.add_argument("--key-ec", help="Llave pública X25519 para cifrar")

    # decrypt
    sub_dec = subparsers.add_parser("decrypt", help="Descifrar un archivo")
    sub_dec.add_argument("--in-file", help="Archivo cifrado a descifrar (omitir si se usa --stdin)")
    sub_dec.add_argument("--out-file", help="Archivo descifrado de salida (omitir si se usa --stdout)")
    sub_dec.add_argument("--password", help="Descifrar usando contraseña")
    sub_dec.add_argument("--key-rsa", help="Llave privada RSA para descifrar")
    sub_dec.add_argument("--key-ec", help="Llave privada X25519 para descifrar")
    sub_dec.add_argument("--key-password", help="Contraseña de la llave pem si corresponde")

    # shamir-split
    sub_split = subparsers.add_parser("shamir-split", help="Dividir un secreto usando el esquema de Shamir")
    sub_split.add_argument("--secret", required=True, help="El texto del secreto a dividir")
    sub_split.add_argument("-n", type=int, required=True, help="Número total de partes (N)")
    sub_split.add_argument("-t", type=int, required=True, help="Umbral mínimo requerido (T)")

    # encrypt-module
    sub_mod = subparsers.add_parser("encrypt-module", help="Cifrar un archivo de código Python (.py -> .py.enc)")
    sub_mod.add_argument("--in-py", required=True, help="Ruta del archivo de código .py")
    sub_mod.add_argument("--out-enc", required=True, help="Ruta de guardado .py.enc")
    sub_mod.add_argument("--password", required=True, help="Contraseña para importar el módulo")

    # interactive
    subparsers.add_parser("interactive", help="Lanza el menú interactivo con formato de consola")

    args = parser.parse_args()
    
    if args.command is None or args.command == "interactive":
        menu_interactivo()
        return
        
    if args.command == "gen-keys":
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
            imprimir_exito(f"Par de llaves {args.type} generado.", args.json, {"type": args.type, "private": args.out_private, "public": args.out_public})
        except Exception as e:
            imprimir_error(f"Fallo al generar llaves: {e}", args.json)
            sys.exit(1)
            
    elif args.command == "encrypt":
        try:
            # Si se usa stdin, leemos los datos desde sys.stdin.buffer
            if args.stdin:
                datos = sys.stdin.buffer.read()
            else:
                with open(args.in_file, 'rb') as f:
                    datos = f.read()
            
            # Cifrado en memoria temporalmente
            temp_in = tempfile.NamedTemporaryFile(delete=False)
            temp_out = tempfile.NamedTemporaryFile(delete=False)
            try:
                temp_in.write(datos)
                temp_in.close()
                temp_out.close()
                
                if args.password:
                    zch_e2ee.encriptar_archivo_con_password(temp_in.name, temp_out.name, args.password)
                elif args.key_rsa:
                    pub = zch_e2ee.cargar_llave_publica_desde_archivo(args.key_rsa)
                    zch_e2ee.encriptar_archivo_e2ee(temp_in.name, temp_out.name, pub)
                elif args.key_ec:
                    pub = zch_e2ee.cargar_llave_publica_ec_desde_archivo(args.key_ec)
                    zch_e2ee.encriptar_archivo_e2ee_ec(temp_in.name, temp_out.name, pub)
                else:
                    imprimir_error("Debe especificar --password, --key-rsa o --key-ec para cifrar.", args.json)
                    sys.exit(1)
                    
                with open(temp_out.name, 'rb') as f:
                    datos_cifrados = f.read()
            finally:
                for t in [temp_in.name, temp_out.name]:
                    if os.path.exists(t):
                        os.remove(t)
            
            if args.stdout:
                sys.stdout.buffer.write(datos_cifrados)
            else:
                with open(args.out_file, 'wb') as f:
                    f.write(datos_cifrados)
                imprimir_exito(f"Archivo cifrado guardado en '{args.out_file}'.", args.json, {"out_file": args.out_file})
        except Exception as e:
            imprimir_error(f"Fallo al cifrar: {e}", args.json)
            sys.exit(1)
            
    elif args.command == "decrypt":
        try:
            if args.stdin:
                datos = sys.stdin.buffer.read()
            else:
                with open(args.in_file, 'rb') as f:
                    datos = f.read()
            
            temp_in = tempfile.NamedTemporaryFile(delete=False)
            temp_out = tempfile.NamedTemporaryFile(delete=False)
            try:
                temp_in.write(datos)
                temp_in.close()
                temp_out.close()
                
                if args.password:
                    zch_e2ee.desencriptar_archivo_con_password(temp_in.name, temp_out.name, args.password)
                elif args.key_rsa:
                    priv = zch_e2ee.cargar_llave_privada_desde_archivo(args.key_rsa, args.key_password)
                    zch_e2ee.desencriptar_archivo_e2ee(temp_in.name, temp_out.name, priv)
                elif args.key_ec:
                    priv = zch_e2ee.cargar_llave_privada_ec_desde_archivo(args.key_ec, args.key_password)
                    zch_e2ee.desencriptar_archivo_e2ee_ec(temp_in.name, temp_out.name, priv)
                else:
                    imprimir_error("Debe especificar --password, --key-rsa o --key-ec.", args.json)
                    sys.exit(1)
                    
                with open(temp_out.name, 'rb') as f:
                    datos_descifrados = f.read()
            finally:
                for t in [temp_in.name, temp_out.name]:
                    if os.path.exists(t):
                        os.remove(t)
            
            if args.stdout:
                sys.stdout.buffer.write(datos_descifrados)
            else:
                with open(args.out_file, 'wb') as f:
                    f.write(datos_descifrados)
                imprimir_exito(f"Archivo descifrado guardado en '{args.out_file}'.", args.json, {"out_file": args.out_file})
        except Exception as e:
            imprimir_error(f"Fallo al descifrar: {e}", args.json)
            sys.exit(1)
            
    elif args.command == "shamir-split":
        try:
            secreto = args.secret.encode('utf-8')
            partes = zch_e2ee.dividir_secreto_shamir(secreto, args.n, args.t)
            res_dict = {}
            for idx, datos in partes:
                parte_b64 = base64.b64encode(datos).decode('utf-8')
                res_dict[str(idx)] = f"{idx}-{parte_b64}"
            imprimir_exito("Secreto dividido.", args.json, {"shares": res_dict})
        except Exception as e:
            imprimir_error(f"Fallo al dividir: {e}", args.json)
            sys.exit(1)
            
    elif args.command == "encrypt-module":
        try:
            zch_e2ee.encriptar_modulo_python(args.in_py, args.out_enc, args.password)
            imprimir_exito(f"Módulo Python cifrado.", args.json, {"out_enc": args.out_enc})
        except Exception as e:
            imprimir_error(f"Fallo al cifrar módulo: {e}", args.json)
            sys.exit(1)

if __name__ == "__main__":
    main()
