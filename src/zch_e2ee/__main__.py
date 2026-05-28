import os
import sys
import json
import argparse
import base64
import tempfile
import zch_e2ee
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519, rsa

def serializar_sesion_ratchet(sesion):
    dhp_pem = sesion.dhp.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    dhr_raw = sesion.dhr.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()
    
    dh_local_pem = sesion.dh_local.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    last_dh_remota_raw = None
    if sesion.last_dh_remota:
        last_dh_remota_raw = sesion.last_dh_remota.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()
        
    return {
        "dhp_pem": dhp_pem,
        "dhr_raw": dhr_raw,
        "es_iniciador": sesion.es_iniciador,
        "dh_local_pem": dh_local_pem,
        "rk_hex": sesion.rk.hex(),
        "ck_send_hex": sesion.ck_send.hex() if sesion.ck_send else None,
        "ck_recv_hex": sesion.ck_recv.hex() if sesion.ck_recv else None,
        "last_dh_remota_raw": last_dh_remota_raw
    }

def deserializar_sesion_ratchet(data):
    dhp = serialization.load_pem_private_key(data["dhp_pem"].encode('utf-8'), password=None)
    dhr = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(data["dhr_raw"]))
    
    sesion = zch_e2ee.SesionDoubleRatchet(dhp, dhr, data["es_iniciador"])
    
    sesion.dh_local = serialization.load_pem_private_key(data["dh_local_pem"].encode('utf-8'), password=None)
    sesion.rk = bytes.fromhex(data["rk_hex"])
    sesion.ck_send = bytes.fromhex(data["ck_send_hex"]) if data["ck_send_hex"] else None
    sesion.ck_recv = bytes.fromhex(data["ck_recv_hex"]) if data["ck_recv_hex"] else None
    
    if data["last_dh_remota_raw"]:
        sesion.last_dh_remota = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(data["last_dh_remota_raw"]))
    else:
        sesion.last_dh_remota = None
        
    return sesion

def imprimir_exito(mensaje, json_mode=False, data_dict=None):
    if json_mode:
        res = {"status": "success", "message": mensaje}
        if data_dict:
            res.update(data_dict)
        print(json.dumps(res))
    else:
        print(f"\n[ÉXITO] {mensaje}")

def imprimir_error(mensaje, json_mode=False):
    if json_mode:
        print(json.dumps({"status": "error", "message": mensaje}), file=sys.stderr)
    else:
        print(f"\n[ERROR] {mensaje}", file=sys.stderr)

def menu_interactivo():
    while True:
        print("\n" + "=" * 70)
        print(" zch-e2ee — MENÚ CRIPTOGRÁFICO INTERACTIVO (v1.1.4)")
        print("=" * 70)
        print("  1. Generar pares de llaves (RSA, X25519 o Ed25519)")
        print("  2. Cifrar un archivo (Contraseña o Clave Pública)")
        print("  3. Descifrar un archivo (Contraseña o Clave Privada)")
        print("  4. Cifrar un directorio completo (ZIP cifrado)")
        print("  5. Descifrar un directorio completo (ZIP descifrado)")
        print("  6. Firmar un archivo digitalmente")
        print("  7. Verificar firma digital de un archivo")
        print("  8. Dividir un secreto (Esquema de Shamir)")
        print("  9. Reconstruir un secreto desde sus partes")
        print("  10. Cifrar un módulo Python (.py -> .py.enc)")
        print("  11. Gestionar llavero criptográfico (Keystore)")
        print("  12. Cifrar o descifrar texto directo")
        print("  13. Calcular o verificar hash SHA-256 de archivo")
        print("  14. Calcular o verificar HMAC de archivo")
        print("  15. Simular sesión interactiva de Double Ratchet")
        print("  16. Cifrar un archivo para múltiples destinatarios")
        print("  17. Descifrar un archivo multi-destinatario")
        print("  18. Cifrar un texto para múltiples destinatarios")
        print("  19. Descifrar un texto multi-destinatario")
        print("  20. Cifrar un directorio completo para múltiples destinatarios")
        print("  21. Descifrar un directorio completo multi-destinatario")
        print("  22. Salir")
        print("=" * 70)
        
        opcion = input("Selecciona una opción (1-22): ").strip()
        
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
                print(f"\nFirma digital (Base64):\n{firma}")
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
                print("\nPartes Generadas (compártelas de forma segura):")
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
                print(f"\nSecreto Reconstruido: '{secreto.decode('utf-8', errors='ignore')}'")
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
            print("\n--- Gestionar Llavero Criptográfico (Keystore) ---")
            print("  a. Crear un llavero vacío (.json)")
            print("  b. Listar alias en un llavero")
            print("  c. Agregar una clave (.pem) al llavero")
            print("  d. Exportar una clave a un archivo (.pem)")
            print("  e. Respaldar llavero completo (Backup)")
            print("  f. Restaurar llavero desde respaldo (Restore)")
            sub_opc = input("Selecciona una opción (a/b/c/d/e/f): ").strip().lower()
            
            if sub_opc == "a":
                ruta_ks = input("Ruta del nuevo llavero (ej: llavero.json): ").strip()
                pwd = input("Contraseña maestra del llavero: ").strip()
                try:
                    zch_e2ee.KeystoreZCH.crear(ruta_ks, pwd)
                    imprimir_exito(f"Llavero creado en '{ruta_ks}'.")
                except Exception as e:
                    imprimir_error(f"Error al crear llavero: {e}")
                    
            elif sub_opc == "b":
                ruta_ks = input("Ruta del llavero: ").strip()
                pwd = input("Contraseña maestra: ").strip()
                try:
                    ks = zch_e2ee.KeystoreZCH.cargar(ruta_ks, pwd)
                    aliases = ks.listar_alias()
                    print("\n--- ALIAS EN LLAVERO ---")
                    print("Claves Privadas Propias:")
                    for a in aliases["claves_privadas"]:
                        print(f"  - {a}")
                    print("\nClaves Públicas de Contactos:")
                    for a in aliases["claves_publicas"]:
                        print(f"  - {a}")
                    imprimir_exito("Alias listados correctamente.")
                except Exception as e:
                    imprimir_error(f"Error al listar: {e}")
                    
            elif sub_opc == "c":
                ruta_ks = input("Ruta del llavero: ").strip()
                pwd = input("Contraseña maestra: ").strip()
                alias = input("Alias para registrar la clave: ").strip()
                ruta_key = input("Ruta del archivo PEM de la clave: ").strip()
                tipo = input("¿Es clave pública (u) o privada (r)?: ").strip().lower()
                
                try:
                    ks = zch_e2ee.KeystoreZCH.cargar(ruta_ks, pwd)
                    with open(ruta_key, 'r', encoding='utf-8') as f:
                        pem_str = f.read()
                        
                    if tipo == "r":
                        pwd_pem = input("Contraseña de la clave privada PEM (Enter si no tiene): ").strip() or None
                        try:
                            clave = zch_e2ee.cargar_llave_privada_ec(pem_str, pwd_pem)
                        except Exception:
                            clave = zch_e2ee.cargar_llave_privada(pem_str, pwd_pem)
                        ks.guardar_clave_propia(alias, clave)
                    else:
                        try:
                            clave = zch_e2ee.cargar_llave_publica_ec(pem_str)
                        except Exception:
                            clave = zch_e2ee.cargar_llave_publica(pem_str)
                        ks.guardar_clave_contacto(alias, clave)
                        
                    ks.guardar(ruta_ks, pwd)
                    imprimir_exito(f"Clave guardada bajo el alias '{alias}'.")
                except Exception as e:
                    imprimir_error(f"Error al agregar clave: {e}")
                    
            elif sub_opc == "d":
                ruta_ks = input("Ruta del llavero: ").strip()
                pwd = input("Contraseña maestra: ").strip()
                alias = input("Alias de la clave a exportar: ").strip()
                ruta_dest = input("Ruta de destino del archivo PEM: ").strip()
                tipo = input("¿Es clave pública (u) o privada (r)?: ").strip().lower()
                
                try:
                    ks = zch_e2ee.KeystoreZCH.cargar(ruta_ks, pwd)
                    if tipo == "r":
                        clave = ks.obtener_clave_privada(alias)
                        pwd_pem = input("Contraseña para cifrar el archivo PEM (Enter para no cifrar): ").strip() or None
                        try:
                            zch_e2ee.guardar_llave_privada_ec_en_archivo(clave, ruta_dest, pwd_pem)
                        except Exception:
                            zch_e2ee.guardar_llave_privada_en_archivo(clave, ruta_dest, pwd_pem)
                    else:
                        clave = ks.obtener_clave_contacto(alias)
                        try:
                            zch_e2ee.guardar_llave_publica_ec_en_archivo(clave, ruta_dest)
                        except Exception:
                            zch_e2ee.guardar_llave_publica_en_archivo(clave, ruta_dest)
                            
                    imprimir_exito(f"Clave '{alias}' exportada con éxito en '{ruta_dest}'.")
                except Exception as e:
                    imprimir_error(f"Error al exportar: {e}")
            elif sub_opc == "e":
                ruta_ks = input("Ruta del llavero: ").strip()
                pwd = input("Contraseña maestra del llavero: ").strip()
                ruta_bak = input("Ruta de destino del respaldo (.json / .bak): ").strip()
                pwd_bak = input("Contraseña de cifrado para el respaldo: ").strip()
                try:
                    ks = zch_e2ee.KeystoreZCH.cargar(ruta_ks, pwd)
                    data = {
                        "claves_privadas": ks.claves_privadas,
                        "claves_publicas": ks.claves_publicas
                    }
                    datos_json = json.dumps(data)
                    backup_b64 = zch_e2ee.encriptar_con_password(datos_json, pwd_bak)
                    with open(ruta_bak, 'w', encoding='utf-8') as f:
                        f.write(backup_b64)
                    imprimir_exito(f"Respaldo cifrado creado con éxito en '{ruta_bak}'.")
                except Exception as e:
                    imprimir_error(f"Error al respaldar llavero: {e}")

            elif sub_opc == "f":
                ruta_ks = input("Ruta del llavero destino: ").strip()
                pwd = input("Contraseña maestra del llavero destino: ").strip()
                ruta_bak = input("Ruta del archivo de respaldo: ").strip()
                pwd_bak = input("Contraseña de cifrado del respaldo: ").strip()
                try:
                    with open(ruta_bak, 'r', encoding='utf-8') as f:
                        backup_b64 = f.read()
                    datos_json = zch_e2ee.desencriptar_con_password(backup_b64, pwd_bak)
                    data = json.loads(datos_json)
                    
                    if os.path.exists(ruta_ks):
                        try:
                            ks = zch_e2ee.KeystoreZCH.cargar(ruta_ks, pwd)
                        except Exception:
                            ks = zch_e2ee.KeystoreZCH()
                    else:
                        ks = zch_e2ee.KeystoreZCH()
                        
                    ks.claves_privadas.update(data.get("claves_privadas", {}))
                    ks.claves_publicas.update(data.get("claves_publicas", {}))
                    ks.guardar(ruta_ks, pwd)
                    imprimir_exito(f"Llavero restaurado y actualizado con éxito en '{ruta_ks}'.")
                except Exception as e:
                    imprimir_error(f"Error al restaurar llavero: {e}")
            else:
                imprimir_error("Opción de submenú inválida.")
                
        elif opcion == "12":
            print("\n--- Cifrar o Descifrar Texto Directo ---")
            print("  a. Cifrar texto")
            print("  b. Descifrar texto")
            sub_opc = input("Selecciona una opción (a/b): ").strip().lower()
            
            if sub_opc == "a":
                texto = input("Ingresa el texto a cifrar: ")
                print("  1. Contraseña simétrica (Scrypt)")
                print("  2. Llave pública RSA")
                print("  3. Llave pública X25519 (EC)")
                metodo = input("Selecciona método de cifrado (1/2/3): ").strip()
                
                try:
                    if metodo == "1":
                        pwd = input("Contraseña de cifrado: ").strip()
                        cifrado = zch_e2ee.encriptar_con_password(texto, pwd)
                        print(f"\nTexto cifrado (Base64):\n{cifrado}")
                        imprimir_exito("Texto cifrado correctamente.")
                    elif metodo == "2":
                        ruta_pub = input("Ruta de llave pública RSA (.pem): ").strip()
                        pub = zch_e2ee.cargar_llave_publica_desde_archivo(ruta_pub)
                        cifrado = zch_e2ee.encriptar_e2ee(texto, pub)
                        print(f"\nTexto cifrado (Base64):\n{cifrado}")
                        imprimir_exito("Texto cifrado correctamente.")
                    elif metodo == "3":
                        ruta_pub = input("Ruta de llave pública X25519 (.pem): ").strip()
                        pub = zch_e2ee.cargar_llave_publica_ec_desde_archivo(ruta_pub)
                        cifrado = zch_e2ee.encriptar_e2ee_ec(texto, pub)
                        print(f"\nTexto cifrado (Base64):\n{cifrado}")
                        imprimir_exito("Texto cifrado correctamente.")
                    else:
                        imprimir_error("Método inválido.")
                except Exception as e:
                    imprimir_error(f"Error al cifrar texto: {e}")

            elif sub_opc == "b":
                texto_cifrado = input("Ingresa el texto cifrado (Base64): ").strip()
                print("  1. Contraseña simétrica")
                print("  2. Llave privada RSA")
                print("  3. Llave privada X25519 (EC)")
                metodo = input("Selecciona método de descifrado (1/2/3): ").strip()
                
                try:
                    if metodo == "1":
                        pwd = input("Contraseña: ").strip()
                        descifrado = zch_e2ee.desencriptar_con_password(texto_cifrado, pwd)
                        print(f"\nTexto descifrado:\n{descifrado}")
                        imprimir_exito("Texto descifrado correctamente.")
                    elif metodo == "2":
                        ruta_priv = input("Ruta de llave privada RSA (.pem): ").strip()
                        pwd = input("Contraseña de la llave pem (Enter si no tiene): ").strip() or None
                        priv = zch_e2ee.cargar_llave_privada_desde_archivo(ruta_priv, pwd)
                        descifrado = zch_e2ee.desencriptar_e2ee(texto_cifrado, priv)
                        print(f"\nTexto descifrado:\n{descifrado}")
                        imprimir_exito("Texto descifrado correctamente.")
                    elif metodo == "3":
                        ruta_priv = input("Ruta de llave privada X25519 (.pem): ").strip()
                        pwd = input("Contraseña de la llave pem (Enter si no tiene): ").strip() or None
                        priv = zch_e2ee.cargar_llave_privada_ec_desde_archivo(ruta_priv, pwd)
                        descifrado = zch_e2ee.desencriptar_e2ee_ec(texto_cifrado, priv)
                        print(f"\nTexto descifrado:\n{descifrado}")
                        imprimir_exito("Texto descifrado correctamente.")
                    else:
                        imprimir_error("Método inválido.")
                except Exception as e:
                    imprimir_error(f"Error al descifrar texto: {e}")
            else:
                imprimir_error("Opción de submenú inválida.")

        elif opcion == "13":
            print("\n--- Calcular o Verificar Hash SHA-256 de Archivo ---")
            print("  a. Calcular hash SHA-256")
            print("  b. Verificar hash SHA-256")
            sub_opc = input("Selecciona una opción (a/b): ").strip().lower()
            
            ruta_archivo = input("Ruta del archivo: ").strip()
            if not os.path.exists(ruta_archivo):
                imprimir_error("El archivo no existe.")
                continue
                
            try:
                hash_val = zch_e2ee.calcular_sha256(ruta_archivo)
                if sub_opc == "a":
                    print(f"\nHash SHA-256: {hash_val}")
                    imprimir_exito("Hash calculado correctamente.")
                elif sub_opc == "b":
                    expected = input("Ingresa el hash SHA-256 esperado (hex): ").strip()
                    if hash_val.lower().strip() == expected.lower().strip():
                        imprimir_exito("El checksum del archivo es valido.")
                    else:
                        imprimir_error("El checksum del archivo es invalido o el archivo fue modificado.")
                else:
                    imprimir_error("Opción de submenú inválida.")
            except Exception as e:
                imprimir_error(f"Fallo al procesar hash: {e}")

        elif opcion == "14":
            print("\n--- Calcular o Verificar HMAC de Archivo ---")
            print("  a. Calcular HMAC-SHA256")
            print("  b. Verificar HMAC-SHA256")
            sub_opc = input("Selecciona una opción (a/b): ").strip().lower()
            
            ruta_archivo = input("Ruta del archivo: ").strip()
            if not os.path.exists(ruta_archivo):
                imprimir_error("El archivo no existe.")
                continue
                
            key_str = input("Ingresa la clave/contraseña simétrica: ").strip()
            if not key_str:
                imprimir_error("La clave no puede estar vacía.")
                continue
                
            try:
                with open(ruta_archivo, 'rb') as f:
                    datos = f.read()
                key_bytes = key_str.encode('utf-8')
                
                if sub_opc == "a":
                    hmac_bytes = zch_e2ee.calcular_hmac(datos, key_bytes)
                    print(f"\nHMAC-SHA256 (hex): {hmac_bytes.hex()}")
                    imprimir_exito("HMAC calculado correctamente.")
                elif sub_opc == "b":
                    expected_hex = input("Ingresa el HMAC esperado (hex): ").strip()
                    try:
                        expected_bytes = bytes.fromhex(expected_hex.strip())
                    except ValueError:
                        imprimir_error("El valor HMAC esperado debe ser hexadecimal válido.")
                        continue
                        
                    es_valido = zch_e2ee.verificar_hmac(datos, expected_bytes, key_bytes)
                    if es_valido:
                        imprimir_exito("El HMAC es totalmente valido.")
                    else:
                        imprimir_error("El HMAC es invalido o el archivo fue modificado.")
                else:
                    imprimir_error("Opción de submenú inválida.")
            except Exception as e:
                imprimir_error(f"Fallo al procesar HMAC: {e}")

        elif opcion == "15":
            print("\n--- Simulación Interactiva de Double Ratchet ---")
            print("Generando llaves efímeras para Alice y Bob...")
            try:
                priv_alice, pub_alice = zch_e2ee.generar_llaves_ec()
                priv_bob, pub_bob = zch_e2ee.generar_llaves_ec()
                
                sesion_alice = zch_e2ee.SesionDoubleRatchet(priv_alice, pub_bob, es_iniciador=True)
                sesion_bob = zch_e2ee.SesionDoubleRatchet(priv_bob, pub_alice, es_iniciador=False)
                
                print("Sesiones inicializadas correctamente.")
                while True:
                    print("\nAcciones disponibles:")
                    print("  1. Alice envía mensaje a Bob")
                    print("  2. Bob envía mensaje a Alice")
                    print("  3. Volver al menú principal")
                    sub_opt = input("Selecciona acción (1-3): ").strip()
                    
                    if sub_opt == "1":
                        texto = input("Mensaje de Alice para Bob: ")
                        cifrado = sesion_alice.enviar_mensaje(texto)
                        print(f"Mensaje cifrado (Base64):\n{cifrado}")
                        descifrado = sesion_bob.recibir_mensaje(cifrado)
                        print(f"Bob descifró con éxito: {descifrado}")
                    elif sub_opt == "2":
                        texto = input("Mensaje de Bob para Alice: ")
                        cifrado = sesion_bob.enviar_mensaje(texto)
                        print(f"Mensaje cifrado (Base64):\n{cifrado}")
                        descifrado = sesion_alice.recibir_mensaje(cifrado)
                        print(f"Alice descifró con éxito: {descifrado}")
                    elif sub_opt == "3":
                        break
                    else:
                        imprimir_error("Acción inválida.")
            except Exception as e:
                imprimir_error(f"Error en la simulación: {e}")

        elif opcion == "16":
            print("\n--- Cifrar Archivo Multi-destinatario ---")
            ruta_orig = input("Ruta del archivo origen: ").strip()
            if not os.path.exists(ruta_orig) or os.path.isdir(ruta_orig):
                imprimir_error("El archivo de origen no existe o es una carpeta.")
                continue
            ruta_dest = input("Ruta del archivo cifrado de salida: ").strip()
            
            print("  a. Cargar llaves públicas (.pem) desde archivos")
            print("  b. Cargar llaves públicas desde un Keystore")
            modo_llaves = input("Selecciona opción (a/b): ").strip().lower()
            
            try:
                llaves_publicas = []
                if modo_llaves == "a":
                    rutas_str = input("Ingresa las rutas de las llaves públicas (.pem) separadas por comas: ").strip()
                    for r in rutas_str.split(","):
                        r = r.strip()
                        if r:
                            try:
                                pub = zch_e2ee.cargar_llave_publica_ec_desde_archivo(r)
                            except Exception:
                                pub = zch_e2ee.cargar_llave_publica_desde_archivo(r)
                            llaves_publicas.append(pub)
                elif modo_llaves == "b":
                    ruta_ks = input("Ruta del Keystore (.json): ").strip()
                    pwd_ks = input("Contraseña del Keystore: ").strip()
                    ks = zch_e2ee.KeystoreZCH.cargar(ruta_ks, pwd_ks)
                    aliases_str = input("Ingresa los alias de contacto separados por comas: ").strip()
                    for a in aliases_str.split(","):
                        a = a.strip()
                        if a:
                            pub = ks.obtener_clave_contacto(a)
                            llaves_publicas.append(pub)
                else:
                    imprimir_error("Opción inválida.")
                    continue
                
                if not llaves_publicas:
                    imprimir_error("No se ingresaron llaves públicas válidas.")
                    continue
                    
                zch_e2ee.encriptar_archivo_e2ee_multi(ruta_orig, ruta_dest, llaves_publicas)
                imprimir_exito("Archivo cifrado para múltiples destinatarios con éxito.")
            except Exception as e:
                imprimir_error(f"Fallo al cifrar archivo: {e}")
                
        elif opcion == "17":
            print("\n--- Descifrar Archivo Multi-destinatario ---")
            ruta_orig = input("Ruta del archivo cifrado: ").strip()
            if not os.path.exists(ruta_orig):
                imprimir_error("El archivo cifrado no existe.")
                continue
            ruta_dest = input("Ruta del archivo descifrado de salida: ").strip()
            
            print("  a. Cargar llave privada (.pem) desde archivo")
            print("  b. Cargar llave privada desde un Keystore")
            modo_llave = input("Selecciona opción (a/b): ").strip().lower()
            
            try:
                priv = None
                key_alias = None
                ruta_ks = None
                pwd_ks = None
                
                if modo_llave == "a":
                    ruta_priv = input("Ruta de la llave privada: ").strip()
                    pwd = input("Contraseña de la llave (Enter si no tiene): ").strip() or None
                    try:
                        priv = zch_e2ee.cargar_llave_privada_ec_desde_archivo(ruta_priv, pwd)
                    except Exception:
                        priv = zch_e2ee.cargar_llave_privada_desde_archivo(ruta_priv, pwd)
                elif modo_llave == "b":
                    ruta_ks = input("Ruta del Keystore (.json): ").strip()
                    pwd_ks = input("Contraseña del Keystore: ").strip()
                    ks = zch_e2ee.KeystoreZCH.cargar(ruta_ks, pwd_ks)
                    key_alias = input("Alias de tu llave privada: ").strip()
                    priv = ks.obtener_clave_privada(key_alias)
                else:
                    imprimir_error("Opción inválida.")
                    continue
                
                if not priv:
                    imprimir_error("No se pudo cargar la llave privada.")
                    continue
                    
                exito = False
                try:
                    zch_e2ee.desencriptar_archivo_e2ee_multi(ruta_orig, ruta_dest, priv)
                    exito = True
                except (zch_e2ee.ErrorDescifrado, zch_e2ee.CriptoError):
                    if key_alias and ruta_ks and pwd_ks:
                        ks = zch_e2ee.KeystoreZCH.cargar(ruta_ks, pwd_ks)
                        historial = ks.obtener_historial_clave_privada(key_alias)
                        for priv_hist in historial:
                            try:
                                zch_e2ee.desencriptar_archivo_e2ee_multi(ruta_orig, ruta_dest, priv_hist)
                                exito = True
                                break
                            except Exception:
                                continue
                if not exito:
                    raise zch_e2ee.ErrorDescifrado("Fallo al descifrar el archivo multi-destinatario (incluso usando historial de claves).")
                imprimir_exito("Archivo descifrado con éxito.")
            except Exception as e:
                imprimir_error(f"Fallo al descifrar archivo: {e}")

        elif opcion == "18":
            print("\n--- Cifrar Texto Multi-destinatario ---")
            texto = input("Ingresa el texto a cifrar: ")
            
            print("  a. Cargar llaves públicas (.pem) desde archivos")
            print("  b. Cargar llaves públicas desde un Keystore")
            modo_llaves = input("Selecciona opción (a/b): ").strip().lower()
            
            try:
                llaves_publicas = []
                if modo_llaves == "a":
                    rutas_str = input("Ingresa las rutas de las llaves públicas (.pem) separadas por comas: ").strip()
                    for r in rutas_str.split(","):
                        r = r.strip()
                        if r:
                            try:
                                pub = zch_e2ee.cargar_llave_publica_ec_desde_archivo(r)
                            except Exception:
                                pub = zch_e2ee.cargar_llave_publica_desde_archivo(r)
                            llaves_publicas.append(pub)
                elif modo_llaves == "b":
                    ruta_ks = input("Ruta del Keystore (.json): ").strip()
                    pwd_ks = input("Contraseña del Keystore: ").strip()
                    ks = zch_e2ee.KeystoreZCH.cargar(ruta_ks, pwd_ks)
                    aliases_str = input("Ingresa los alias de contacto separados por comas: ").strip()
                    for a in aliases_str.split(","):
                        a = a.strip()
                        if a:
                            pub = ks.obtener_clave_contacto(a)
                            llaves_publicas.append(pub)
                else:
                    imprimir_error("Opción inválida.")
                    continue
                
                if not llaves_publicas:
                    imprimir_error("No se ingresaron llaves públicas válidas.")
                    continue
                    
                cifrado = zch_e2ee.encriptar_e2ee_multi(texto, llaves_publicas)
                print("\nTexto cifrado en Base64:")
                print(cifrado)
                imprimir_exito("Texto cifrado con éxito.")
            except Exception as e:
                imprimir_error(f"Fallo al cifrar texto: {e}")

        elif opcion == "19":
            print("\n--- Descifrar Texto Multi-destinatario ---")
            texto_cifrado = input("Ingresa el texto cifrado (Base64): ").strip()
            
            print("  a. Cargar llave privada (.pem) desde archivo")
            print("  b. Cargar llave privada desde un Keystore")
            modo_llave = input("Selecciona opción (a/b): ").strip().lower()
            
            try:
                priv = None
                key_alias = None
                ruta_ks = None
                pwd_ks = None
                
                if modo_llave == "a":
                    ruta_priv = input("Ruta de la llave privada: ").strip()
                    pwd = input("Contraseña de la llave (Enter si no tiene): ").strip() or None
                    try:
                        priv = zch_e2ee.cargar_llave_privada_ec_desde_archivo(ruta_priv, pwd)
                    except Exception:
                        priv = zch_e2ee.cargar_llave_privada_desde_archivo(ruta_priv, pwd)
                elif modo_llave == "b":
                    ruta_ks = input("Ruta del Keystore (.json): ").strip()
                    pwd_ks = input("Contraseña del Keystore: ").strip()
                    ks = zch_e2ee.KeystoreZCH.cargar(ruta_ks, pwd_ks)
                    key_alias = input("Alias de tu llave privada: ").strip()
                    priv = ks.obtener_clave_privada(key_alias)
                else:
                    imprimir_error("Opción inválida.")
                    continue
                
                if not priv:
                    imprimir_error("No se pudo cargar la llave privada.")
                    continue
                    
                exito = False
                descifrado = None
                try:
                    descifrado = zch_e2ee.desencriptar_e2ee_multi(texto_cifrado, priv)
                    exito = True
                except (zch_e2ee.ErrorDescifrado, zch_e2ee.CriptoError):
                    if key_alias and ruta_ks and pwd_ks:
                        ks = zch_e2ee.KeystoreZCH.cargar(ruta_ks, pwd_ks)
                        historial = ks.obtener_historial_clave_privada(key_alias)
                        for priv_hist in historial:
                            try:
                                descifrado = zch_e2ee.desencriptar_e2ee_multi(texto_cifrado, priv_hist)
                                exito = True
                                break
                            except Exception:
                                continue
                if not exito:
                    raise zch_e2ee.ErrorDescifrado("Fallo al descifrar el texto (incluso usando historial de claves).")
                print("\nTexto descifrado:")
                print(descifrado)
                imprimir_exito("Texto descifrado con éxito.")
            except Exception as e:
                imprimir_error(f"Fallo al descifrar texto: {e}")

        elif opcion == "20":
            print("\n--- Cifrar Directorio Multi-destinatario ---")
            ruta_orig = input("Ruta del directorio origen: ").strip()
            if not os.path.exists(ruta_orig) or not os.path.isdir(ruta_orig):
                imprimir_error("El directorio de origen no existe o no es una carpeta.")
                continue
            ruta_dest = input("Ruta del archivo cifrado de salida: ").strip()
            
            print("  a. Cargar llaves públicas (.pem) desde archivos")
            print("  b. Cargar llaves públicas desde un Keystore")
            modo_llaves = input("Selecciona opción (a/b): ").strip().lower()
            
            try:
                llaves_publicas = []
                if modo_llaves == "a":
                    rutas_str = input("Ingresa las rutas de las llaves públicas (.pem) separadas por comas: ").strip()
                    for r in rutas_str.split(","):
                        r = r.strip()
                        if r:
                            try:
                                pub = zch_e2ee.cargar_llave_publica_ec_desde_archivo(r)
                            except Exception:
                                pub = zch_e2ee.cargar_llave_publica_desde_archivo(r)
                            llaves_publicas.append(pub)
                elif modo_llaves == "b":
                    ruta_ks = input("Ruta del Keystore (.json): ").strip()
                    pwd_ks = input("Contraseña del Keystore: ").strip()
                    ks = zch_e2ee.KeystoreZCH.cargar(ruta_ks, pwd_ks)
                    aliases_str = input("Ingresa los alias de contacto separados por comas: ").strip()
                    for a in aliases_str.split(","):
                        a = a.strip()
                        if a:
                            pub = ks.obtener_clave_contacto(a)
                            llaves_publicas.append(pub)
                else:
                    imprimir_error("Opción inválida.")
                    continue
                
                if not llaves_publicas:
                    imprimir_error("No se ingresaron llaves públicas válidas.")
                    continue
                    
                zch_e2ee.encriptar_directorio_e2ee_multi(ruta_orig, ruta_dest, llaves_publicas)
                imprimir_exito("Directorio cifrado para múltiples destinatarios con éxito.")
            except Exception as e:
                imprimir_error(f"Fallo al cifrar directorio multi-destinatario: {e}")
                
        elif opcion == "21":
            print("\n--- Descifrar Directorio Multi-destinatario ---")
            ruta_orig = input("Ruta del archivo cifrado: ").strip()
            if not os.path.exists(ruta_orig):
                imprimir_error("El archivo cifrado no existe.")
                continue
            ruta_dest = input("Ruta del directorio destino: ").strip()
            
            print("  a. Cargar llave privada (.pem) desde archivo")
            print("  b. Cargar llave privada desde un Keystore")
            modo_llave = input("Selecciona opción (a/b): ").strip().lower()
            
            try:
                priv = None
                key_alias = None
                ruta_ks = None
                pwd_ks = None
                if modo_llave == "a":
                    ruta_priv = input("Ruta de la llave privada: ").strip()
                    pwd = input("Contraseña de la llave (Enter si no tiene): ").strip() or None
                    try:
                        priv = zch_e2ee.cargar_llave_privada_ec_desde_archivo(ruta_priv, pwd)
                    except Exception:
                        priv = zch_e2ee.cargar_llave_privada_desde_archivo(ruta_priv, pwd)
                elif modo_llave == "b":
                    ruta_ks = input("Ruta del Keystore (.json): ").strip()
                    pwd_ks = input("Contraseña del Keystore: ").strip()
                    ks = zch_e2ee.KeystoreZCH.cargar(ruta_ks, pwd_ks)
                    key_alias = input("Alias de tu llave privada: ").strip()
                    priv = ks.obtener_clave_privada(key_alias)
                else:
                    imprimir_error("Opción inválida.")
                    continue
                
                if not priv:
                    imprimir_error("No se pudo cargar la llave privada.")
                    continue
                    
                exito = False
                try:
                    zch_e2ee.desencriptar_directorio_e2ee_multi(ruta_orig, ruta_dest, priv)
                    exito = True
                except (zch_e2ee.ErrorDescifrado, zch_e2ee.CriptoError):
                    if key_alias and ruta_ks and pwd_ks:
                        ks = zch_e2ee.KeystoreZCH.cargar(ruta_ks, pwd_ks)
                        historial = ks.obtener_historial_clave_privada(key_alias)
                        for priv_hist in historial:
                            try:
                                zch_e2ee.desencriptar_directorio_e2ee_multi(ruta_orig, ruta_dest, priv_hist)
                                exito = True
                                break
                            except Exception:
                                continue
                if not exito:
                    raise zch_e2ee.ErrorDescifrado("Fallo al descifrar el directorio multi-destinatario (incluso usando historial de claves).")
                imprimir_exito("Directorio descifrado con éxito.")
            except Exception as e:
                imprimir_error(f"Fallo al descifrar directorio multi-destinatario: {e}")
                
        elif opcion == "22":
            print("\n¡Hasta luego! Mantente seguro.")
            break
        else:
            imprimir_error("Opción inválida.")
 
def obtener_publica_desde_args(args, key_rsa_path=None, key_ec_path=None, key_alias=None, key_public_path=None):
    if key_alias:
        if not args.keystore or not args.keystore_password:
            raise ValueError("Se requiere --keystore y --keystore-password para cargar la llave publica usando alias.")
        ks = zch_e2ee.KeystoreZCH.cargar(args.keystore, args.keystore_password)
        return ks.obtener_clave_contacto(key_alias)
    elif key_public_path:
        try:
            return zch_e2ee.cargar_llave_publica_ec_desde_archivo(key_public_path)
        except Exception:
            return zch_e2ee.cargar_llave_publica_desde_archivo(key_public_path)
    elif key_rsa_path:
        return zch_e2ee.cargar_llave_publica_desde_archivo(key_rsa_path)
    elif key_ec_path:
        return zch_e2ee.cargar_llave_publica_ec_desde_archivo(key_ec_path)
    return None

def obtener_privada_desde_args(args, key_rsa_path=None, key_ec_path=None, key_alias=None, key_password=None, key_private_path=None):
    if key_alias:
        if not args.keystore or not args.keystore_password:
            raise ValueError("Se requiere --keystore y --keystore-password para cargar la llave privada usando alias.")
        ks = zch_e2ee.KeystoreZCH.cargar(args.keystore, args.keystore_password)
        return ks.obtener_clave_privada(key_alias)
    elif key_private_path:
        try:
            return zch_e2ee.cargar_llave_privada_ec_desde_archivo(key_private_path, key_password)
        except Exception:
            return zch_e2ee.cargar_llave_privada_desde_archivo(key_private_path, key_password)
    elif key_rsa_path:
        return zch_e2ee.cargar_llave_privada_desde_archivo(key_rsa_path, key_password)
    elif key_ec_path:
        return zch_e2ee.cargar_llave_privada_ec_desde_archivo(key_ec_path, key_password)
    return None

def obtener_kdf_params(args):
    params = {}
    kdf_alg = getattr(args, "kdf", "scrypt")
    if kdf_alg == "scrypt":
        if getattr(args, "kdf_n", None) is not None:
            params["n"] = args.kdf_n
        if getattr(args, "kdf_r", None) is not None:
            params["r"] = args.kdf_r
        if getattr(args, "kdf_p", None) is not None:
            params["p"] = args.kdf_p
    elif kdf_alg == "argon2id":
        if getattr(args, "kdf_memory", None) is not None:
            params["memory_cost"] = args.kdf_memory
        if getattr(args, "kdf_time", None) is not None:
            params["time_cost"] = args.kdf_time
        if getattr(args, "kdf_parallel", None) is not None:
            params["parallelism"] = args.kdf_parallel
    return params

def main():
    def agregar_argumentos_kdf(subparser):
        subparser.add_argument("--kdf", choices=["scrypt", "argon2id"], default="scrypt", help="Algoritmo de derivacion de clave (scrypt o argon2id)")
        subparser.add_argument("--kdf-n", type=int, help="Parametro n para Scrypt")
        subparser.add_argument("--kdf-r", type=int, help="Parametro r para Scrypt")
        subparser.add_argument("--kdf-p", type=int, help="Parametro p para Scrypt")
        subparser.add_argument("--kdf-memory", type=int, help="Costo de memoria para Argon2id (KB)")
        subparser.add_argument("--kdf-time", type=int, help="Costo de tiempo para Argon2id")
        subparser.add_argument("--kdf-parallel", type=int, help="Paralelismo para Argon2id")

    parser = argparse.ArgumentParser(description="zch-e2ee CLI v1.1.4 — Herramienta de criptografía de nivel industrial.")
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
    sub_enc.add_argument("--key-alias", help="Alias de la llave pública/contacto a recuperar del Keystore")
    sub_enc.add_argument("--keystore", help="Ruta al Keystore")
    sub_enc.add_argument("--keystore-password", help="Contraseña del Keystore")
    agregar_argumentos_kdf(sub_enc)

    # decrypt
    sub_dec = subparsers.add_parser("decrypt", help="Descifrar un archivo")
    sub_dec.add_argument("--in-file", help="Archivo cifrado a descifrar (omitir si se usa --stdin)")
    sub_dec.add_argument("--out-file", help="Archivo descifrado de salida (omitir si se usa --stdout)")
    sub_dec.add_argument("--password", help="Descifrar usando contraseña")
    sub_dec.add_argument("--key-rsa", help="Llave privada RSA para descifrar")
    sub_dec.add_argument("--key-ec", help="Llave privada X25519 para descifrar")
    sub_dec.add_argument("--key-password", help="Contraseña de la llave pem si corresponde")
    sub_dec.add_argument("--key-alias", help="Alias de tu llave privada propia a recuperar del Keystore")
    sub_dec.add_argument("--keystore", help="Ruta al Keystore")
    sub_dec.add_argument("--keystore-password", help="Contraseña del Keystore")

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

    # keystore-create
    sub_ks_create = subparsers.add_parser("keystore-create", help="Crear un llavero criptográfico vacío (.json)")
    sub_ks_create.add_argument("--keystore", required=True, help="Ruta de guardado del llavero")
    sub_ks_create.add_argument("--password", required=True, help="Contraseña maestra del llavero")

    # keystore-list
    sub_ks_list = subparsers.add_parser("keystore-list", help="Listar los alias guardados en el llavero")
    sub_ks_list.add_argument("--keystore", required=True, help="Ruta del llavero")
    sub_ks_list.add_argument("--password", required=True, help="Contraseña maestra del llavero")

    # keystore-add-key
    sub_ks_add = subparsers.add_parser("keystore-add-key", help="Agregar una llave pública o privada al llavero")
    sub_ks_add.add_argument("--keystore", required=True, help="Ruta del llavero")
    sub_ks_add.add_argument("--password", required=True, help="Contraseña maestra del llavero")
    sub_ks_add.add_argument("--alias", required=True, help="Alias identificador de la llave")
    sub_ks_add.add_argument("--key-file", required=True, help="Ruta del archivo PEM de la llave")
    sub_ks_add.add_argument("--type", choices=["private", "public"], required=True, help="Especificar si es clave pública o privada")
    sub_ks_add.add_argument("--key-password", help="Contraseña opcional si la clave privada PEM está cifrada")
    sub_ks_add.add_argument("--expiration-days", type=int, help="Dias para la expiracion de la llave (opcional)")
    sub_ks_add.add_argument("--description", default="", help="Descripcion opcional de la llave")

    # keystore-rotate
    sub_ks_rotate = subparsers.add_parser("keystore-rotate", help="Rotar una llave del llavero y pasar la actual al historial")
    sub_ks_rotate.add_argument("--keystore", required=True, help="Ruta del llavero")
    sub_ks_rotate.add_argument("--password", required=True, help="Contraseña maestra del llavero")
    sub_ks_rotate.add_argument("--alias", required=True, help="Alias de la llave a rotar")
    sub_ks_rotate.add_argument("--new-key-file", help="Ruta de un archivo PEM con la nueva llave (opcional, si se omite se autogenerará)")
    sub_ks_rotate.add_argument("--key-password", help="Contraseña opcional si la nueva llave privada PEM está cifrada")
    sub_ks_rotate.add_argument("--expiration-days", type=int, help="Dias para la expiracion de la nueva llave (opcional)")

    # keystore-check-expired
    sub_ks_expired = subparsers.add_parser("keystore-check-expired", help="Verificar el estado de expiración de las llaves en el llavero")
    sub_ks_expired.add_argument("--keystore", required=True, help="Ruta del llavero")
    sub_ks_expired.add_argument("--password", required=True, help="Contraseña maestra del llavero")

    # keystore-export-key
    sub_ks_export = subparsers.add_parser("keystore-export-key", help="Exportar una llave del llavero a un archivo PEM")
    sub_ks_export.add_argument("--keystore", required=True, help="Ruta del llavero")
    sub_ks_export.add_argument("--password", required=True, help="Contraseña maestra del llavero")
    sub_ks_export.add_argument("--alias", required=True, help="Alias de la llave a exportar")
    sub_ks_export.add_argument("--out-pem", required=True, help="Ruta del archivo PEM de destino")
    sub_ks_export.add_argument("--type", choices=["private", "public"], required=True, help="Especificar si es clave pública o privada")
    sub_ks_export.add_argument("--key-password", help="Contraseña opcional para cifrar la clave privada PEM exportada")

    # hash
    sub_hash = subparsers.add_parser("hash", help="Calcular el hash SHA-256 de un archivo")
    sub_hash.add_argument("--file", required=True, help="Ruta del archivo a procesar")

    # hash-verify
    sub_hash_ver = subparsers.add_parser("hash-verify", help="Verificar el hash SHA-256 de un archivo")
    sub_hash_ver.add_argument("--file", required=True, help="Ruta del archivo a procesar")
    sub_hash_ver.add_argument("--checksum", required=True, help="Checksum esperado en formato hex")

    # encrypt-text
    sub_enc_txt = subparsers.add_parser("encrypt-text", help="Cifrar un texto directo")
    sub_enc_txt.add_argument("--text", help="Texto original a cifrar (omitir si se usa --stdin)")
    sub_enc_txt.add_argument("--password", help="Cifrar con contraseña simétrica")
    sub_enc_txt.add_argument("--key-rsa", help="Llave pública RSA para cifrar")
    sub_enc_txt.add_argument("--key-ec", help="Llave pública X25519 para cifrar")
    sub_enc_txt.add_argument("--key-alias", help="Alias de la llave pública/contacto a recuperar del Keystore")
    sub_enc_txt.add_argument("--keystore", help="Ruta al Keystore")
    sub_enc_txt.add_argument("--keystore-password", help="Contraseña del Keystore")
    agregar_argumentos_kdf(sub_enc_txt)

    # decrypt-text
    sub_dec_txt = subparsers.add_parser("decrypt-text", help="Descifrar un texto cifrado directo")
    sub_dec_txt.add_argument("--text", help="Texto cifrado (Base64) a descifrar (omitir si se usa --stdin)")
    sub_dec_txt.add_argument("--password", help="Descifrar usando contraseña")
    sub_dec_txt.add_argument("--key-rsa", help="Llave privada RSA para descifrar")
    sub_dec_txt.add_argument("--key-ec", help="Llave privada X25519 para descifrar")
    sub_dec_txt.add_argument("--key-password", help="Contraseña de la llave privada PEM si está cifrada")
    sub_dec_txt.add_argument("--key-alias", help="Alias de tu llave privada propia a recuperar del Keystore")
    sub_dec_txt.add_argument("--keystore", help="Ruta al Keystore")
    sub_dec_txt.add_argument("--keystore-password", help="Contraseña del Keystore")

    # hmac-calc
    sub_hmac_calc = subparsers.add_parser("hmac-calc", help="Calcular el HMAC-SHA256 de un archivo")
    sub_hmac_calc.add_argument("--file", required=True, help="Ruta del archivo a procesar")
    sub_hmac_calc.add_argument("--key", required=True, help="Clave simétrica para calcular el HMAC")

    # hmac-verify
    sub_hmac_ver = subparsers.add_parser("hmac-verify", help="Verificar el HMAC-SHA256 de un archivo")
    sub_hmac_ver.add_argument("--file", required=True, help="Ruta del archivo a procesar")
    sub_hmac_ver.add_argument("--key", required=True, help="Clave simétrica usada para calcular el HMAC")
    sub_hmac_ver.add_argument("--hmac", required=True, help="Valor de HMAC esperado en formato hex")

    # sign-file
    sub_sign = subparsers.add_parser("sign-file", help="Firmar un archivo digitalmente")
    sub_sign.add_argument("--file", required=True, help="Ruta del archivo a firmar")
    sub_sign.add_argument("--key-private", help="Ruta de la llave privada (.pem)")
    sub_sign.add_argument("--key-password", help="Contraseña opcional de la llave privada PEM")
    sub_sign.add_argument("--key-alias", help="Alias de tu llave privada propia a recuperar del Keystore")
    sub_sign.add_argument("--keystore", help="Ruta al Keystore")
    sub_sign.add_argument("--keystore-password", help="Contraseña del Keystore")

    # verify-file
    sub_verify = subparsers.add_parser("verify-file", help="Verificar la firma digital de un archivo")
    sub_verify.add_argument("--file", required=True, help="Ruta del archivo original")
    sub_verify.add_argument("--key-public", help="Ruta de la llave pública (.pem)")
    sub_verify.add_argument("--signature", required=True, help="Firma digital en formato Base64")
    sub_verify.add_argument("--key-alias", help="Alias de la llave pública/contacto a recuperar del Keystore")
    sub_verify.add_argument("--keystore", help="Ruta al Keystore")
    sub_verify.add_argument("--keystore-password", help="Contraseña del Keystore")

    # ratchet-sim
    sub_ratchet = subparsers.add_parser("ratchet-sim", help="Simular una sesión Double Ratchet interactiva o por script")

    # keystore-backup
    sub_ks_bak = subparsers.add_parser("keystore-backup", help="Crear un respaldo cifrado de todo el Keystore")
    sub_ks_bak.add_argument("--keystore", required=True, help="Ruta del llavero original")
    sub_ks_bak.add_argument("--password", required=True, help="Contraseña maestra del llavero original")
    sub_ks_bak.add_argument("--out-backup", required=True, help="Ruta del archivo de respaldo de salida")
    sub_ks_bak.add_argument("--backup-password", required=True, help="Contraseña para cifrar el archivo de respaldo")

    # keystore-restore
    sub_ks_res = subparsers.add_parser("keystore-restore", help="Restaurar y fusionar un respaldo en un Keystore")
    sub_ks_res.add_argument("--keystore", required=True, help="Ruta del llavero destino")
    sub_ks_res.add_argument("--password", required=True, help="Contraseña maestra del llavero destino")
    sub_ks_res.add_argument("--in-backup", required=True, help="Ruta del archivo de respaldo a importar")
    sub_ks_res.add_argument("--backup-password", required=True, help="Contraseña de descifrado del archivo de respaldo")

    # encrypt-dir
    sub_enc_dir = subparsers.add_parser("encrypt-dir", help="Cifrar un directorio completo")
    sub_enc_dir.add_argument("--in-dir", required=True, help="Directorio origen a cifrar")
    sub_enc_dir.add_argument("--out-file", required=True, help="Archivo cifrado de salida")
    sub_enc_dir.add_argument("--password", help="Cifrar con contraseña simétrica")
    sub_enc_dir.add_argument("--key-rsa", help="Llave pública RSA para cifrar")
    sub_enc_dir.add_argument("--key-ec", help="Llave pública X25519 para cifrar")
    sub_enc_dir.add_argument("--key-alias", help="Alias de la llave pública/contacto a recuperar del Keystore")
    sub_enc_dir.add_argument("--keystore", help="Ruta al Keystore")
    sub_enc_dir.add_argument("--keystore-password", help="Contraseña del Keystore")
    agregar_argumentos_kdf(sub_enc_dir)

    # decrypt-dir
    sub_dec_dir = subparsers.add_parser("decrypt-dir", help="Descifrar un directorio completo")
    sub_dec_dir.add_argument("--in-file", required=True, help="Archivo cifrado a descifrar")
    sub_dec_dir.add_argument("--out-dir", required=True, help="Directorio destino para extraer")
    sub_dec_dir.add_argument("--password", help="Descifrar usando contraseña")
    sub_dec_dir.add_argument("--key-rsa", help="Llave privada RSA para descifrar")
    sub_dec_dir.add_argument("--key-ec", help="Llave privada X25519 para descifrar")
    sub_dec_dir.add_argument("--key-password", help="Contraseña de la llave privada PEM si está cifrada")
    sub_dec_dir.add_argument("--key-alias", help="Alias de tu llave privada propia a recuperar del Keystore")
    sub_dec_dir.add_argument("--keystore", help="Ruta al Keystore")
    sub_dec_dir.add_argument("--keystore-password", help="Contraseña del Keystore")

    # encrypt-dir-multi
    sub_enc_dir_multi = subparsers.add_parser("encrypt-dir-multi", help="Cifrar un directorio completo para múltiples destinatarios")
    sub_enc_dir_multi.add_argument("--in-dir", required=True, help="Directorio origen a cifrar")
    sub_enc_dir_multi.add_argument("--out-file", required=True, help="Archivo cifrado de salida")
    sub_enc_dir_multi.add_argument("--keys-public", help="Rutas de llaves públicas (.pem) separadas por comas")
    sub_enc_dir_multi.add_argument("--keys-aliases", help="Alias de llaves de contacto en Keystore separados por comas")
    sub_enc_dir_multi.add_argument("--keystore", help="Ruta del llavero Keystore (.json) si se usan alias")
    sub_enc_dir_multi.add_argument("--password", help="Contraseña maestra del llavero Keystore")

    # decrypt-dir-multi
    sub_dec_dir_multi = subparsers.add_parser("decrypt-dir-multi", help="Descifrar un directorio completo multi-destinatario")
    sub_dec_dir_multi.add_argument("--in-file", required=True, help="Archivo cifrado a descifrar")
    sub_dec_dir_multi.add_argument("--out-dir", required=True, help="Directorio destino para extraer")
    sub_dec_dir_multi.add_argument("--key-private", help="Ruta de tu llave privada (.pem)")
    sub_dec_dir_multi.add_argument("--key-password", help="Contraseña opcional de tu llave privada PEM")
    sub_dec_dir_multi.add_argument("--key-alias", help="Alias de tu llave privada en el Keystore")
    sub_dec_dir_multi.add_argument("--keystore", help="Ruta del llavero Keystore (.json) si se usa alias")
    sub_dec_dir_multi.add_argument("--password", help="Contraseña maestra del llavero Keystore")

    # encrypt-multi
    sub_enc_multi = subparsers.add_parser("encrypt-multi", help="Cifrar un archivo para múltiples destinatarios")
    sub_enc_multi.add_argument("--in-file", required=True, help="Archivo original a cifrar")
    sub_enc_multi.add_argument("--out-file", required=True, help="Archivo cifrado de salida")
    sub_enc_multi.add_argument("--keys-public", help="Rutas de llaves públicas (.pem) separadas por comas")
    sub_enc_multi.add_argument("--keys-aliases", help="Alias de llaves de contacto en Keystore separados por comas")
    sub_enc_multi.add_argument("--keystore", help="Ruta del llavero Keystore (.json) si se usan alias")
    sub_enc_multi.add_argument("--password", help="Contraseña maestra del llavero Keystore")

    # decrypt-multi
    sub_dec_multi = subparsers.add_parser("decrypt-multi", help="Descifrar un archivo de múltiples destinatarios")
    sub_dec_multi.add_argument("--in-file", required=True, help="Archivo cifrado a descifrar")
    sub_dec_multi.add_argument("--out-file", required=True, help="Archivo descifrado de salida")
    sub_dec_multi.add_argument("--key-private", help="Ruta de tu llave privada (.pem)")
    sub_dec_multi.add_argument("--key-password", help="Contraseña opcional de tu llave privada PEM")
    sub_dec_multi.add_argument("--key-alias", help="Alias de tu llave privada en el Keystore")
    sub_dec_multi.add_argument("--keystore", help="Ruta del llavero Keystore (.json) si se usa alias")
    sub_dec_multi.add_argument("--password", help="Contraseña maestra del llavero Keystore")

    # encrypt-text-multi
    sub_enc_txt_multi = subparsers.add_parser("encrypt-text-multi", help="Cifrar un texto para múltiples destinatarios")
    sub_enc_txt_multi.add_argument("--text", help="Texto original a cifrar (omitir si se usa --stdin)")
    sub_enc_txt_multi.add_argument("--keys-public", help="Rutas de llaves públicas (.pem) separadas por comas")
    sub_enc_txt_multi.add_argument("--keys-aliases", help="Alias de llaves de contacto en Keystore separados por comas")
    sub_enc_txt_multi.add_argument("--keystore", help="Ruta del llavero Keystore (.json) si se usan alias")
    sub_enc_txt_multi.add_argument("--password", help="Contraseña maestra del llavero Keystore")

    # decrypt-text-multi
    sub_dec_txt_multi = subparsers.add_parser("decrypt-text-multi", help="Descifrar un texto de múltiples destinatarios")
    sub_dec_txt_multi.add_argument("--text", help="Texto cifrado (Base64) a descifrar (omitir si se usa --stdin)")
    sub_dec_txt_multi.add_argument("--key-private", help="Ruta de tu llave privada (.pem)")
    sub_dec_txt_multi.add_argument("--key-password", help="Contraseña opcional de tu llave privada PEM")
    sub_dec_txt_multi.add_argument("--key-alias", help="Alias de tu llave privada en el Keystore")
    sub_dec_txt_multi.add_argument("--keystore", help="Ruta del llavero Keystore (.json) si se usa alias")
    sub_dec_txt_multi.add_argument("--password", help="Contraseña maestra del llavero Keystore")

    # ratchet-init
    sub_rat_init = subparsers.add_parser("ratchet-init", help="Inicializar un archivo de sesión Double Ratchet")
    sub_rat_init.add_argument("--key-private", help="Ruta de tu llave privada (.pem)")
    sub_rat_init.add_argument("--key-public", help="Ruta de la llave pública (.pem) del destinatario")
    sub_rat_init.add_argument("--initiator", action="store_true", help="Especificar si inicias la conversación")
    sub_rat_init.add_argument("--out-session", required=True, help="Ruta del archivo de sesión JSON de salida")
    sub_rat_init.add_argument("--key-password", help="Contraseña opcional de tu llave privada PEM")
    sub_rat_init.add_argument("--key-private-alias", help="Alias de tu llave privada propia a recuperar del Keystore")
    sub_rat_init.add_argument("--key-public-alias", help="Alias de la llave pública del contacto a recuperar del Keystore")
    sub_rat_init.add_argument("--keystore", help="Ruta al Keystore")
    sub_rat_init.add_argument("--keystore-password", help="Contraseña del Keystore")

    # ratchet-encrypt
    sub_rat_enc = subparsers.add_parser("ratchet-encrypt", help="Cifrar mensaje usando una sesión Double Ratchet activa")
    sub_rat_enc.add_argument("--session", required=True, help="Ruta del archivo de sesión JSON")
    sub_rat_enc.add_argument("--text", help="Texto del mensaje a cifrar")
    sub_rat_enc.add_argument("--out-session", required=True, help="Ruta del archivo de sesión JSON actualizado")

    # ratchet-decrypt
    sub_rat_dec = subparsers.add_parser("ratchet-decrypt", help="Descifrar mensaje usando una sesión Double Ratchet activa")
    sub_rat_dec.add_argument("--session", required=True, help="Ruta del archivo de sesión JSON")
    sub_rat_dec.add_argument("--text", help="Mensaje cifrado en Base64")
    sub_rat_dec.add_argument("--out-session", required=True, help="Ruta del archivo de sesión JSON actualizado")

    # shamir-reconstruct
    sub_sha_rec = subparsers.add_parser("shamir-reconstruct", help="Reconstruir un secreto de Shamir usando fragmentos en línea")
    sub_sha_rec.add_argument("--shares", required=True, help="Lista de fragmentos separados por comas (formato: Indice-Base64)")

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
                    kdf_params = obtener_kdf_params(args)
                    zch_e2ee.encriptar_archivo_con_password(temp_in.name, temp_out.name, args.password, kdf_name=args.kdf, **kdf_params)
                else:
                    pub = obtener_publica_desde_args(args, key_rsa_path=args.key_rsa, key_ec_path=args.key_ec, key_alias=args.key_alias)
                    if not pub:
                        imprimir_error("Debe especificar --password, --key-rsa, --key-ec o --key-alias para cifrar.", args.json)
                        sys.exit(1)
                    if isinstance(pub, rsa.RSAPublicKey):
                        zch_e2ee.encriptar_archivo_e2ee(temp_in.name, temp_out.name, pub)
                    elif isinstance(pub, x25519.X25519PublicKey):
                        zch_e2ee.encriptar_archivo_e2ee_ec(temp_in.name, temp_out.name, pub)
                    else:
                        imprimir_error("Tipo de llave pública no soportado para cifrar (debe ser RSA o X25519).", args.json)
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
                else:
                    priv = obtener_privada_desde_args(args, key_rsa_path=args.key_rsa, key_ec_path=args.key_ec, key_alias=args.key_alias, key_password=args.key_password)
                    if not priv:
                        imprimir_error("Debe especificar --password, --key-rsa, --key-ec o --key-alias para descifrar.", args.json)
                        sys.exit(1)
                    
                    exito = False
                    try:
                        if isinstance(priv, rsa.RSAPrivateKey):
                            zch_e2ee.desencriptar_archivo_e2ee(temp_in.name, temp_out.name, priv)
                        elif isinstance(priv, x25519.X25519PrivateKey):
                            zch_e2ee.desencriptar_archivo_e2ee_ec(temp_in.name, temp_out.name, priv)
                        else:
                            imprimir_error("Tipo de llave privada no soportado para descifrar (debe ser RSA o X25519).", args.json)
                            sys.exit(1)
                        exito = True
                    except (zch_e2ee.ErrorDescifrado, zch_e2ee.CriptoError):
                        if args.key_alias and args.keystore and args.keystore_password:
                            ks = zch_e2ee.KeystoreZCH.cargar(args.keystore, args.keystore_password)
                            historial = ks.obtener_historial_clave_privada(args.key_alias)
                            for priv_hist in historial:
                                try:
                                    if isinstance(priv_hist, rsa.RSAPrivateKey):
                                        zch_e2ee.desencriptar_archivo_e2ee(temp_in.name, temp_out.name, priv_hist)
                                    elif isinstance(priv_hist, x25519.X25519PrivateKey):
                                        zch_e2ee.desencriptar_archivo_e2ee_ec(temp_in.name, temp_out.name, priv_hist)
                                    else:
                                        continue
                                    exito = True
                                    break
                                except Exception:
                                    continue
                    if not exito:
                        raise zch_e2ee.ErrorDescifrado("Fallo al descifrar el archivo (incluso usando historial de claves).")
                    
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

    elif args.command == "keystore-create":
        try:
            zch_e2ee.KeystoreZCH.crear(args.keystore, args.password)
            imprimir_exito(f"Llavero creado correctamente en '{args.keystore}'.", args.json, {"keystore": args.keystore})
        except Exception as e:
            imprimir_error(f"Fallo al crear llavero: {e}", args.json)
            sys.exit(1)

    elif args.command == "keystore-list":
        try:
            ks = zch_e2ee.KeystoreZCH.cargar(args.keystore, args.password)
            aliases = ks.listar_alias()
            
            detailed_priv = {}
            for a, info in ks.claves_privadas.items():
                detailed_priv[a] = {
                    "descripcion": info.get("descripcion", ""),
                    "fecha_expiracion": info.get("fecha_expiracion"),
                    "historial_count": len(info.get("historial", []))
                }
            detailed_pub = {}
            for a, info in ks.claves_publicas.items():
                detailed_pub[a] = {
                    "descripcion": info.get("descripcion", ""),
                    "fecha_expiracion": info.get("fecha_expiracion"),
                    "historial_count": len(info.get("historial", []))
                }
                
            imprimir_exito("Alias del llavero recuperados.", args.json, {
                "aliases": aliases,
                "detailed_privadas": detailed_priv,
                "detailed_publicas": detailed_pub
            })
            if not args.json:
                print("\n--- ALIAS EN LLAVERO ---")
                print("Claves Privadas Propias:")
                for a in aliases["claves_privadas"]:
                    info = ks.claves_privadas[a]
                    desc = info.get("descripcion", "")
                    desc_str = f" - Desc: {desc}" if desc else ""
                    exp = info.get("fecha_expiracion")
                    exp_str = f" - Exp: {exp}" if exp else " - Exp: Nunca"
                    hist = len(info.get("historial", []))
                    hist_str = f" - Historial: {hist} llaves anteriores" if hist > 0 else ""
                    print(f"  - {a}{desc_str}{exp_str}{hist_str}")
                print("\nClaves Públicas de Contactos:")
                for a in aliases["claves_publicas"]:
                    info = ks.claves_publicas[a]
                    desc = info.get("descripcion", "")
                    desc_str = f" - Desc: {desc}" if desc else ""
                    exp = info.get("fecha_expiracion")
                    exp_str = f" - Exp: {exp}" if exp else " - Exp: Nunca"
                    hist = len(info.get("historial", []))
                    hist_str = f" - Historial: {hist} llaves anteriores" if hist > 0 else ""
                    print(f"  - {a}{desc_str}{exp_str}{hist_str}")
        except Exception as e:
            imprimir_error(f"Fallo al listar llavero: {e}", args.json)
            sys.exit(1)

    elif args.command == "keystore-add-key":
        try:
            ks = zch_e2ee.KeystoreZCH.cargar(args.keystore, args.password)
            with open(args.key_file, 'r', encoding='utf-8') as f:
                pem_str = f.read()
                
            if args.type == "private":
                try:
                    clave = zch_e2ee.cargar_llave_privada_ec(pem_str, args.key_password)
                except Exception:
                    clave = zch_e2ee.cargar_llave_privada(pem_str, args.key_password)
                ks.guardar_clave_propia(args.alias, clave, expiracion_dias=args.expiration_days, descripcion=args.description)
            else:
                try:
                    clave = zch_e2ee.cargar_llave_publica_ec(pem_str)
                except Exception:
                    clave = zch_e2ee.cargar_llave_publica(pem_str)
                ks.guardar_clave_contacto(args.alias, clave, expiracion_dias=args.expiration_days, descripcion=args.description)
                
            ks.guardar(args.keystore, args.password)
            imprimir_exito(f"Clave guardada en llavero bajo el alias '{args.alias}'.", args.json, {"alias": args.alias})
        except Exception as e:
            imprimir_error(f"Fallo al agregar clave: {e}", args.json)
            sys.exit(1)

    elif args.command == "keystore-export-key":
        try:
            ks = zch_e2ee.KeystoreZCH.cargar(args.keystore, args.password)
            if args.type == "private":
                clave = ks.obtener_clave_privada(args.alias)
                try:
                    zch_e2ee.guardar_llave_privada_ec_en_archivo(clave, args.out_pem, args.key_password)
                except Exception:
                    zch_e2ee.guardar_llave_privada_en_archivo(clave, args.out_pem, args.key_password)
            else:
                clave = ks.obtener_clave_contacto(args.alias)
                try:
                    zch_e2ee.guardar_llave_publica_ec_en_archivo(clave, args.out_pem)
                except Exception:
                    zch_e2ee.guardar_llave_publica_en_archivo(clave, args.out_pem)
                    
            imprimir_exito(f"Clave '{args.alias}' exportada con éxito en '{args.out_pem}'.", args.json, {"alias": args.alias, "out_pem": args.out_pem})
        except Exception as e:
            imprimir_error(f"Fallo al exportar clave: {e}", args.json)
            sys.exit(1)

    elif args.command == "hash":
        try:
            hash_val = zch_e2ee.calcular_sha256(args.file)
            if args.json:
                imprimir_exito("Checksum calculado.", args.json, {"hash": hash_val})
            else:
                if args.stdout:
                    sys.stdout.write(hash_val)
                else:
                    print(hash_val)
        except Exception as e:
            imprimir_error(f"Fallo al calcular hash: {e}", args.json)
            sys.exit(1)

    elif args.command == "hash-verify":
        try:
            hash_val = zch_e2ee.calcular_sha256(args.file)
            if hash_val.lower().strip() == args.checksum.lower().strip():
                imprimir_exito("El checksum del archivo es valido.", args.json, {"valid": True})
            else:
                imprimir_error("El checksum del archivo es invalido o el archivo fue modificado.", args.json)
                sys.exit(1)
        except Exception as e:
            imprimir_error(f"Fallo al verificar hash: {e}", args.json)
            sys.exit(1)

    elif args.command == "encrypt-text":
        try:
            if args.stdin:
                mensaje = sys.stdin.read()
            else:
                if args.text is None:
                    imprimir_error("Debe especificar --text o usar --stdin.", args.json)
                    sys.exit(1)
                mensaje = args.text

            cifrado = None
            if args.password:
                kdf_params = obtener_kdf_params(args)
                cifrado = zch_e2ee.encriptar_con_password(mensaje, args.password, kdf_name=args.kdf, **kdf_params)
            else:
                pub = obtener_publica_desde_args(args, key_rsa_path=args.key_rsa, key_ec_path=args.key_ec, key_alias=args.key_alias)
                if not pub:
                    imprimir_error("Debe especificar --password, --key-rsa, --key-ec o --key-alias para cifrar.", args.json)
                    sys.exit(1)
                if isinstance(pub, rsa.RSAPublicKey):
                    cifrado = zch_e2ee.encriptar_e2ee(mensaje, pub)
                elif isinstance(pub, x25519.X25519PublicKey):
                    cifrado = zch_e2ee.encriptar_e2ee_ec(mensaje, pub)
                else:
                    imprimir_error("Tipo de llave pública no soportado para cifrar (debe ser RSA o X25519).", args.json)
                    sys.exit(1)

            if args.json:
                imprimir_exito("Texto cifrado.", args.json, {"cipher": cifrado})
            else:
                if args.stdout:
                    sys.stdout.write(cifrado)
                else:
                    print(cifrado)
        except Exception as e:
            imprimir_error(f"Fallo al cifrar texto: {e}", args.json)
            sys.exit(1)

    elif args.command == "decrypt-text":
        try:
            if args.stdin:
                texto_cifrado = sys.stdin.read()
            else:
                if args.text is None:
                    imprimir_error("Debe especificar --text o usar --stdin.", args.json)
                    sys.exit(1)
                texto_cifrado = args.text

            descifrado = None
            if args.password:
                descifrado = zch_e2ee.desencriptar_con_password(texto_cifrado, args.password)
            else:
                priv = obtener_privada_desde_args(args, key_rsa_path=args.key_rsa, key_ec_path=args.key_ec, key_alias=args.key_alias, key_password=args.key_password)
                if not priv:
                    imprimir_error("Debe especificar --password, --key-rsa, --key-ec o --key-alias para descifrar.", args.json)
                    sys.exit(1)
                
                exito = False
                try:
                    if isinstance(priv, rsa.RSAPrivateKey):
                        descifrado = zch_e2ee.desencriptar_e2ee(texto_cifrado, priv)
                    elif isinstance(priv, x25519.X25519PrivateKey):
                        descifrado = zch_e2ee.desencriptar_e2ee_ec(texto_cifrado, priv)
                    else:
                        imprimir_error("Tipo de llave privada no soportado para descifrar (debe ser RSA o X25519).", args.json)
                        sys.exit(1)
                    exito = True
                except (zch_e2ee.ErrorDescifrado, zch_e2ee.CriptoError):
                    if args.key_alias and args.keystore and args.keystore_password:
                        ks = zch_e2ee.KeystoreZCH.cargar(args.keystore, args.keystore_password)
                        historial = ks.obtener_historial_clave_privada(args.key_alias)
                        for priv_hist in historial:
                            try:
                                if isinstance(priv_hist, rsa.RSAPrivateKey):
                                    descifrado = zch_e2ee.desencriptar_e2ee(texto_cifrado, priv_hist)
                                elif isinstance(priv_hist, x25519.X25519PrivateKey):
                                    descifrado = zch_e2ee.desencriptar_e2ee_ec(texto_cifrado, priv_hist)
                                else:
                                    continue
                                exito = True
                                break
                            except Exception:
                                continue
                if not exito:
                    raise zch_e2ee.ErrorDescifrado("Fallo al descifrar texto (incluso usando historial de claves).")

            if args.json:
                imprimir_exito("Texto descifrado.", args.json, {"plain": descifrado})
            else:
                if args.stdout:
                    sys.stdout.write(descifrado)
                else:
                    print(descifrado)
        except Exception as e:
            imprimir_error(f"Fallo al descifrar texto: {e}", args.json)
            sys.exit(1)

    elif args.command == "hmac-calc":
        try:
            with open(args.file, 'rb') as f:
                datos = f.read()
            key_bytes = args.key.encode('utf-8')
            hmac_bytes = zch_e2ee.calcular_hmac(datos, key_bytes)
            hmac_hex = hmac_bytes.hex()

            if args.json:
                imprimir_exito("HMAC calculado.", args.json, {"hmac": hmac_hex})
            else:
                if args.stdout:
                    sys.stdout.write(hmac_hex)
                else:
                    print(hmac_hex)
        except Exception as e:
            imprimir_error(f"Fallo al calcular HMAC: {e}", args.json)
            sys.exit(1)

    elif args.command == "hmac-verify":
        try:
            with open(args.file, 'rb') as f:
                datos = f.read()
            key_bytes = args.key.encode('utf-8')
            try:
                expected_bytes = bytes.fromhex(args.hmac.strip())
            except ValueError:
                imprimir_error("El valor HMAC esperado debe ser una cadena hexadecimal valida.", args.json)
                sys.exit(1)
            
            es_valido = zch_e2ee.verificar_hmac(datos, expected_bytes, key_bytes)
            if es_valido:
                imprimir_exito("El HMAC es totalmente valido.", args.json, {"valid": True})
            else:
                imprimir_error("El HMAC es invalido o el archivo fue modificado.", args.json)
                sys.exit(1)
        except Exception as e:
            imprimir_error(f"Fallo al verificar HMAC: {e}", args.json)
            sys.exit(1)

    elif args.command == "sign-file":
        try:
            priv = obtener_privada_desde_args(args, key_private_path=args.key_private, key_alias=args.key_alias, key_password=args.key_password)
            if not priv:
                imprimir_error("Debe especificar --key-private o --key-alias para firmar.", args.json)
                sys.exit(1)

            if "Ed25519" in type(priv).__name__:
                with open(args.file, 'rb') as f:
                    datos = f.read()
                firma = zch_e2ee.firmar_mensaje_ed25519(datos.decode('utf-8', errors='ignore'), priv)
            else:
                firma = zch_e2ee.firmar_archivo(args.file, priv)

            if args.json:
                imprimir_exito("Firma generada correctamente.", args.json, {"signature": firma})
            else:
                if args.stdout:
                    sys.stdout.write(firma)
                else:
                    print(firma)
        except Exception as e:
            imprimir_error(f"Fallo al firmar archivo: {e}", args.json)
            sys.exit(1)

    elif args.command == "verify-file":
        try:
            pub = obtener_publica_desde_args(args, key_public_path=args.key_public, key_alias=args.key_alias)
            if not pub:
                imprimir_error("Debe especificar --key-public o --key-alias para verificar.", args.json)
                sys.exit(1)

            if "Ed25519" in type(pub).__name__:
                with open(args.file, 'rb') as f:
                    datos = f.read()
                es_valido = zch_e2ee.verificar_firma_ed25519(datos.decode('utf-8', errors='ignore'), args.signature, pub)
            else:
                es_valido = zch_e2ee.verificar_firma_archivo(args.file, args.signature, pub)

            # Fallback a historial si es alias de contacto y la verificación inicial falló
            if not es_valido and args.key_alias and args.keystore and args.keystore_password:
                ks = zch_e2ee.KeystoreZCH.cargar(args.keystore, args.keystore_password)
                historial = ks.obtener_historial_clave_contacto(args.key_alias)
                for pub_hist in historial:
                    try:
                        if "Ed25519" in type(pub_hist).__name__:
                            es_valido = zch_e2ee.verificar_firma_ed25519(datos.decode('utf-8', errors='ignore'), args.signature, pub_hist)
                        else:
                            es_valido = zch_e2ee.verificar_firma_archivo(args.file, args.signature, pub_hist)
                        if es_valido:
                            break
                    except Exception:
                        continue

            if es_valido:
                imprimir_exito("La firma es totalmente valida.", args.json, {"valid": True})
            else:
                imprimir_error("La firma es invalida o el archivo fue alterado.", args.json)
                sys.exit(1)
        except Exception as e:
            imprimir_error(f"Fallo al verificar firma: {e}", args.json)
            sys.exit(1)

    elif args.command == "ratchet-sim":
        try:
            if args.json:
                priv_alice, pub_alice = zch_e2ee.generar_llaves_ec()
                priv_bob, pub_bob = zch_e2ee.generar_llaves_ec()
                sesion_alice = zch_e2ee.SesionDoubleRatchet(priv_alice, pub_bob, es_iniciador=True)
                sesion_bob = zch_e2ee.SesionDoubleRatchet(priv_bob, pub_alice, es_iniciador=False)
                
                sim_log = []
                # 1. Alice -> Bob
                txt1 = "Hola Bob, este es el inicio de nuestra sesion segura."
                cifrado1 = sesion_alice.enviar_mensaje(txt1)
                descifrado1 = sesion_bob.recibir_mensaje(cifrado1)
                sim_log.append({"from": "Alice", "to": "Bob", "plain": txt1, "cipher": cifrado1, "decrypted": descifrado1})
                
                # 2. Bob -> Alice
                txt2 = "Entendido Alice, te escucho fuerte y claro."
                cifrado2 = sesion_bob.enviar_mensaje(txt2)
                descifrado2 = sesion_alice.recibir_mensaje(cifrado2)
                sim_log.append({"from": "Bob", "to": "Alice", "plain": txt2, "cipher": cifrado2, "decrypted": descifrado2})
                
                # 3. Alice -> Bob
                txt3 = "Excelente. El trinquete esta rotando las llaves perfectamente."
                cifrado3 = sesion_alice.enviar_mensaje(txt3)
                descifrado3 = sesion_bob.recibir_mensaje(cifrado3)
                sim_log.append({"from": "Alice", "to": "Bob", "plain": txt3, "cipher": cifrado3, "decrypted": descifrado3})
                
                imprimir_exito("Simulacion automatica completada.", args.json, {"simulation": sim_log})
            else:
                print("\n--- Simulación Interactiva de Double Ratchet (CLI) ---")
                print("Generando llaves efímeras para Alice y Bob...")
                priv_alice, pub_alice = zch_e2ee.generar_llaves_ec()
                priv_bob, pub_bob = zch_e2ee.generar_llaves_ec()
                
                sesion_alice = zch_e2ee.SesionDoubleRatchet(priv_alice, pub_bob, es_iniciador=True)
                sesion_bob = zch_e2ee.SesionDoubleRatchet(priv_bob, pub_alice, es_iniciador=False)
                print("Sesiones inicializadas correctamente.")
                
                while True:
                    print("\nAcciones disponibles:")
                    print("  1. Alice envía mensaje a Bob")
                    print("  2. Bob envía mensaje a Alice")
                    print("  3. Terminar simulación")
                    sub_opt = input("Selecciona acción (1-3): ").strip()
                    
                    if sub_opt == "1":
                        texto = input("Mensaje de Alice para Bob: ")
                        cifrado = sesion_alice.enviar_mensaje(texto)
                        print(f"Mensaje cifrado (Base64):\n{cifrado}")
                        descifrado = sesion_bob.recibir_mensaje(cifrado)
                        print(f"Bob descifró con éxito: {descifrado}")
                    elif sub_opt == "2":
                        texto = input("Mensaje de Bob para Alice: ")
                        cifrado = sesion_bob.enviar_mensaje(texto)
                        print(f"Mensaje cifrado (Base64):\n{cifrado}")
                        descifrado = sesion_alice.recibir_mensaje(cifrado)
                        print(f"Alice descifró con éxito: {descifrado}")
                    elif sub_opt == "3":
                        break
                    else:
                        print("Acción inválida.")
        except Exception as e:
            imprimir_error(f"Fallo en simulador de Double Ratchet: {e}", args.json)
            sys.exit(1)

    elif args.command == "keystore-backup":
        try:
            ks = zch_e2ee.KeystoreZCH.cargar(args.keystore, args.password)
            data = {
                "claves_privadas": ks.claves_privadas,
                "claves_publicas": ks.claves_publicas
            }
            datos_json = json.dumps(data)
            backup_b64 = zch_e2ee.encriptar_con_password(datos_json, args.backup_password)
            with open(args.out_backup, 'w', encoding='utf-8') as f:
                f.write(backup_b64)
            imprimir_exito(f"Respaldo cifrado de Keystore creado correctamente en '{args.out_backup}'.", args.json, {"out_backup": args.out_backup})
        except Exception as e:
            imprimir_error(f"Fallo al realizar respaldo de Keystore: {e}", args.json)
            sys.exit(1)

    elif args.command == "keystore-restore":
        try:
            with open(args.in_backup, 'r', encoding='utf-8') as f:
                backup_b64 = f.read()
            datos_json = zch_e2ee.desencriptar_con_password(backup_b64, args.backup_password)
            data = json.loads(datos_json)
            
            if os.path.exists(args.keystore):
                try:
                    ks = zch_e2ee.KeystoreZCH.cargar(args.keystore, args.password)
                except Exception:
                    ks = zch_e2ee.KeystoreZCH()
            else:
                ks = zch_e2ee.KeystoreZCH()
                
            ks.claves_privadas.update(data.get("claves_privadas", {}))
            ks.claves_publicas.update(data.get("claves_publicas", {}))
            ks.guardar(args.keystore, args.password)
            
            imprimir_exito(f"Respaldo de Keystore restaurado correctamente en '{args.keystore}'.", args.json, {"keystore": args.keystore})
        except Exception as e:
            imprimir_error(f"Fallo al restaurar respaldo de Keystore: {e}", args.json)
            sys.exit(1)

    elif args.command == "keystore-rotate":
        try:
            ks = zch_e2ee.KeystoreZCH.cargar(args.keystore, args.password)
            nueva_clave_pem = None
            if args.new_key_file:
                with open(args.new_key_file, 'r', encoding='utf-8') as f:
                    nueva_clave_pem = f.read()
            ks.rotar_clave(args.alias, nueva_clave_pem=nueva_clave_pem, expiracion_dias=args.expiration_days)
            ks.guardar(args.keystore, args.password)
            imprimir_exito(f"Clave '{args.alias}' rotada con éxito.", args.json, {"alias": args.alias})
        except Exception as e:
            imprimir_error(f"Fallo al rotar clave: {e}", args.json)
            sys.exit(1)

    elif args.command == "keystore-check-expired":
        try:
            import datetime
            ks = zch_e2ee.KeystoreZCH.cargar(args.keystore, args.password)
            ahora = datetime.datetime.now(datetime.timezone.utc)
            reporte = []
            
            def verificar_categoria(claves_dict, tipo):
                for alias, info in claves_dict.items():
                    exp_str = info.get("fecha_expiracion")
                    expirada = False
                    dias_restantes = None
                    if exp_str:
                        clean_exp_str = exp_str
                        if clean_exp_str.endswith('Z'):
                            clean_exp_str = clean_exp_str[:-1] + '+00:00'
                        try:
                            dt_exp = datetime.datetime.fromisoformat(clean_exp_str)
                            expirada = dt_exp < ahora
                            dias_restantes = (dt_exp - ahora).days
                        except Exception:
                            pass
                    reporte.append({
                        "alias": alias,
                        "tipo": tipo,
                        "fecha_expiracion": exp_str,
                        "expirada": expirada,
                        "dias_restantes": dias_restantes,
                        "descripcion": info.get("descripcion", "")
                    })
            
            verificar_categoria(ks.claves_privadas, "privada")
            verificar_categoria(ks.claves_publicas, "publica")
            
            if args.json:
                imprimir_exito("Estado de expiracion verificado.", args.json, {"report": reporte})
            else:
                print("\n--- ESTADO DE EXPIRACIÓN DE CLAVES ---")
                for item in reporte:
                    status = "EXPIRADA" if item["expirada"] else "ACTIVA"
                    exp_info = item["fecha_expiracion"] if item["fecha_expiracion"] else "Nunca"
                    dias_str = f" ({item['dias_restantes']} dias restantes)" if item["dias_restantes"] is not None and not item["expirada"] else ""
                    if item["expirada"]:
                        dias_str = f" (hace {-item['dias_restantes']} dias)" if item["dias_restantes"] is not None else ""
                    print(f"Alias: {item['alias']} ({item['tipo']}) - Estado: {status} - Expira: {exp_info}{dias_str}")
                imprimir_exito("Verificacion de expiracion completada.")
        except Exception as e:
            imprimir_error(f"Fallo al verificar expiracion: {e}", args.json)
            sys.exit(1)

    elif args.command == "encrypt-dir":
        try:
            if args.password:
                kdf_params = obtener_kdf_params(args)
                zch_e2ee.encriptar_directorio_con_password(args.in_dir, args.out_file, args.password, kdf_name=args.kdf, **kdf_params)
            else:
                pub = obtener_publica_desde_args(args, key_rsa_path=args.key_rsa, key_ec_path=args.key_ec, key_alias=args.key_alias)
                if not pub:
                    imprimir_error("Debe especificar --password, --key-rsa, --key-ec o --key-alias para cifrar.", args.json)
                    sys.exit(1)
                if isinstance(pub, rsa.RSAPublicKey):
                    zch_e2ee.encriptar_directorio_e2ee(args.in_dir, args.out_file, pub)
                elif isinstance(pub, x25519.X25519PublicKey):
                    zch_e2ee.encriptar_directorio_e2ee_ec(args.in_dir, args.out_file, pub)
                else:
                    imprimir_error("Tipo de llave pública no soportado para cifrar (debe ser RSA o X25519).", args.json)
                    sys.exit(1)
            imprimir_exito(f"Directorio cifrado guardado en '{args.out_file}'.", args.json, {"out_file": args.out_file})
        except Exception as e:
            imprimir_error(f"Fallo al cifrar directorio: {e}", args.json)
            sys.exit(1)

    elif args.command == "decrypt-dir":
        try:
            if args.password:
                zch_e2ee.desencriptar_directorio_con_password(args.in_file, args.out_dir, args.password)
            else:
                priv = obtener_privada_desde_args(args, key_rsa_path=args.key_rsa, key_ec_path=args.key_ec, key_alias=args.key_alias, key_password=args.key_password)
                if not priv:
                    imprimir_error("Debe especificar --password, --key-rsa, --key-ec o --key-alias para descifrar.", args.json)
                    sys.exit(1)
                
                exito = False
                try:
                    if isinstance(priv, rsa.RSAPrivateKey):
                        zch_e2ee.desencriptar_directorio_e2ee(args.in_file, args.out_dir, priv)
                    elif isinstance(priv, x25519.X25519PrivateKey):
                        zch_e2ee.desencriptar_directorio_e2ee_ec(args.in_file, args.out_dir, priv)
                    else:
                        imprimir_error("Tipo de llave privada no soportado para descifrar (debe ser RSA o X25519).", args.json)
                        sys.exit(1)
                    exito = True
                except (zch_e2ee.ErrorDescifrado, zch_e2ee.CriptoError):
                    if args.key_alias and args.keystore and args.keystore_password:
                        ks = zch_e2ee.KeystoreZCH.cargar(args.keystore, args.keystore_password)
                        historial = ks.obtener_historial_clave_privada(args.key_alias)
                        for priv_hist in historial:
                            try:
                                if isinstance(priv_hist, rsa.RSAPrivateKey):
                                    zch_e2ee.desencriptar_directorio_e2ee(args.in_file, args.out_dir, priv_hist)
                                elif isinstance(priv_hist, x25519.X25519PrivateKey):
                                    zch_e2ee.desencriptar_directorio_e2ee_ec(args.in_file, args.out_dir, priv_hist)
                                else:
                                    continue
                                exito = True
                                break
                            except Exception:
                                continue
                if not exito:
                    raise zch_e2ee.ErrorDescifrado("Fallo al descifrar directorio (incluso usando historial de claves).")
            imprimir_exito(f"Directorio descifrado en '{args.out_dir}'.", args.json, {"out_dir": args.out_dir})
        except Exception as e:
            imprimir_error(f"Fallo al descifrar directorio: {e}", args.json)
            sys.exit(1)

    elif args.command == "encrypt-dir-multi":
        try:
            llaves_publicas = []
            if args.keys_public:
                for path in args.keys_public.split(","):
                    path = path.strip()
                    if path:
                        try:
                            pub = zch_e2ee.cargar_llave_publica_ec_desde_archivo(path)
                        except Exception:
                            pub = zch_e2ee.cargar_llave_publica_desde_archivo(path)
                        llaves_publicas.append(pub)
            
            if args.keys_aliases:
                if not args.keystore or not args.password:
                    imprimir_error("Se requiere --keystore y --password para cargar llaves usando alias.", args.json)
                    sys.exit(1)
                ks = zch_e2ee.KeystoreZCH.cargar(args.keystore, args.password)
                for alias in args.keys_aliases.split(","):
                    alias = alias.strip()
                    if alias:
                        pub = ks.obtener_clave_contacto(alias)
                        llaves_publicas.append(pub)
            
            if not llaves_publicas:
                imprimir_error("Debe especificar al menos una llave pública válida usando --keys-public o --keys-aliases.", args.json)
                sys.exit(1)
                
            zch_e2ee.encriptar_directorio_e2ee_multi(args.in_dir, args.out_file, llaves_publicas)
            imprimir_exito(f"Directorio cifrado guardado en '{args.out_file}'.", args.json, {"out_file": args.out_file})
        except Exception as e:
            imprimir_error(f"Fallo al cifrar directorio multi-destinatario: {e}", args.json)
            sys.exit(1)

    elif args.command == "decrypt-dir-multi":
        try:
            priv = None
            if args.key_private:
                try:
                    priv = zch_e2ee.cargar_llave_privada_ec_desde_archivo(args.key_private, args.key_password)
                except Exception:
                    priv = zch_e2ee.cargar_llave_privada_desde_archivo(args.key_private, args.key_password)
            
            elif args.key_alias:
                if not args.keystore or not args.password:
                    imprimir_error("Se requiere --keystore y --password para cargar la llave usando alias.", args.json)
                    sys.exit(1)
                ks = zch_e2ee.KeystoreZCH.cargar(args.keystore, args.password)
                priv = ks.obtener_clave_privada(args.key_alias)
                
            else:
                imprimir_error("Debe especificar --key-private o --key-alias para descifrar.", args.json)
                sys.exit(1)
                
            exito = False
            try:
                zch_e2ee.desencriptar_directorio_e2ee_multi(args.in_file, args.out_dir, priv)
                exito = True
            except (zch_e2ee.ErrorDescifrado, zch_e2ee.CriptoError):
                if args.key_alias and args.keystore and args.password:
                    ks = zch_e2ee.KeystoreZCH.cargar(args.keystore, args.password)
                    historial = ks.obtener_historial_clave_privada(args.key_alias)
                    for priv_hist in historial:
                        try:
                            zch_e2ee.desencriptar_directorio_e2ee_multi(args.in_file, args.out_dir, priv_hist)
                            exito = True
                            break
                        except Exception:
                            continue
            if not exito:
                raise zch_e2ee.ErrorDescifrado("Fallo al descifrar el directorio multi-destinatario (incluso usando historial de claves).")
            imprimir_exito(f"Directorio descifrado en '{args.out_dir}'.", args.json, {"out_dir": args.out_dir})
        except Exception as e:
            imprimir_error(f"Fallo al descifrar directorio multi-destinatario: {e}", args.json)
            sys.exit(1)

    elif args.command == "encrypt-multi":
        try:
            llaves_publicas = []
            if args.keys_public:
                for path in args.keys_public.split(","):
                    path = path.strip()
                    if path:
                        try:
                            pub = zch_e2ee.cargar_llave_publica_ec_desde_archivo(path)
                        except Exception:
                            pub = zch_e2ee.cargar_llave_publica_desde_archivo(path)
                        llaves_publicas.append(pub)
            
            if args.keys_aliases:
                if not args.keystore or not args.password:
                    imprimir_error("Se requiere --keystore y --password para cargar llaves usando alias.", args.json)
                    sys.exit(1)
                ks = zch_e2ee.KeystoreZCH.cargar(args.keystore, args.password)
                for alias in args.keys_aliases.split(","):
                    alias = alias.strip()
                    if alias:
                        pub = ks.obtener_clave_contacto(alias)
                        llaves_publicas.append(pub)
            
            if not llaves_publicas:
                imprimir_error("Debe especificar al menos una llave pública válida usando --keys-public o --keys-aliases.", args.json)
                sys.exit(1)
                
            zch_e2ee.encriptar_archivo_e2ee_multi(args.in_file, args.out_file, llaves_publicas)
            imprimir_exito(f"Archivo cifrado guardado en '{args.out_file}'.", args.json, {"out_file": args.out_file})
        except Exception as e:
            imprimir_error(f"Fallo al cifrar archivo multi-destinatario: {e}", args.json)
            sys.exit(1)

    elif args.command == "decrypt-multi":
        try:
            priv = None
            if args.key_private:
                try:
                    priv = zch_e2ee.cargar_llave_privada_ec_desde_archivo(args.key_private, args.key_password)
                except Exception:
                    priv = zch_e2ee.cargar_llave_privada_desde_archivo(args.key_private, args.key_password)
            
            elif args.key_alias:
                if not args.keystore or not args.password:
                    imprimir_error("Se requiere --keystore y --password para cargar la llave usando alias.", args.json)
                    sys.exit(1)
                ks = zch_e2ee.KeystoreZCH.cargar(args.keystore, args.password)
                priv = ks.obtener_clave_privada(args.key_alias)
                
            else:
                imprimir_error("Debe especificar --key-private o --key-alias para descifrar.", args.json)
                sys.exit(1)
                
            exito = False
            try:
                zch_e2ee.desencriptar_archivo_e2ee_multi(args.in_file, args.out_file, priv)
                exito = True
            except (zch_e2ee.ErrorDescifrado, zch_e2ee.CriptoError):
                if args.key_alias and args.keystore and args.password:
                    ks = zch_e2ee.KeystoreZCH.cargar(args.keystore, args.password)
                    historial = ks.obtener_historial_clave_privada(args.key_alias)
                    for priv_hist in historial:
                        try:
                            zch_e2ee.desencriptar_archivo_e2ee_multi(args.in_file, args.out_file, priv_hist)
                            exito = True
                            break
                        except Exception:
                            continue
            if not exito:
                raise zch_e2ee.ErrorDescifrado("Fallo al descifrar el archivo multi-destinatario (incluso usando historial de claves).")
            imprimir_exito(f"Archivo descifrado en '{args.out_file}'.", args.json, {"out_file": args.out_file})
        except Exception as e:
            imprimir_error(f"Fallo al descifrar archivo multi-destinatario: {e}", args.json)
            sys.exit(1)

    elif args.command == "encrypt-text-multi":
        try:
            texto = args.text
            if not texto and args.stdin:
                texto = sys.stdin.read()
            if not texto:
                imprimir_error("Debe proporcionar el texto a cifrar usando --text o --stdin.", args.json)
                sys.exit(1)
                
            llaves_publicas = []
            if args.keys_public:
                for path in args.keys_public.split(","):
                    path = path.strip()
                    if path:
                        try:
                            pub = zch_e2ee.cargar_llave_publica_ec_desde_archivo(path)
                        except Exception:
                            pub = zch_e2ee.cargar_llave_publica_desde_archivo(path)
                        llaves_publicas.append(pub)
            
            if args.keys_aliases:
                if not args.keystore or not args.password:
                    imprimir_error("Se requiere --keystore y --password para cargar llaves usando alias.", args.json)
                    sys.exit(1)
                ks = zch_e2ee.KeystoreZCH.cargar(args.keystore, args.password)
                for alias in args.keys_aliases.split(","):
                    alias = alias.strip()
                    if alias:
                        pub = ks.obtener_clave_contacto(alias)
                        llaves_publicas.append(pub)
            
            if not llaves_publicas:
                imprimir_error("Debe especificar al menos una llave pública válida usando --keys-public o --keys-aliases.", args.json)
                sys.exit(1)
                
            cifrado = zch_e2ee.encriptar_e2ee_multi(texto, llaves_publicas)
            if args.json:
                imprimir_exito("Texto cifrado.", args.json, {"cipher": cifrado})
            else:
                if args.stdout:
                    sys.stdout.write(cifrado)
                else:
                    print(cifrado)
        except Exception as e:
            imprimir_error(f"Fallo al cifrar texto multi-destinatario: {e}", args.json)
            sys.exit(1)

    elif args.command == "decrypt-text-multi":
        try:
            texto_cifrado = args.text
            if not texto_cifrado and args.stdin:
                texto_cifrado = sys.stdin.read().strip()
            if not texto_cifrado:
                imprimir_error("Debe proporcionar el texto cifrado usando --text o --stdin.", args.json)
                sys.exit(1)
                
            priv = None
            if args.key_private:
                try:
                    priv = zch_e2ee.cargar_llave_privada_ec_desde_archivo(args.key_private, args.key_password)
                except Exception:
                    priv = zch_e2ee.cargar_llave_privada_desde_archivo(args.key_private, args.key_password)
            
            elif args.key_alias:
                if not args.keystore or not args.password:
                    imprimir_error("Se requiere --keystore y --password para cargar la llave usando alias.", args.json)
                    sys.exit(1)
                ks = zch_e2ee.KeystoreZCH.cargar(args.keystore, args.password)
                priv = ks.obtener_clave_privada(args.key_alias)
                
            else:
                imprimir_error("Debe especificar --key-private o --key-alias para descifrar.", args.json)
                sys.exit(1)
                
            exito = False
            descifrado = None
            try:
                descifrado = zch_e2ee.desencriptar_e2ee_multi(texto_cifrado, priv)
                exito = True
            except (zch_e2ee.ErrorDescifrado, zch_e2ee.CriptoError):
                if args.key_alias and args.keystore and args.password:
                    ks = zch_e2ee.KeystoreZCH.cargar(args.keystore, args.password)
                    historial = ks.obtener_historial_clave_privada(args.key_alias)
                    for priv_hist in historial:
                        try:
                            descifrado = zch_e2ee.desencriptar_e2ee_multi(texto_cifrado, priv_hist)
                            exito = True
                            break
                        except Exception:
                            continue
            if not exito:
                raise zch_e2ee.ErrorDescifrado("Fallo al descifrar el texto multi-destinatario (incluso usando historial de claves).")
                
            if args.json:
                imprimir_exito("Texto descifrado.", args.json, {"plain": descifrado})
            else:
                if args.stdout:
                    sys.stdout.write(descifrado)
                else:
                    print(descifrado)
        except Exception as e:
            imprimir_error(f"Fallo al descifrar texto multi-destinatario: {e}", args.json)
            sys.exit(1)

    elif args.command == "ratchet-init":
        try:
            priv = obtener_privada_desde_args(
                args,
                key_ec_path=args.key_private,
                key_alias=args.key_private_alias,
                key_password=args.key_password
            )
            pub = obtener_publica_desde_args(
                args,
                key_ec_path=args.key_public,
                key_alias=args.key_public_alias
            )
            
            if not priv or not pub:
                imprimir_error("Debe especificar las llaves privada y pública correspondientes (usando archivos o alias del Keystore).", args.json)
                sys.exit(1)
            
            sesion = zch_e2ee.SesionDoubleRatchet(priv, pub, args.initiator)
            state = serializar_sesion_ratchet(sesion)
            
            with open(args.out_session, 'w', encoding='utf-8') as f:
                json.dump(state, f, indent=2)
                
            imprimir_exito(f"Sesion Double Ratchet inicializada en '{args.out_session}'.", args.json, {"session_file": args.out_session})
        except Exception as e:
            imprimir_error(f"Fallo al inicializar sesion Double Ratchet: {e}", args.json)
            sys.exit(1)

    elif args.command == "ratchet-encrypt":
        try:
            with open(args.session, 'r', encoding='utf-8') as f:
                state = json.load(f)
            sesion = deserializar_sesion_ratchet(state)
            
            if args.stdin:
                mensaje = sys.stdin.read()
            else:
                if args.text is None:
                    imprimir_error("Debe especificar --text o usar --stdin.", args.json)
                    sys.exit(1)
                mensaje = args.text
                
            cifrado = sesion.enviar_mensaje(mensaje)
            
            new_state = serializar_sesion_ratchet(sesion)
            with open(args.out_session, 'w', encoding='utf-8') as f:
                json.dump(new_state, f, indent=2)
                
            if args.json:
                imprimir_exito("Mensaje cifrado con Double Ratchet.", args.json, {"cipher": cifrado, "out_session": args.out_session})
            else:
                if args.stdout:
                    sys.stdout.write(cifrado)
                else:
                    print(cifrado)
        except Exception as e:
            imprimir_error(f"Fallo al cifrar con Double Ratchet: {e}", args.json)
            sys.exit(1)

    elif args.command == "ratchet-decrypt":
        try:
            with open(args.session, 'r', encoding='utf-8') as f:
                state = json.load(f)
            sesion = deserializar_sesion_ratchet(state)
            
            if args.stdin:
                texto_cifrado = sys.stdin.read()
            else:
                if args.text is None:
                    imprimir_error("Debe especificar --text o usar --stdin.", args.json)
                    sys.exit(1)
                texto_cifrado = args.text
                
            descifrado = sesion.recibir_mensaje(texto_cifrado)
            
            new_state = serializar_sesion_ratchet(sesion)
            with open(args.out_session, 'w', encoding='utf-8') as f:
                json.dump(new_state, f, indent=2)
                
            if args.json:
                imprimir_exito("Mensaje descifrado con Double Ratchet.", args.json, {"plain": descifrado, "out_session": args.out_session})
            else:
                if args.stdout:
                    sys.stdout.write(descifrado)
                else:
                    print(descifrado)
        except Exception as e:
            imprimir_error(f"Fallo al descifrar con Double Ratchet: {e}", args.json)
            sys.exit(1)

    elif args.command == "shamir-reconstruct":
        try:
            partes = []
            for parte_str in args.shares.split(","):
                parte_str = parte_str.strip()
                if not parte_str:
                    continue
                try:
                    idx_str, parte_b64 = parte_str.split("-", 1)
                    idx = int(idx_str)
                    datos = base64.b64decode(parte_b64.encode('utf-8'))
                    partes.append((idx, datos))
                except Exception:
                    imprimir_error(f"Formato de parte invalido: '{parte_str}'. Debe ser 'Indice-Base64'.", args.json)
                    sys.exit(1)
            
            if not partes:
                imprimir_error("No se ingresaron partes validas.", args.json)
                sys.exit(1)
                
            secreto_bytes = zch_e2ee.reconstruir_secreto_shamir(partes)
            secreto_str = secreto_bytes.decode('utf-8', errors='ignore')
            
            if args.json:
                imprimir_exito("Secreto reconstruido.", args.json, {"secret": secreto_str})
            else:
                if args.stdout:
                    sys.stdout.write(secreto_str)
                else:
                    print(secreto_str)
        except Exception as e:
            imprimir_error(f"Fallo al reconstruir secreto de Shamir: {e}", args.json)
            sys.exit(1)

if __name__ == "__main__":
    main()
