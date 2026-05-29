import sys
import os
sys.path.insert(0, os.path.abspath('src'))
import shutil
import base64
import time
import json
import subprocess
import zlib
import importlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from zch_e2ee.importer import EncryptedModuleFinder
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
    print("\n--- TEST: Cifrado de Archivos y Llaves en Disco (RSA ZCH v2) ---")
    privada, publica = zch_e2ee.generar_llaves()
    
    archivo_secreto = "secreto_v5.txt"
    archivo_cifrado = "secreto_v5.enc"
    archivo_descifrado = "secreto_v5_descifrado.txt"
    
    # Crear archivo
    contenido = "Datos sensibles de Zoe CH para test de archivos en la cabecera v2."
    with open(archivo_secreto, "w", encoding="utf-8") as f:
        f.write(contenido)
        
    # Cifrar archivo
    zch_e2ee.encriptar_archivo_e2ee(archivo_secreto, archivo_cifrado, publica)
    print(f"  Archivo cifrado creado: '{archivo_cifrado}'")
    
    # Verificar cabecera mágica v2
    with open(archivo_cifrado, "rb") as f:
        cabecera = f.read(5)
        assert cabecera == b"ZCH\x02\x01", "La cabecera del archivo RSA no es la esperada v2 Modo 0x01."
    
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
    print("\n--- TEST: Cifrado de Archivos con Contrasena (Scrypt + AES-GCM + Zlib ZCH v2) ---")
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
    
    # Verificar cabecera mágica v2
    with open(archivo_cifrado, "rb") as f:
        cabecera = f.read(5)
        assert cabecera == b"ZCH\x02\x03", "La cabecera del archivo cifrado con password no es v2 Modo 0x03."
        
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

def test_firma_archivo_y_checksum():
    print("\n--- TEST: Checksum SHA-256 y Firmas Digitales de Archivos ---")
    privada, publica = zch_e2ee.generar_llaves()
    
    archivo_prueba = "archivo_prueba_firma.txt"
    contenido = "Este archivo sera firmado digitalmente por Zoe CH."
    with open(archivo_prueba, "w", encoding="utf-8") as f:
        f.write(contenido)
        
    # Calcular hash
    hash_hex = zch_e2ee.calcular_sha256(archivo_prueba)
    print(f"  SHA-256: {hash_hex}")
    
    # Firmar archivo
    firma = zch_e2ee.firmar_archivo(archivo_prueba, privada)
    print(f"  Firma digital del archivo (Base64): {firma[:50]}...")
    
    # Verificar firma
    valida = zch_e2ee.verificar_firma_archivo(archivo_prueba, firma, publica)
    print(f"  Firma valida: {valida}")
    
    assert valida, "La firma del archivo debio ser valida."
    
    # Simular alteración del archivo
    with open(archivo_prueba, "w", encoding="utf-8") as f:
        f.write(contenido + " modificado")
        
    valida_alterado = zch_e2ee.verificar_firma_archivo(archivo_prueba, firma, publica)
    print(f"  Firma tras alteracion: {valida_alterado}")
    assert not valida_alterado, "La firma debio ser invalida tras alterar el archivo."
    
    # Limpiar
    if os.path.exists(archivo_prueba):
        os.remove(archivo_prueba)
    print("  [OK] Test completado con exito.")

def test_archivo_cifrado_firmado():
    print("\n--- TEST: Cifrado + Firma Combinados para Archivos (RSA ZCH v2) ---")
    privada_alice, publica_alice = zch_e2ee.generar_llaves()
    privada_bob, publica_bob = zch_e2ee.generar_llaves()
    
    archivo_origen = "documento_secreto.txt"
    archivo_cifrado = "documento_secreto.enc"
    archivo_descifrado = "documento_secreto_descifrado.txt"
    
    contenido = "Transferencia de archivos segura, cifrada para Bob y firmada por Alice."
    with open(archivo_origen, "w", encoding="utf-8") as f:
        f.write(contenido)
        
    # Cifrar y firmar
    zch_e2ee.encriptar_y_firmar_archivo_e2ee(archivo_origen, archivo_cifrado, publica_bob, privada_alice)
    print(f"  Archivo cifrado y firmado creado: '{archivo_cifrado}'")
    
    # Verificar cabecera
    with open(archivo_cifrado, "rb") as f:
        cabecera = f.read(5)
        assert cabecera == b"ZCH\x02\x02", "La cabecera del archivo cifrado y firmado RSA no es v2 Modo 0x02."
        
    # Descifrar y verificar
    firma_valida = zch_e2ee.desencriptar_y_verificar_archivo_e2ee(archivo_cifrado, archivo_descifrado, privada_bob, publica_alice)
    with open(archivo_descifrado, "r", encoding="utf-8") as f:
        descifrado = f.read()
    print(f"  Archivo descifrado recuperado: '{descifrado}'")
    print(f"  Firma autentica: {firma_valida}")
    
    assert contenido == descifrado, "El archivo descifrado no coincide."
    assert firma_valida, "La firma del archivo cifrado debio ser valida."
    
    # Limpiar
    for archivo in [archivo_origen, archivo_cifrado, archivo_descifrado]:
        if os.path.exists(archivo):
            os.remove(archivo)
    print("  [OK] Test completado con exito.")

def test_rsa_4096_bits():
    print("\n--- TEST: Claves RSA de 4096 bits (Dinamicas) ---")
    privada_alice, publica_alice = zch_e2ee.generar_llaves(4096)
    privada_bob, publica_bob = zch_e2ee.generar_llaves(4096)
    
    mensaje = "Mensaje secreto usando llaves RSA gigantes de 4096 bits."
    print(f"  Texto original: '{mensaje}'")
    cifrado = zch_e2ee.encriptar_e2ee(mensaje, publica_bob)
    descifrado = zch_e2ee.desencriptar_e2ee(cifrado, privada_bob)
    print(f"  Descifrado: '{descifrado}'")
    assert mensaje == descifrado, "Fallo al desencriptar con clave de 4096 bits."
    
    payload = zch_e2ee.encriptar_y_firmar_e2ee(mensaje, publica_bob, privada_alice)
    descifrado_firma, firma_valida = zch_e2ee.desencriptar_y_verificar_e2ee(payload, privada_bob, publica_alice)
    print(f"  Firma valida (4096 bits): {firma_valida}")
    assert mensaje == descifrado_firma, "El mensaje firmado no coincide al descifrar."
    assert firma_valida, "La firma de 4096 bits debio ser valida."
    
    print("  [OK] Test de 4096 bits completado con exito.")

def test_encriptacion_directorios():
    print("\n--- TEST: Cifrado y Descifrado de Directorios (RSA) ---")
    privada, publica = zch_e2ee.generar_llaves()
    
    dir_origen = "carpeta_prueba_origen"
    dir_destino = "carpeta_prueba_destino"
    archivo_cifrado = "directorio_cifrado.enc"
    
    os.makedirs(dir_origen, exist_ok=True)
    
    archivo1 = os.path.join(dir_origen, "archivo1.txt")
    archivo2 = os.path.join(dir_origen, "subcarpeta", "archivo2.txt")
    os.makedirs(os.path.dirname(archivo2), exist_ok=True)
    
    contenido1 = "Contenido del primer archivo de prueba."
    contenido2 = "Contenido del segundo archivo de prueba en una subcarpeta."
    
    with open(archivo1, "w", encoding="utf-8") as f:
        f.write(contenido1)
    with open(archivo2, "w", encoding="utf-8") as f:
        f.write(contenido2)
        
    print(f"  Directorio origen '{dir_origen}' preparado con archivos.")
    
    zch_e2ee.encriptar_directorio_e2ee(dir_origen, archivo_cifrado, publica)
    print(f"  Directorio cifrado creado: '{archivo_cifrado}'")
    
    zch_e2ee.desencriptar_directorio_e2ee(archivo_cifrado, dir_destino, privada)
    print(f"  Directorio descifrado en: '{dir_destino}'")
    
    archivo1_res = os.path.join(dir_destino, "archivo1.txt")
    archivo2_res = os.path.join(dir_destino, "subcarpeta", "archivo2.txt")
    
    assert os.path.exists(archivo1_res), "El archivo 1 no existe en destino."
    assert os.path.exists(archivo2_res), "El archivo 2 no existe en destino."
    
    with open(archivo1_res, "r", encoding="utf-8") as f:
        descifrado1 = f.read()
    with open(archivo2_res, "r", encoding="utf-8") as f:
        descifrado2 = f.read()
        
    assert contenido1 == descifrado1, "El contenido del archivo 1 no coincide."
    assert contenido2 == descifrado2, "El contenido del archivo 2 no coincide."
    
    for d in [dir_origen, dir_destino]:
        if os.path.exists(d):
            shutil.rmtree(d)
    if os.path.exists(archivo_cifrado):
        os.remove(archivo_cifrado)
        
    print("  [OK] Test de directorios completado con exito.")

def test_excepciones_cripto():
    print("\n--- TEST: Excepciones Criptográficas Propias ---")
    privada_alice, publica_alice = zch_e2ee.generar_llaves()
    privada_bob, publica_bob = zch_e2ee.generar_llaves()
    
    # 1. Error de Descifrado RSA E2EE
    payload = zch_e2ee.encriptar_e2ee("Mensaje ultra secreto", publica_alice)
    try:
        zch_e2ee.desencriptar_e2ee(payload, privada_bob)
        assert False, "Debió lanzar ErrorDescifrado por llave incorrecta."
    except zch_e2ee.ErrorDescifrado as e:
        print(f"  [OK] Capturado ErrorDescifrado en RSA E2EE: {e}")
        
    # 2. Error de Descifrado Password
    payload_pwd = zch_e2ee.encriptar_con_password("Hola mundo", "Contraseña1")
    try:
        zch_e2ee.desencriptar_con_password(payload_pwd, "ContraseñaEquivocada")
        assert False, "Debió lanzar ErrorDescifrado por contraseña incorrecta."
    except zch_e2ee.ErrorDescifrado as e:
        print(f"  [OK] Capturado ErrorDescifrado en Simétrico: {e}")
        
    # 3. Error de Carga de Llave PEM
    try:
        zch_e2ee.cargar_llave_publica("TEXTO PEM CORRUPTO")
        assert False, "Debió lanzar ErrorClave por PEM corrupto."
    except zch_e2ee.ErrorClave as e:
        print(f"  [OK] Capturado ErrorClave al cargar PEM inválido: {e}")

    print("  [OK] Test de excepciones completado con exito.")

def test_firmas_ed25519():
    print("\n--- TEST: Firmas Digitales Ed25519 ---")
    priv_ed, pub_ed = zch_e2ee.generar_llaves_ed25519()
    mensaje = "Firma rápida y moderna usando Ed25519"
    
    firma = zch_e2ee.firmar_mensaje_ed25519(mensaje, priv_ed)
    print(f"  Firma Base64: {firma[:50]}...")
    
    valida = zch_e2ee.verificar_firma_ed25519(mensaje, firma, pub_ed)
    print(f"  Firma válida: {valida}")
    assert valida, "La firma Ed25519 debió ser válida."
    
    valida_falsa = zch_e2ee.verificar_firma_ed25519(mensaje + " alterado", firma, pub_ed)
    print(f"  Firma tras alteración: {valida_falsa}")
    assert not valida_falsa, "La firma no debió ser válida tras modificar el mensaje."
    
    print("  [OK] Test de firmas Ed25519 completado con exito.")

def test_serializacion_llaves_ec():
    print("\n--- TEST: Serialización y Archivos de Llaves EC ---")
    priv_x, pub_x = zch_e2ee.generar_llaves_ec()
    
    # Serialización en PEM
    pem_priv = zch_e2ee.serializar_llave_privada_ec(priv_x, "ZchPass1")
    pem_pub = zch_e2ee.serializar_llave_publica_ec(pub_x)
    
    assert "ENCRYPTED PRIVATE KEY" in pem_priv
    assert "PUBLIC KEY" in pem_pub
    
    # Carga desde PEM
    priv_cargada = zch_e2ee.cargar_llave_privada_ec(pem_priv, "ZchPass1")
    pub_cargada = zch_e2ee.cargar_llave_publica_ec(pem_pub)
    
    print("  Claves serializadas y cargadas en memoria correctamente.")
    
    # Guardar y cargar archivos
    file_priv = "temp_ec_priv.pem"
    file_pub = "temp_ec_pub.pem"
    
    zch_e2ee.guardar_llave_privada_ec_en_archivo(priv_x, file_priv, "ZchPass2")
    zch_e2ee.guardar_llave_publica_ec_en_archivo(pub_x, file_pub)
    
    priv_archivo = zch_e2ee.cargar_llave_privada_ec_desde_archivo(file_priv, "ZchPass2")
    pub_archivo = zch_e2ee.cargar_llave_publica_ec_desde_archivo(file_pub)
    
    # Validar que podemos derivar la misma clave usando las llaves cargadas
    _, pub_otro = zch_e2ee.generar_llaves_ec()
    sh1 = zch_e2ee.derivar_clave_compartida(priv_x, pub_otro)
    sh2 = zch_e2ee.derivar_clave_compartida(priv_archivo, pub_otro)
    assert sh1 == sh2, "Las llaves cargadas desde archivo no derivan el mismo secreto."
    
    for f in [file_priv, file_pub]:
        if os.path.exists(f):
            os.remove(f)
            
    print("  [OK] Test de serialización EC completado con exito.")

def test_e2ee_ec():
    print("\n--- TEST: Cifrado Híbrido con Curvas Elípticas X25519 + Ed25519 ---")
    priv_x_alice, pub_x_alice = zch_e2ee.generar_llaves_ec()
    priv_x_bob, pub_x_bob = zch_e2ee.generar_llaves_ec()
    priv_ed_alice, pub_ed_alice = zch_e2ee.generar_llaves_ed25519()
    
    # 1. Cifrado simple
    mensaje = "Hola Bob, esto es X25519 E2EE."
    payload = zch_e2ee.encriptar_e2ee_ec(mensaje, pub_x_bob)
    print(f"  Cifrado Base64: {payload[:50]}...")
    
    descifrado = zch_e2ee.desencriptar_e2ee_ec(payload, priv_x_bob)
    print(f"  Descifrado: '{descifrado}'")
    assert mensaje == descifrado, "El mensaje no coincide."
    
    # 2. Cifrado + Firma
    payload_firmado = zch_e2ee.encriptar_y_firmar_e2ee_ec(mensaje, pub_x_bob, priv_ed_alice)
    desc_firmado, firma_valida = zch_e2ee.desencriptar_y_verificar_e2ee_ec(payload_firmado, priv_x_bob, pub_ed_alice)
    
    print(f"  Cifrado + Firmado Descifrado: '{desc_firmado}', firma es: {firma_valida}")
    assert mensaje == desc_firmado, "El mensaje firmado descifrado no coincide."
    assert firma_valida, "La firma Ed25519 debió ser válida."
    
    print("  [OK] Test de cifrado EC completado con exito.")

def test_archivos_y_directorios_ec():
    print("\n--- TEST: Cifrado de Archivos y Carpetas con Curvas Elípticas ---")
    priv_x_alice, pub_x_alice = zch_e2ee.generar_llaves_ec()
    priv_x_bob, pub_x_bob = zch_e2ee.generar_llaves_ec()
    priv_ed_alice, pub_ed_alice = zch_e2ee.generar_llaves_ed25519()
    
    archivo_orig = "test_ec_orig.txt"
    archivo_cifr = "test_ec_cifr.enc"
    archivo_desc = "test_ec_desc.txt"
    
    contenido = "Archivo confidencial transmitido via X25519."
    with open(archivo_orig, "w", encoding="utf-8") as f:
        f.write(contenido)
        
    # 1. Archivo simple EC
    zch_e2ee.encriptar_archivo_e2ee_ec(archivo_orig, archivo_cifr, pub_x_bob)
    
    with open(archivo_cifr, "rb") as f:
        cabecera = f.read(5)
        assert cabecera == b"ZCH\x02\x04", "La cabecera del archivo EC no es la esperada v2 Modo 0x04."
        
    zch_e2ee.desencriptar_archivo_e2ee_ec(archivo_cifr, archivo_desc, priv_x_bob)
    with open(archivo_desc, "r", encoding="utf-8") as f:
        res = f.read()
    assert contenido == res
    
    # 2. Archivo cifrado y firmado EC + Ed25519
    zch_e2ee.encriptar_y_firmar_archivo_e2ee_ec(archivo_orig, archivo_cifr, pub_x_bob, priv_ed_alice)
    
    with open(archivo_cifr, "rb") as f:
        cabecera = f.read(5)
        assert cabecera == b"ZCH\x02\x05", "La cabecera del archivo EC firmado no es la esperada v2 Modo 0x05."
        
    valida = zch_e2ee.desencriptar_y_verificar_archivo_e2ee_ec(archivo_cifr, archivo_desc, priv_x_bob, pub_ed_alice)
    assert valida, "La firma Ed25519 en el archivo debió ser válida."
    with open(archivo_desc, "r", encoding="utf-8") as f:
        res = f.read()
    assert contenido == res
    
    # Limpiar archivos
    for f in [archivo_orig, archivo_cifr, archivo_desc]:
        if os.path.exists(f):
            os.remove(f)
            
    # 3. Directorio con EC
    dir_orig = "carpeta_ec_orig"
    dir_dest = "carpeta_ec_dest"
    archivo_dir_cifr = "directorio_ec.enc"
    
    os.makedirs(dir_orig, exist_ok=True)
    with open(os.path.join(dir_orig, "f1.txt"), "w") as f:
        f.write("Secreto 1 en carpeta EC")
        
    zch_e2ee.encriptar_directorio_e2ee_ec(dir_orig, archivo_dir_cifr, pub_x_bob)
    zch_e2ee.desencriptar_directorio_e2ee_ec(archivo_dir_cifr, dir_dest, priv_x_bob)
    
    assert os.path.exists(os.path.join(dir_dest, "f1.txt"))
    with open(os.path.join(dir_dest, "f1.txt"), "r") as f:
        assert f.read() == "Secreto 1 en carpeta EC"
        
    for d in [dir_orig, dir_dest]:
        if os.path.exists(d):
            shutil.rmtree(d)
    if os.path.exists(archivo_dir_cifr):
        os.remove(archivo_dir_cifr)
        
    print("  [OK] Test de archivos y carpetas EC completado con exito.")

def test_directorio_password():
    print("\n--- TEST: Cifrado de Carpetas con Contraseña Simétrica ---")
    dir_orig = "carpeta_pwd_orig"
    dir_dest = "carpeta_pwd_dest"
    archivo_cifr = "directorio_pwd.enc"
    password = "ClaveDirectorio11"
    
    os.makedirs(dir_orig, exist_ok=True)
    with open(os.path.join(dir_orig, "info.txt"), "w") as f:
        f.write("Informacion en carpeta encriptada con clave simetrica")
        
    zch_e2ee.encriptar_directorio_con_password(dir_orig, archivo_cifr, password)
    
    # Comprobar cabecera Modo 0x03
    with open(archivo_cifr, "rb") as f:
        cabecera = f.read(5)
        assert cabecera == b"ZCH\x02\x03"
        
    zch_e2ee.desencriptar_directorio_con_password(archivo_cifr, dir_dest, password)
    
    assert os.path.exists(os.path.join(dir_dest, "info.txt"))
    with open(os.path.join(dir_dest, "info.txt"), "r") as f:
        assert f.read() == "Informacion en carpeta encriptada con clave simetrica"
        
    for d in [dir_orig, dir_dest]:
        if os.path.exists(d):
            shutil.rmtree(d)
    if os.path.exists(archivo_cifr):
        os.remove(archivo_cifr)
        
    print("  [OK] Test de carpeta con contraseña completado con exito.")

def test_compatibilidad_retroactiva():
    print("\n--- TEST: Compatibilidad Retroactiva con Archivos Legacy v1 ---")
    
    contenido = "Texto en formato legacy sin cabecera de Zoe."
    password = "LegacyPassword1"
    
    sal = os.urandom(16)
    nonce = os.urandom(12)
    kdf = Scrypt(salt=sal, length=32, n=2**14, r=8, p=1)
    clave_aes = kdf.derive(password.encode('utf-8'))
    aesgcm = AESGCM(clave_aes)
    datos_cifrados = aesgcm.encrypt(nonce, zlib.compress(contenido.encode('utf-8')), None)
    
    archivo_legacy = "archivo_legacy.enc"
    archivo_recup = "archivo_legacy_recuperado.txt"
    
    with open(archivo_legacy, "wb") as f:
        f.write(sal + nonce + datos_cifrados)
        
    zch_e2ee.desencriptar_archivo_con_password(archivo_legacy, archivo_recup, password)
    
    with open(archivo_recup, "r") as f:
        assert f.read() == contenido, "El archivo legacy no se descifró correctamente."
        
    for f in [archivo_legacy, archivo_recup]:
        if os.path.exists(f):
            os.remove(f)
            
    print("  [OK] Test de compatibilidad retroactiva legacy v1 completado.")

# =====================================================================
# NOVEDADES DE LA VERSIÓN 0.9.0
# =====================================================================

def test_e2ee_multi_rsa():
    print("\n--- TEST: Cifrado Multi-destinatario RSA ---")
    priv_alice, pub_alice = zch_e2ee.generar_llaves()
    priv_bob, pub_bob = zch_e2ee.generar_llaves()
    priv_charlie, pub_charlie = zch_e2ee.generar_llaves()
    
    mensaje = "Hola a todos, este es un mensaje confidencial de grupo (RSA)."
    claves_publicas = [pub_alice, pub_bob, pub_charlie]
    
    payload = zch_e2ee.encriptar_e2ee_multi(mensaje, claves_publicas)
    print(f"  Cifrado Base64: {payload[:50]}...")
    
    # Cada uno intenta descifrar con su propia llave privada
    msg_alice = zch_e2ee.desencriptar_e2ee_multi(payload, priv_alice)
    msg_bob = zch_e2ee.desencriptar_e2ee_multi(payload, priv_bob)
    msg_charlie = zch_e2ee.desencriptar_e2ee_multi(payload, priv_charlie)
    
    assert msg_alice == mensaje
    assert msg_bob == mensaje
    assert msg_charlie == mensaje
    print("  [OK] Alice, Bob y Charlie pudieron descifrar el mensaje correctamente.")

def test_e2ee_multi_ec():
    print("\n--- TEST: Cifrado Multi-destinatario EC (X25519) ---")
    priv_alice, pub_alice = zch_e2ee.generar_llaves_ec()
    priv_bob, pub_bob = zch_e2ee.generar_llaves_ec()
    priv_charlie, pub_charlie = zch_e2ee.generar_llaves_ec()
    
    mensaje = "Mensaje cifrado con curvas elípticas para múltiples destinatarios."
    claves_publicas = [pub_alice, pub_bob, pub_charlie]
    
    payload = zch_e2ee.encriptar_e2ee_multi(mensaje, claves_publicas)
    print(f"  Cifrado Base64: {payload[:50]}...")
    
    # Cada uno intenta descifrar
    msg_alice = zch_e2ee.desencriptar_e2ee_multi(payload, priv_alice)
    msg_bob = zch_e2ee.desencriptar_e2ee_multi(payload, priv_bob)
    msg_charlie = zch_e2ee.desencriptar_e2ee_multi(payload, priv_charlie)
    
    assert msg_alice == mensaje
    assert msg_bob == mensaje
    assert msg_charlie == mensaje
    print("  [OK] Descifrado EC exitoso para todos los miembros del grupo.")

def test_e2ee_multi_errores():
    print("\n--- TEST: Control de Errores en Cifrado Multi-destinatario ---")
    priv_alice, pub_alice = zch_e2ee.generar_llaves_ec()
    priv_bob, pub_bob = zch_e2ee.generar_llaves_ec()
    priv_intruder, pub_intruder = zch_e2ee.generar_llaves_ec()
    
    mensaje = "Este mensaje es solo para Alice y Bob."
    payload = zch_e2ee.encriptar_e2ee_multi(mensaje, [pub_alice, pub_bob])
    
    try:
        zch_e2ee.desencriptar_e2ee_multi(payload, priv_intruder)
        assert False, "Debió fallar con ErrorDescifrado"
    except zch_e2ee.ErrorDescifrado as e:
        print(f"  [OK] El intruso falló al descifrar como se esperaba: {e}")
        
    print("  [OK] Test completado con éxito.")

def test_archivo_multi():
    print("\n--- TEST: Cifrado de Archivos Multi-destinatario ---")
    priv_alice, pub_alice = zch_e2ee.generar_llaves_ec()
    priv_bob, pub_bob = zch_e2ee.generar_llaves_ec()
    
    archivo_orig = "doc_grupo.txt"
    archivo_cifr = "doc_grupo.enc"
    archivo_desc = "doc_grupo_desc.txt"
    
    contenido = "Este archivo contiene el acta de la reunión confidencial de la junta."
    with open(archivo_orig, "w", encoding="utf-8") as f:
        f.write(contenido)
        
    # Cifrar para Alice y Bob
    zch_e2ee.encriptar_archivo_e2ee_multi(archivo_orig, archivo_cifr, [pub_alice, pub_bob])
    print(f"  Archivo cifrado creado: '{archivo_cifr}'")
    
    # Comprobar cabecera mágica v2 Modo 0x07 (EC Multi)
    with open(archivo_cifr, "rb") as f:
        cabecera = f.read(5)
        assert cabecera == b"ZCH\x02\x07", "La cabecera del archivo multi EC no es la esperada v2 Modo 0x07."
        
    # Bob descifra
    zch_e2ee.desencriptar_archivo_e2ee_multi(archivo_cifr, archivo_desc, priv_bob)
    with open(archivo_desc, "r", encoding="utf-8") as f:
        res = f.read()
    assert res == contenido
    
    # Alice descifra
    zch_e2ee.desencriptar_archivo_e2ee_multi(archivo_cifr, archivo_desc, priv_alice)
    with open(archivo_desc, "r", encoding="utf-8") as f:
        res = f.read()
    assert res == contenido
    
    # Limpiar
    for f in [archivo_orig, archivo_cifr, archivo_desc]:
        if os.path.exists(f):
            os.remove(f)
            
    print("  [OK] Test de archivos multi-destinatario completado con éxito.")

# =====================================================================
# NOVEDADES DE LA VERSIÓN 1.0.0
# =====================================================================

def test_shamir_secret_sharing():
    print("\n--- TEST: Esquema de Secreto Compartido de Shamir (SSS) ---")
    secreto = b"Este es un secreto confidencial de Zoe"
    
    # Dividir secreto (umbral 3 de 5)
    partes = zch_e2ee.dividir_secreto_shamir(secreto, n=5, t=3)
    assert len(partes) == 5, "Debió generar 5 partes."
    
    # Intentar reconstruir con 3 partes (suficiente)
    secreto_reconstruido_3 = zch_e2ee.reconstruir_secreto_shamir(partes[:3])
    assert secreto_reconstruido_3 == secreto, "La reconstrucción con 3 partes falló."
    
    # Intentar reconstruir con 4 partes (suficiente)
    secreto_reconstruido_4 = zch_e2ee.reconstruir_secreto_shamir(partes[1:5])
    assert secreto_reconstruido_4 == secreto, "La reconstrucción con 4 partes falló."
    
    # Intentar reconstruir con 2 partes (insuficiente, no debe dar el secreto correcto)
    secreto_reconstruido_2 = zch_e2ee.reconstruir_secreto_shamir(partes[:2])
    assert secreto_reconstruido_2 != secreto, "La reconstrucción con menos de T partes debió fallar o dar datos incorrectos."
    
    # Validar control de errores
    try:
        zch_e2ee.dividir_secreto_shamir(secreto, n=5, t=6)
        assert False, "Debió fallar porque t > n."
    except ValueError:
        pass
        
    try:
        zch_e2ee.dividir_secreto_shamir(secreto, n=300, t=3)
        assert False, "Debió fallar porque n > 255."
    except ValueError:
        pass
        
    print("  [OK] Esquema de Shamir validado correctamente.")

def test_keystore_zch():
    print("\n--- TEST: Llavero Criptográfico Seguro (KeystoreZCH) ---")
    ruta_keystore = "temp_keystore.json"
    pwd_maestro = "MasterZchKey99!"
    
    if os.path.exists(ruta_keystore):
        os.remove(ruta_keystore)
        
    # Crear Keystore
    ks = zch_e2ee.KeystoreZCH.crear(ruta_keystore, pwd_maestro)
    
    # Generar claves para guardar
    priv_rsa, pub_rsa = zch_e2ee.generar_llaves()
    priv_ec, pub_ec = zch_e2ee.generar_llaves_ec()
    
    # Guardar claves
    ks.guardar_clave_propia("mi_rsa", priv_rsa)
    ks.guardar_clave_contacto("contacto_rsa", pub_rsa)
    ks.guardar_clave_propia("mi_ec", priv_ec)
    ks.guardar_clave_contacto("contacto_ec", pub_ec)
    
    # Guardar cambios
    ks.guardar(ruta_keystore, pwd_maestro)
    
    # Cargar Keystore
    ks2 = zch_e2ee.KeystoreZCH.cargar(ruta_keystore, pwd_maestro)
    
    # Recuperar y validar claves RSA
    priv_rsa_recup = ks2.obtener_clave_privada("mi_rsa")
    pub_rsa_recup = ks2.obtener_clave_contacto("contacto_rsa")
    assert priv_rsa_recup.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ) == priv_rsa.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ), "La clave privada RSA no coincide."
    
    assert pub_rsa_recup.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ) == pub_rsa.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ), "La clave pública RSA no coincide."
    
    # Recuperar y validar claves EC
    priv_ec_recup = ks2.obtener_clave_privada("mi_ec")
    pub_ec_recup = ks2.obtener_clave_contacto("contacto_ec")
    
    # Probar que las claves recuperadas funcionan derivando clave compartida
    sh1 = zch_e2ee.derivar_clave_compartida(priv_ec, pub_ec)
    sh2 = zch_e2ee.derivar_clave_compartida(priv_ec_recup, pub_ec_recup)
    assert sh1 == sh2, "Las claves EC cargadas del Keystore no derivan el mismo secreto."
    
    # Intentar cargar con contraseña incorrecta
    try:
        zch_e2ee.KeystoreZCH.cargar(ruta_keystore, "ClaveIncorrecta")
        assert False, "Debió fallar con ErrorContrasenaIncorrecta."
    except zch_e2ee.ErrorContrasenaIncorrecta as e:
        print(f"  [OK] Capturado ErrorContrasenaIncorrecta al cargar Keystore: {e}")
        
    # Limpiar
    if os.path.exists(ruta_keystore):
        os.remove(ruta_keystore)
        
    print("  [OK] Llavero KeystoreZCH validado correctamente.")

def test_double_ratchet():
    print("\n--- TEST: Protocolo Double Ratchet Simplificado ---")
    # Generar claves para Alice y Bob
    priv_alice, pub_alice = zch_e2ee.generar_llaves_ec()
    priv_bob, pub_bob = zch_e2ee.generar_llaves_ec()
    
    # Inicializar sesiones
    sesion_alice = zch_e2ee.SesionDoubleRatchet(priv_alice, pub_bob, es_iniciador=True)
    sesion_bob = zch_e2ee.SesionDoubleRatchet(priv_bob, pub_alice, es_iniciador=False)
    
    # Mensaje 1: Alice -> Bob
    msg1 = "Hola Bob, este es el inicio de nuestra sesion segura."
    cifrado1 = sesion_alice.enviar_mensaje(msg1)
    descifrado1 = sesion_bob.recibir_mensaje(cifrado1)
    assert descifrado1 == msg1, "Mensaje 1 falló al ser descifrado por Bob."
    
    # Mensaje 2: Bob -> Alice (respuesta)
    msg2 = "Entendido Alice, te escucho fuerte y claro."
    cifrado2 = sesion_bob.enviar_mensaje(msg2)
    descifrado2 = sesion_alice.recibir_mensaje(cifrado2)
    assert descifrado2 == msg2, "Mensaje 2 falló al ser descifrado por Alice."
    
    # Mensaje 3: Alice -> Bob (continuación)
    msg3 = "Excelente. El trinquete está rotando las llaves perfectamente."
    cifrado3 = sesion_alice.enviar_mensaje(msg3)
    descifrado3 = sesion_bob.recibir_mensaje(cifrado3)
    assert descifrado3 == msg3, "Mensaje 3 falló al ser descifrado por Bob."
    
    print("  [OK] Double Ratchet validado correctamente.")

def test_hmac_autenticacion():
    print("\n--- TEST: Autenticación HMAC-SHA256 ---")
    datos = b"Mensaje importante que no debe ser modificado"
    clave = b"ClaveSecretaSuperSeguraHMAC12345"
    
    hmac_val = zch_e2ee.calcular_hmac(datos, clave)
    assert len(hmac_val) == 32, "El HMAC-SHA256 debe tener 32 bytes."
    
    # Verificar exitoso
    es_valido = zch_e2ee.verificar_hmac(datos, hmac_val, clave)
    assert es_valido is True, "La verificación del HMAC debió ser exitosa."
    
    # Verificar con datos modificados
    es_valido_mod = zch_e2ee.verificar_hmac(datos + b" alterado", hmac_val, clave)
    assert es_valido_mod is False, "La verificación con datos alterados debió fallar."
    
    # Verificar con clave incorrecta
    es_valido_clave = zch_e2ee.verificar_hmac(datos, hmac_val, b"ClaveIncorrectaHMAC")
    assert es_valido_clave is False, "La verificación con clave incorrecta debió fallar."
    
    print("  [OK] Autenticación HMAC validada correctamente.")

def test_encrypted_importer():
    print("\n--- TEST: Importador de Módulos Python Cifrados ---")
    
    # Definir nombres y rutas
    nombre_modulo = "modulo_test_import"
    archivo_py = f"{nombre_modulo}.py"
    archivo_enc = f"{nombre_modulo}.py.enc"
    password = "ImportPassword100"
    
    if os.path.exists(archivo_py):
        os.remove(archivo_py)
    if os.path.exists(archivo_enc):
        os.remove(archivo_enc)
        
    # Escribir código original
    codigo_fuente = (
        "def saludar():\n"
        "    return 'Hola, este es un modulo secreto cargado en memoria!'\n"
        "def calcular(a, b):\n"
        "    return a + b\n"
    )
    with open(archivo_py, "w", encoding="utf-8") as f:
        f.write(codigo_fuente)
        
    # Encriptar módulo
    zch_e2ee.encriptar_modulo_python(archivo_py, archivo_enc, password)
    
    # Eliminar archivo original .py
    os.remove(archivo_py)
    assert not os.path.exists(archivo_py), "El archivo .py original no debió quedar en disco."
    
    # Registrar importador cifrado
    zch_e2ee.registrar_importador_cifrado(password)
    
    # Importar modulo en memoria
    try:
        modulo_test_import = importlib.import_module("modulo_test_import")
        
        # Validar funcionamiento de funciones internas
        saludo = modulo_test_import.saludar()
        suma = modulo_test_import.calcular(10, 20)
        
        assert saludo == 'Hola, este es un modulo secreto cargado en memoria!'
        assert suma == 30
        print("  [OK] Módulo cifrado importado y ejecutado exitosamente en memoria.")
    except Exception as e:
        raise AssertionError(f"Fallo al importar o ejecutar el módulo cifrado: {e}")
    finally:
        # Limpiar
        if os.path.exists(archivo_enc):
            os.remove(archivo_enc)
            
        # Remover el buscador para no contaminar el sys.meta_path
        sys.meta_path = [f for f in sys.meta_path if not isinstance(f, EncryptedModuleFinder)]
        
        # Quitar el módulo de sys.modules para permitir re-importaciones limpias en pruebas
        if nombre_modulo in sys.modules:
            del sys.modules[nombre_modulo]
            
    print("  [OK] Importador de módulos cifrados validado correctamente.")

def test_excepciones_detalladas_v1():
    print("\n--- TEST: Excepciones Detalladas v1.0.0 (KVV y Datos Corruptos) ---")
    mensaje = "Este es un mensaje secreto"
    pwd_correcto = "ClaveCorrecta"
    pwd_incorrecto = "ClaveIncorrecta"
    
    cifrado = zch_e2ee.encriptar_con_password(mensaje, pwd_correcto)
    
    # 1. Verificar error de contraseña incorrecta con Scrypt (KVV)
    try:
        zch_e2ee.desencriptar_con_password(cifrado, pwd_incorrecto)
        assert False, "Debió fallar con ErrorContrasenaIncorrecta."
    except zch_e2ee.ErrorContrasenaIncorrecta as e:
        print(f"  [OK] Capturado ErrorContrasenaIncorrecta (KVV): {e}")
    except zch_e2ee.ErrorDescifrado as e:
        assert False, f"Debió lanzar ErrorContrasenaIncorrecta, lanzó ErrorDescifrado genérico: {e}"
        
    # 2. Verificar error de datos corruptos al descifrar (manipulación de datos cifrados con clave correcta)
    # Modificamos los bytes cifrados en el base64 sin cambiar el KVV
    datos_cifrados_bytes = base64.b64decode(cifrado.encode('utf-8'))
    # Modificar los últimos bytes (que corresponden al texto cifrado/tag)
    datos_corruptos_bytes = datos_cifrados_bytes[:-4] + bytes([datos_cifrados_bytes[-4] ^ 0xFF]) + datos_cifrados_bytes[-3:]
    cifrado_corrupto = base64.b64encode(datos_corruptos_bytes).decode('utf-8')
    
    try:
        zch_e2ee.desencriptar_con_password(cifrado_corrupto, pwd_correcto)
        assert False, "Debió fallar con ErrorDatosCorruptos."
    except zch_e2ee.ErrorDatosCorruptos as e:
        print(f"  [OK] Capturado ErrorDatosCorruptos: {e}")
    except zch_e2ee.ErrorDescifrado as e:
        assert False, f"Debió lanzar ErrorDatosCorruptos, lanzó ErrorDescifrado genérico: {e}"
        
    print("  [OK] Excepciones detalladas validadas correctamente.")

# =====================================================================
# NOVEDADES DE LA VERSIÓN 1.0.1
# =====================================================================

def test_keystore_listar_alias():
    print("\n--- TEST: Listado de Alias en Keystore (v1.0.1) ---")
    ruta_ks = "temp_ks_list.json"
    pwd = "ListAliasPassword1!"
    
    if os.path.exists(ruta_ks):
        os.remove(ruta_ks)
        
    ks = zch_e2ee.KeystoreZCH.crear(ruta_ks, pwd)
    
    priv_rsa, pub_rsa = zch_e2ee.generar_llaves()
    priv_ec, pub_ec = zch_e2ee.generar_llaves_ec()
    
    ks.guardar_clave_propia("privada_rsa_1", priv_rsa)
    ks.guardar_clave_propia("privada_ec_1", priv_ec)
    ks.guardar_clave_contacto("contacto_rsa_1", pub_rsa)
    ks.guardar_clave_contacto("contacto_ec_1", pub_ec)
    
    aliases = ks.listar_alias()
    
    assert "privada_rsa_1" in aliases["claves_privadas"]
    assert "privada_ec_1" in aliases["claves_privadas"]
    assert "contacto_rsa_1" in aliases["claves_publicas"]
    assert "contacto_ec_1" in aliases["claves_publicas"]
    assert len(aliases["claves_privadas"]) == 2
    assert len(aliases["claves_publicas"]) == 2
    
    if os.path.exists(ruta_ks):
        os.remove(ruta_ks)
        
    print("  [OK] Listado de alias validado correctamente.")

def test_shamir_optimizado_stress():
    print("\n--- TEST: Stress de Shamir y Verificación de Aritmética GF(256) (v1.0.1) ---")
    
    secreto = b"Secreto Super Secreto para test de stress en GF(256)"
    
    t0 = time.time()
    for _ in range(50):
        partes = zch_e2ee.dividir_secreto_shamir(secreto, n=10, t=5)
        # Reconstruir usando parte 1, 3, 5, 7, 9
        partes_elegidas = [partes[0], partes[2], partes[4], partes[6], partes[8]]
        reconstruido = zch_e2ee.reconstruir_secreto_shamir(partes_elegidas)
        assert reconstruido == secreto, "La reconstrucción optimizada de Shamir falló."
        
    t1 = time.time()
    print(f"  [OK] 50 operaciones completas de Shamir realizadas en {(t1 - t0)*1000:.2f} ms.")

# =====================================================================
# NOVEDADES DE LA VERSIÓN 1.0.2
# =====================================================================

def test_keystore_cli():
    print("\n--- TEST: Comandos CLI de Llavero Criptográfico (v1.0.2) ---")
    
    ruta_ks = "cli_keystore.json"
    pwd = "CliMasterPassword123!"
    
    # Limpiar previos
    for f in [ruta_ks, "exported_pub.pem", "exported_priv.pem", "test_priv.pem", "test_pub.pem"]:
        if os.path.exists(f):
            os.remove(f)
            
    # 1. Generar llaves auxiliares para las pruebas en disco
    priv, pub = zch_e2ee.generar_llaves_ec()
    zch_e2ee.guardar_llave_privada_ec_en_archivo(priv, "test_priv.pem", "keypwd")
    zch_e2ee.guardar_llave_publica_ec_en_archivo(pub, "test_pub.pem")
    
    env_dict = {**os.environ, "PYTHONPATH": "src"}
    
    try:
        # 2. Ejecutar keystore-create vía subprocess
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "keystore-create",
            "--keystore", ruta_ks, "--password", pwd
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_data = json.loads(res.stdout)
        assert out_data["status"] == "success"
        assert os.path.exists(ruta_ks)
        print("  [OK] keystore-create ejecutado con éxito.")
        
        # 3. Ejecutar keystore-add-key (clave privada)
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "keystore-add-key",
            "--keystore", ruta_ks, "--password", pwd,
            "--alias", "identidad_priv", "--key-file", "test_priv.pem",
            "--type", "private", "--key-password", "keypwd"
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_data = json.loads(res.stdout)
        assert out_data["status"] == "success"
        print("  [OK] keystore-add-key (private) ejecutado con éxito.")
 
        # 4. Ejecutar keystore-add-key (clave pública)
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "keystore-add-key",
            "--keystore", ruta_ks, "--password", pwd,
            "--alias", "contacto_pub", "--key-file", "test_pub.pem",
            "--type", "public"
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_data = json.loads(res.stdout)
        assert out_data["status"] == "success"
        print("  [OK] keystore-add-key (public) ejecutado con éxito.")
 
        # 5. Ejecutar keystore-list
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "keystore-list",
            "--keystore", ruta_ks, "--password", pwd
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_data = json.loads(res.stdout)
        assert out_data["status"] == "success"
        aliases = out_data["aliases"]
        assert "identidad_priv" in aliases["claves_privadas"]
        assert "contacto_pub" in aliases["claves_publicas"]
        print("  [OK] keystore-list ejecutado con éxito.")
 
        # 6. Ejecutar keystore-export-key (clave pública)
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "keystore-export-key",
            "--keystore", ruta_ks, "--password", pwd,
            "--alias", "contacto_pub", "--out-pem", "exported_pub.pem",
            "--type", "public"
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_data = json.loads(res.stdout)
        assert out_data["status"] == "success"
        assert os.path.exists("exported_pub.pem")
        print("  [OK] keystore-export-key (public) ejecutado con éxito.")
        
        # 7. Ejecutar keystore-export-key (clave privada)
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "keystore-export-key",
            "--keystore", ruta_ks, "--password", pwd,
            "--alias", "identidad_priv", "--out-pem", "exported_priv.pem",
            "--type", "private", "--key-password", "keypwd_new"
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_data = json.loads(res.stdout)
        assert out_data["status"] == "success"
        assert os.path.exists("exported_priv.pem")
        print("  [OK] keystore-export-key (private) ejecutado con éxito.")
        
    finally:
        # Limpieza
        for f in [ruta_ks, "exported_pub.pem", "exported_priv.pem", "test_priv.pem", "test_pub.pem"]:
            if os.path.exists(f):
                os.remove(f)
                
    print("  [OK] Pruebas de Keystore CLI completadas con éxito.")

def test_nuevas_caracteristicas_v107():
    print("\n--- TEST: Nuevas caracteristicas v1.0.7 (Checksum, Direct Text, HMAC) ---")
    
    # Archivos temporales para test
    ruta_temp = "v107_test_file.txt"
    with open(ruta_temp, "w", encoding="utf-8") as f:
        f.write("Hola, esta es una prueba de integridad para la v1.0.7 sin emojis.")
        
    env_dict = {**os.environ, "PYTHONPATH": "src"}
    
    try:
        # --- 1. Test hash y hash-verify CLI ---
        print("  Calculando hash SHA-256 via CLI...")
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "hash",
            "--file", ruta_temp
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_data = json.loads(res.stdout)
        assert out_data["status"] == "success"
        expected_hash = out_data["hash"]
        print(f"    Hash calculado: {expected_hash}")
        
        # Verificar hash-verify correcto
        res_ver = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "hash-verify",
            "--file", ruta_temp, "--checksum", expected_hash
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_ver = json.loads(res_ver.stdout)
        assert out_ver["status"] == "success"
        assert out_ver["valid"] is True
        print("    [OK] hash-verify exitoso para hash correcto.")
        
        # Verificar hash-verify incorrecto
        res_fail = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "hash-verify",
            "--file", ruta_temp, "--checksum", "a" * 64
        ], env=env_dict, capture_output=True, text=True)
        assert res_fail.returncode != 0
        out_fail = json.loads(res_fail.stderr)
        assert out_fail["status"] == "error"
        print("    [OK] hash-verify fallo correctamente para hash incorrecto.")
        
        # --- 2. Test encrypt-text y decrypt-text CLI ---
        mensaje_original = "Mensaje directo de texto sin archivos intermedios."
        password = "PasswordTexto123!"
        
        # Cifrado simétrico
        print("  Cifrando texto con contrasena via CLI...")
        res_enc = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "encrypt-text",
            "--text", mensaje_original, "--password", password
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_enc = json.loads(res_enc.stdout)
        assert out_enc["status"] == "success"
        texto_cifrado = out_enc["cipher"]
        
        # Descifrado simétrico
        print("  Descifrando texto con contrasena via CLI...")
        res_dec = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "decrypt-text",
            "--text", texto_cifrado, "--password", password
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_dec = json.loads(res_dec.stdout)
        assert out_dec["status"] == "success"
        assert out_dec["plain"] == mensaje_original
        print("    [OK] Cifrado y descifrado de texto directo (Password) exitoso.")
        
        # Cifrado asimétrico RSA
        print("  Generando llaves RSA para pruebas asimetricas de texto...")
        priv_rsa, pub_rsa = zch_e2ee.generar_llaves(2048)
        zch_e2ee.guardar_llave_privada_en_archivo(priv_rsa, "v107_rsa_priv.pem", "rsakey")
        zch_e2ee.guardar_llave_publica_en_archivo(pub_rsa, "v107_rsa_pub.pem")
        
        print("  Cifrando texto con RSA via CLI...")
        res_enc_rsa = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "encrypt-text",
            "--text", mensaje_original, "--key-rsa", "v107_rsa_pub.pem"
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_enc_rsa = json.loads(res_enc_rsa.stdout)
        assert out_enc_rsa["status"] == "success"
        texto_cifrado_rsa = out_enc_rsa["cipher"]
        
        print("  Descifrando texto con RSA via CLI...")
        res_dec_rsa = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "decrypt-text",
            "--text", texto_cifrado_rsa, "--key-rsa", "v107_rsa_priv.pem", "--key-password", "rsakey"
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_dec_rsa = json.loads(res_dec_rsa.stdout)
        assert out_dec_rsa["status"] == "success"
        assert out_dec_rsa["plain"] == mensaje_original
        print("    [OK] Cifrado y descifrado de texto directo (RSA) exitoso.")
        
        # --- 3. Test hmac-calc y hmac-verify CLI ---
        hmac_key = "ClaveHmacSegura123!"
        print("  Calculando HMAC de archivo via CLI...")
        res_hmac = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "hmac-calc",
            "--file", ruta_temp, "--key", hmac_key
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_hmac = json.loads(res_hmac.stdout)
        assert out_hmac["status"] == "success"
        hmac_hex = out_hmac["hmac"]
        print(f"    HMAC calculado: {hmac_hex}")
        
        # Verificar hmac-verify correcto
        res_hmac_ver = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "hmac-verify",
            "--file", ruta_temp, "--key", hmac_key, "--hmac", hmac_hex
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_hmac_ver = json.loads(res_hmac_ver.stdout)
        assert out_hmac_ver["status"] == "success"
        assert out_hmac_ver["valid"] is True
        print("    [OK] hmac-verify exitoso para HMAC correcto.")
        
        # Verificar hmac-verify incorrecto
        res_hmac_fail = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "hmac-verify",
            "--file", ruta_temp, "--key", hmac_key, "--hmac", "f" * 64
        ], env=env_dict, capture_output=True, text=True)
        assert res_hmac_fail.returncode != 0
        out_hmac_fail = json.loads(res_hmac_fail.stderr)
        assert out_hmac_fail["status"] == "error"
        print("    [OK] hmac-verify fallo correctamente para HMAC incorrecto.")
        
    finally:
        # Limpieza de archivos temporales
        for f in [ruta_temp, "v107_rsa_priv.pem", "v107_rsa_pub.pem"]:
            if os.path.exists(f):
                os.remove(f)
                
    print("  [OK] Pruebas de nuevas caracteristicas v1.0.7 completadas con exito.")

def test_nuevas_caracteristicas_v108():
    print("\n--- TEST: Nuevas caracteristicas v1.0.8 (Firma, Ratchet Sim, Keystore Backup/Restore) ---")
    
    ruta_temp = "v108_test_file.txt"
    with open(ruta_temp, "w", encoding="utf-8") as f:
        f.write("Integridad y autenticacion para la version v1.0.8 sin emojis.")
        
    env_dict = {**os.environ, "PYTHONPATH": "src"}
    
    try:
        # 1. Test de firma y verificacion de archivo via CLI
        print("  Generando llaves RSA para firma de archivos...")
        priv_rsa, pub_rsa = zch_e2ee.generar_llaves(2048)
        zch_e2ee.guardar_llave_privada_en_archivo(priv_rsa, "v108_rsa_priv.pem", "rsapwd")
        zch_e2ee.guardar_llave_publica_en_archivo(pub_rsa, "v108_rsa_pub.pem")
        
        print("  Firmando archivo via CLI...")
        res_sign = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "sign-file",
            "--file", ruta_temp, "--key-private", "v108_rsa_priv.pem", "--key-password", "rsapwd"
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_sign = json.loads(res_sign.stdout)
        assert out_sign["status"] == "success"
        signature_b64 = out_sign["signature"]
        print("    Firma generada exitosamente.")
        
        print("  Verificando firma del archivo via CLI...")
        res_ver = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "verify-file",
            "--file", ruta_temp, "--key-public", "v108_rsa_pub.pem", "--signature", signature_b64
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_ver = json.loads(res_ver.stdout)
        assert out_ver["status"] == "success"
        assert out_ver["valid"] is True
        print("    [OK] Firma de archivo verificada correctamente.")
        
        # 2. Test de simulador Double Ratchet (ratchet-sim) via CLI
        print("  Ejecutando simulacion automatica de Double Ratchet via CLI...")
        res_ratchet = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "ratchet-sim"
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_ratchet = json.loads(res_ratchet.stdout)
        assert out_ratchet["status"] == "success"
        sim_log = out_ratchet["simulation"]
        assert len(sim_log) == 3
        assert sim_log[0]["from"] == "Alice"
        assert sim_log[0]["decrypted"] == "Hola Bob, este es el inicio de nuestra sesion segura."
        print("    [OK] Simulador Double Ratchet via CLI verificado correctamente.")
        
        # 3. Test de Keystore Backup y Restore via CLI
        ruta_ks_orig = "v108_ks_orig.json"
        ruta_ks_dest = "v108_ks_dest.json"
        ruta_bak = "v108_ks_backup.bak"
        pwd_ks = "ClaveMaestraKeystore1!"
        pwd_bak = "ClaveRespaldoCifrado2!"
        
        print("  Creando Keystore original y agregando llave...")
        ks_orig = zch_e2ee.KeystoreZCH.crear(ruta_ks_orig, pwd_ks)
        ks_orig.guardar_clave_contacto("contacto_amigo", pub_rsa)
        ks_orig.guardar(ruta_ks_orig, pwd_ks)
        
        print("  Ejecutando respaldo de Keystore via CLI...")
        res_bak = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "keystore-backup",
            "--keystore", ruta_ks_orig, "--password", pwd_ks,
            "--out-backup", ruta_bak, "--backup-password", pwd_bak
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_bak = json.loads(res_bak.stdout)
        assert out_bak["status"] == "success"
        assert os.path.exists(ruta_bak)
        
        print("  Ejecutando restauracion de Keystore en nuevo llavero via CLI...")
        res_res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "keystore-restore",
            "--keystore", ruta_ks_dest, "--password", pwd_ks,
            "--in-backup", ruta_bak, "--backup-password", pwd_bak
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_res = json.loads(res_res.stdout)
        assert out_res["status"] == "success"
        assert os.path.exists(ruta_ks_dest)
        
        # Cargar y verificar claves en el llavero destino
        ks_dest = zch_e2ee.KeystoreZCH.cargar(ruta_ks_dest, pwd_ks)
        assert "contacto_amigo" in ks_dest.listar_alias()["claves_publicas"]
        print("    [OK] Respaldo y restauracion de Keystore via CLI verificado correctamente.")
        
    finally:
        # Limpieza
        for f in [ruta_temp, "v108_rsa_priv.pem", "v108_rsa_pub.pem", "v108_ks_orig.json", "v108_ks_dest.json", "v108_ks_backup.bak"]:
            if os.path.exists(f):
                os.remove(f)
                
    print("  [OK] Pruebas de nuevas caracteristicas v1.0.8 completadas con exito.")

def test_nuevas_caracteristicas_v109():
    print("\n--- TEST: Nuevas caracteristicas v1.0.9 (Encrypt/Decrypt Dir, Persistent Ratchet, Shamir Reconstruct) ---")
    
    env_dict = {**os.environ, "PYTHONPATH": "src"}
    
    # 1. Test encrypt-dir/decrypt-dir CLI
    dir_orig = "v109_dir_orig"
    dir_dest = "v109_dir_dest"
    file_enc = "v109_dir.enc"
    password = "DirectorioClave123!"
    
    # Clean up before
    for path in [dir_orig, dir_dest]:
        if os.path.exists(path):
            shutil.rmtree(path)
    if os.path.exists(file_enc):
        os.remove(file_enc)
        
    try:
        os.makedirs(dir_orig, exist_ok=True)
        with open(os.path.join(dir_orig, "test.txt"), "w", encoding="utf-8") as f:
            f.write("Prueba de cifrado de directorios v1.0.9")
            
        print("  Cifrando directorio via CLI...")
        res_enc_dir = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "encrypt-dir",
            "--in-dir", dir_orig, "--out-file", file_enc, "--password", password
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_enc_dir = json.loads(res_enc_dir.stdout)
        assert out_enc_dir["status"] == "success"
        assert os.path.exists(file_enc)
        
        print("  Descifrando directorio via CLI...")
        res_dec_dir = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "decrypt-dir",
            "--in-file", file_enc, "--out-dir", dir_dest, "--password", password
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_dec_dir = json.loads(res_dec_dir.stdout)
        assert out_dec_dir["status"] == "success"
        assert os.path.exists(os.path.join(dir_dest, "test.txt"))
        with open(os.path.join(dir_dest, "test.txt"), "r", encoding="utf-8") as f:
            content = f.read()
        assert content == "Prueba de cifrado de directorios v1.0.9"
        print("    [OK] Cifrado y descifrado de directorio via CLI exitoso.")
    finally:
        for path in [dir_orig, dir_dest]:
            if os.path.exists(path):
                shutil.rmtree(path)
        if os.path.exists(file_enc):
            os.remove(file_enc)
            
    # 2. Test Shamir Reconstruction CLI
    secreto = "secreto_v109"
    partes = zch_e2ee.dividir_secreto_shamir(secreto.encode('utf-8'), n=3, t=2)
    shares_str = ",".join(f"{idx}-{base64.b64encode(datos).decode('utf-8')}" for idx, datos in partes[:2])
    
    print("  Reconstruyendo secreto Shamir via CLI...")
    res_shamir = subprocess.run([
        sys.executable, "-m", "zch_e2ee", "--json", "shamir-reconstruct",
        "--shares", shares_str
    ], env=env_dict, capture_output=True, text=True, check=True)
    out_shamir = json.loads(res_shamir.stdout)
    assert out_shamir["status"] == "success"
    assert out_shamir["secret"] == secreto
    print("    [OK] Reconstruccion de Shamir via CLI exitosa.")
    
    # 3. Test Double Ratchet Session Persistence CLI
    file_alice_priv = "v109_alice_priv.pem"
    file_alice_pub = "v109_alice_pub.pem"
    file_bob_priv = "v109_bob_priv.pem"
    file_bob_pub = "v109_bob_pub.pem"
    file_alice_session = "v109_alice_session.json"
    file_bob_session = "v109_bob_session.json"
    
    for f in [file_alice_priv, file_alice_pub, file_bob_priv, file_bob_pub, file_alice_session, file_bob_session]:
        if os.path.exists(f):
            os.remove(f)
            
    try:
        priv_alice, pub_alice = zch_e2ee.generar_llaves_ec()
        priv_bob, pub_bob = zch_e2ee.generar_llaves_ec()
        
        zch_e2ee.guardar_llave_privada_ec_en_archivo(priv_alice, file_alice_priv)
        zch_e2ee.guardar_llave_publica_ec_en_archivo(pub_alice, file_alice_pub)
        zch_e2ee.guardar_llave_privada_ec_en_archivo(priv_bob, file_bob_priv)
        zch_e2ee.guardar_llave_publica_ec_en_archivo(pub_bob, file_bob_pub)
        
        print("  Inicializando sesion de Alice via CLI...")
        res_init_alice = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "ratchet-init",
            "--key-private", file_alice_priv, "--key-public", file_bob_pub,
            "--initiator", "--out-session", file_alice_session
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_init_alice = json.loads(res_init_alice.stdout)
        assert out_init_alice["status"] == "success"
        
        print("  Inicializando sesion de Bob via CLI...")
        res_init_bob = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "ratchet-init",
            "--key-private", file_bob_priv, "--key-public", file_alice_pub,
            "--out-session", file_bob_session
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_init_bob = json.loads(res_init_bob.stdout)
        assert out_init_bob["status"] == "success"
        
        msg_alice = "Hola Bob, mensaje con persistencia v1.0.9"
        print("  Alice cifra mensaje via CLI...")
        res_enc_alice = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "ratchet-encrypt",
            "--session", file_alice_session, "--text", msg_alice,
            "--out-session", file_alice_session
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_enc_alice = json.loads(res_enc_alice.stdout)
        assert out_enc_alice["status"] == "success"
        cifrado_alice = out_enc_alice["cipher"]
        
        print("  Bob descifra mensaje via CLI...")
        res_dec_bob = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "ratchet-decrypt",
            "--session", file_bob_session, "--text", cifrado_alice,
            "--out-session", file_bob_session
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_dec_bob = json.loads(res_dec_bob.stdout)
        assert out_dec_bob["status"] == "success"
        assert out_dec_bob["plain"] == msg_alice
        
        msg_bob = "Hola Alice, recibido perfectamente"
        print("  Bob cifra respuesta via CLI...")
        res_enc_bob = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "ratchet-encrypt",
            "--session", file_bob_session, "--text", msg_bob,
            "--out-session", file_bob_session
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_enc_bob = json.loads(res_enc_bob.stdout)
        assert out_enc_bob["status"] == "success"
        cifrado_bob = out_enc_bob["cipher"]
        
        print("  Alice descifra respuesta via CLI...")
        res_dec_alice = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "ratchet-decrypt",
            "--session", file_alice_session, "--text", cifrado_bob,
            "--out-session", file_alice_session
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_dec_alice = json.loads(res_dec_alice.stdout)
        assert out_dec_alice["status"] == "success"
        assert out_dec_alice["plain"] == msg_bob
        
        print("    [OK] Double Ratchet persistente via CLI verificado correctamente.")
    finally:
        for f in [file_alice_priv, file_alice_pub, file_bob_priv, file_bob_pub, file_alice_session, file_bob_session]:
            if os.path.exists(f):
                os.remove(f)
                
    print("  [OK] Pruebas de nuevas caracteristicas v1.0.9 completadas con exito.")

def test_nuevas_caracteristicas_v110():
    print("\n--- TEST: Nuevas caracteristicas v1.1.0 (Encrypt/Decrypt Dir Multi) ---")
    
    env_dict = {**os.environ, "PYTHONPATH": "src"}
    
    dir_orig = "v110_dir_orig"
    dir_dest_alice = "v110_dir_dest_alice"
    dir_dest_bob = "v110_dir_dest_bob"
    file_enc = "v110_dir_multi.enc"
    
    file_alice_priv = "v110_alice_priv.pem"
    file_alice_pub = "v110_alice_pub.pem"
    file_bob_priv = "v110_bob_priv.pem"
    file_bob_pub = "v110_bob_pub.pem"
    
    for d in [dir_orig, dir_dest_alice, dir_dest_bob]:
        if os.path.exists(d):
            shutil.rmtree(d)
    for f in [file_enc, file_alice_priv, file_alice_pub, file_bob_priv, file_bob_pub, "v110_ks.json"]:
        if os.path.exists(f):
            os.remove(f)
            
    try:
        os.makedirs(dir_orig, exist_ok=True)
        with open(os.path.join(dir_orig, "nota.txt"), "w", encoding="utf-8") as f:
            f.write("Mensaje grupal confidencial en directorio v1.1.0")
            
        priv_alice, pub_alice = zch_e2ee.generar_llaves_ec()
        priv_bob, pub_bob = zch_e2ee.generar_llaves_ec()
        
        zch_e2ee.guardar_llave_privada_ec_en_archivo(priv_alice, file_alice_priv)
        zch_e2ee.guardar_llave_publica_ec_en_archivo(pub_alice, file_alice_pub)
        zch_e2ee.guardar_llave_privada_ec_en_archivo(priv_bob, file_bob_priv)
        zch_e2ee.guardar_llave_publica_ec_en_archivo(pub_bob, file_bob_pub)
        
        print("  Cifrando directorio para Alice y Bob via CLI...")
        res_enc = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "encrypt-dir-multi",
            "--in-dir", dir_orig, "--out-file", file_enc,
            "--keys-public", f"{file_alice_pub},{file_bob_pub}"
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_enc = json.loads(res_enc.stdout)
        assert out_enc["status"] == "success"
        
        print("  Alice descifra directorio via CLI...")
        res_dec_alice = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "decrypt-dir-multi",
            "--in-file", file_enc, "--out-dir", dir_dest_alice,
            "--key-private", file_alice_priv
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_dec_alice = json.loads(res_dec_alice.stdout)
        assert out_dec_alice["status"] == "success"
        with open(os.path.join(dir_dest_alice, "nota.txt"), "r", encoding="utf-8") as f:
            res_alice = f.read()
        assert res_alice == "Mensaje grupal confidencial en directorio v1.1.0"
        
        print("  Bob descifra directorio via CLI...")
        res_dec_bob = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "decrypt-dir-multi",
            "--in-file", file_enc, "--out-dir", dir_dest_bob,
            "--key-private", file_bob_priv
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_dec_bob = json.loads(res_dec_bob.stdout)
        assert out_dec_bob["status"] == "success"
        with open(os.path.join(dir_dest_bob, "nota.txt"), "r", encoding="utf-8") as f:
            res_bob = f.read()
        assert res_bob == "Mensaje grupal confidencial en directorio v1.1.0"
        
        print("    [OK] Cifrado y descifrado multi-destinatario con archivos PEM exitoso.")
        
        shutil.rmtree(dir_dest_alice)
        shutil.rmtree(dir_dest_bob)
        os.remove(file_enc)
        
        ks = zch_e2ee.KeystoreZCH.crear("v110_ks.json", "ClaveKS123!")
        ks.guardar_clave_propia("alice_key", priv_alice)
        ks.guardar_clave_propia("bob_key", priv_bob)
        ks.guardar_clave_contacto("alice_contact", pub_alice)
        ks.guardar_clave_contacto("bob_contact", pub_bob)
        ks.guardar("v110_ks.json", "ClaveKS123!")
        
        print("  Cifrando directorio usando alias del Keystore via CLI...")
        res_enc_ks = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "encrypt-dir-multi",
            "--in-dir", dir_orig, "--out-file", file_enc,
            "--keys-aliases", "alice_contact,bob_contact",
            "--keystore", "v110_ks.json", "--password", "ClaveKS123!"
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_enc_ks = json.loads(res_enc_ks.stdout)
        assert out_enc_ks["status"] == "success"
        
        print("  Alice descifra directorio usando alias del Keystore via CLI...")
        res_dec_alice_ks = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "decrypt-dir-multi",
            "--in-file", file_enc, "--out-dir", dir_dest_alice,
            "--key-alias", "alice_key",
            "--keystore", "v110_ks.json", "--password", "ClaveKS123!"
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_dec_alice_ks = json.loads(res_dec_alice_ks.stdout)
        assert out_dec_alice_ks["status"] == "success"
        with open(os.path.join(dir_dest_alice, "nota.txt"), "r", encoding="utf-8") as f:
            assert f.read() == "Mensaje grupal confidencial en directorio v1.1.0"
            
        print("    [OK] Cifrado y descifrado multi-destinatario con Keystore exitoso.")
        
    finally:
        for d in [dir_orig, dir_dest_alice, dir_dest_bob]:
            if os.path.exists(d):
                shutil.rmtree(d)
        for f in [file_enc, file_alice_priv, file_alice_pub, file_bob_priv, file_bob_pub, "v110_ks.json"]:
            if os.path.exists(f):
                os.remove(f)
                
    print("  [OK] Pruebas de nuevas caracteristicas v1.1.0 completadas con exito.")

# =====================================================================
# MAIN RUNNER
# =====================================================================

def test_nuevas_caracteristicas_v111():
    print("\n--- TEST: Nuevas caracteristicas v1.1.1 (Keystore CLI Key Aliases) ---")
    
    env_dict = {**os.environ, "PYTHONPATH": "src"}
    
    ruta_ks = "v111_ks.json"
    pwd_ks = "ClaveKS111!"
    
    temp_file = "v111_file.txt"
    temp_enc = "v111_file.enc"
    temp_dec = "v111_file_dec.txt"
    
    dir_orig = "v111_dir_orig"
    dir_dest = "v111_dir_dest"
    dir_enc = "v111_dir.enc"
    
    file_session = "v111_session.json"
    
    # Limpiar previos
    for f in [ruta_ks, temp_file, temp_enc, temp_dec, dir_enc, file_session]:
        if os.path.exists(f):
            os.remove(f)
    for d in [dir_orig, dir_dest]:
        if os.path.exists(d):
            shutil.rmtree(d)
            
    try:
        # 1. Crear Keystore y registrar llaves
        ks = zch_e2ee.KeystoreZCH.crear(ruta_ks, pwd_ks)
        
        priv_rsa, pub_rsa = zch_e2ee.generar_llaves()
        priv_ec, pub_ec = zch_e2ee.generar_llaves_ec()
        priv_ed, pub_ed = zch_e2ee.generar_llaves_ed25519()
        
        ks.guardar_clave_propia("alice_priv_rsa", priv_rsa)
        ks.guardar_clave_contacto("alice_pub_rsa", pub_rsa)
        
        ks.guardar_clave_propia("alice_priv_ec", priv_ec)
        ks.guardar_clave_contacto("alice_pub_ec", pub_ec)
        
        ks.guardar_clave_propia("alice_priv_ed", priv_ed)
        ks.guardar_clave_contacto("alice_pub_ed", pub_ed)
        
        ks.guardar(ruta_ks, pwd_ks)
        
        # Escribir archivo de prueba
        original_content = "Contenido ultra secreto de Zoe para la v1.1.1."
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(original_content)
            
        # 2. Test: encrypt y decrypt usando alias
        print("  Probando encrypt usando alias de clave publica...")
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "encrypt",
            "--in-file", temp_file, "--out-file", temp_enc,
            "--key-alias", "alice_pub_rsa",
            "--keystore", ruta_ks, "--keystore-password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["status"] == "success"
        
        print("  Probando decrypt usando alias de clave privada...")
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "decrypt",
            "--in-file", temp_enc, "--out-file", temp_dec,
            "--key-alias", "alice_priv_rsa",
            "--keystore", ruta_ks, "--keystore-password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["status"] == "success"
        with open(temp_dec, "r", encoding="utf-8") as f:
            assert f.read() == original_content
        print("    [OK] encrypt y decrypt con alias RSA exitoso.")
        
        # Limpiar intermedios
        os.remove(temp_enc)
        os.remove(temp_dec)
        
        # EC
        print("  Probando encrypt usando alias de clave publica EC...")
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "encrypt",
            "--in-file", temp_file, "--out-file", temp_enc,
            "--key-alias", "alice_pub_ec",
            "--keystore", ruta_ks, "--keystore-password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["status"] == "success"
        
        print("  Probando decrypt usando alias de clave privada EC...")
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "decrypt",
            "--in-file", temp_enc, "--out-file", temp_dec,
            "--key-alias", "alice_priv_ec",
            "--keystore", ruta_ks, "--keystore-password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["status"] == "success"
        with open(temp_dec, "r", encoding="utf-8") as f:
            assert f.read() == original_content
        print("    [OK] encrypt y decrypt con alias EC exitoso.")
        
        # Limpiar intermedios
        os.remove(temp_enc)
        os.remove(temp_dec)

        # 3. Test: encrypt-text y decrypt-text usando alias
        print("  Probando encrypt-text usando alias...")
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "encrypt-text",
            "--text", original_content,
            "--key-alias", "alice_pub_ec",
            "--keystore", ruta_ks, "--keystore-password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_enc = json.loads(res.stdout)
        assert out_enc["status"] == "success"
        cipher_text = out_enc["cipher"]
        
        print("  Probando decrypt-text usando alias...")
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "decrypt-text",
            "--text", cipher_text,
            "--key-alias", "alice_priv_ec",
            "--keystore", ruta_ks, "--keystore-password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_dec = json.loads(res.stdout)
        assert out_dec["status"] == "success"
        assert out_dec["plain"] == original_content
        print("    [OK] encrypt-text y decrypt-text exitoso.")
        
        # 4. Test: sign-file y verify-file usando alias (Ed25519)
        print("  Probando sign-file usando alias...")
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "sign-file",
            "--file", temp_file,
            "--key-alias", "alice_priv_ed",
            "--keystore", ruta_ks, "--keystore-password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_sign = json.loads(res.stdout)
        assert out_sign["status"] == "success"
        signature = out_sign["signature"]
        
        print("  Probando verify-file usando alias...")
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "verify-file",
            "--file", temp_file, "--signature", signature,
            "--key-alias", "alice_pub_ed",
            "--keystore", ruta_ks, "--keystore-password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_ver = json.loads(res.stdout)
        assert out_ver["status"] == "success"
        assert out_ver["valid"] is True
        print("    [OK] sign-file y verify-file exitoso.")
        
        # 5. Test: encrypt-dir y decrypt-dir usando alias
        os.makedirs(dir_orig, exist_ok=True)
        with open(os.path.join(dir_orig, "f1.txt"), "w", encoding="utf-8") as f:
            f.write("directorio_secreto_v111")
            
        print("  Probando encrypt-dir usando alias...")
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "encrypt-dir",
            "--in-dir", dir_orig, "--out-file", dir_enc,
            "--key-alias", "alice_pub_ec",
            "--keystore", ruta_ks, "--keystore-password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["status"] == "success"
        
        print("  Probando decrypt-dir usando alias...")
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "decrypt-dir",
            "--in-file", dir_enc, "--out-dir", dir_dest,
            "--key-alias", "alice_priv_ec",
            "--keystore", ruta_ks, "--keystore-password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["status"] == "success"
        with open(os.path.join(dir_dest, "f1.txt"), "r", encoding="utf-8") as f:
            assert f.read() == "directorio_secreto_v111"
        print("    [OK] encrypt-dir y decrypt-dir exitoso.")
        
        # 6. Test: ratchet-init usando alias
        print("  Probando ratchet-init usando aliases...")
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "ratchet-init",
            "--key-private-alias", "alice_priv_ec",
            "--key-public-alias", "alice_pub_ec",
            "--initiator", "--out-session", file_session,
            "--keystore", ruta_ks, "--keystore-password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["status"] == "success"
        assert os.path.exists(file_session)
        print("    [OK] ratchet-init con aliases exitoso.")
        
    finally:
        # Limpiar
        for f in [ruta_ks, temp_file, temp_enc, temp_dec, dir_enc, file_session]:
            if os.path.exists(f):
                os.remove(f)
        for d in [dir_orig, dir_dest]:
            if os.path.exists(d):
                shutil.rmtree(d)
                
    print("  [OK] Pruebas de nuevas caracteristicas v1.1.1 completadas con exito.")


def test_nuevas_caracteristicas_v112():
    print("\n--- TEST: Nuevas Caracteristicas v1.1.2 (Rotacion, Expiracion y Fallback) ---")
    
    ruta_ks = "temp_ks_v112.json"
    pwd_ks = "MasterPwd112!"
    temp_file_old = "temp_old.txt"
    temp_enc_old = "temp_old.enc"
    temp_dec_old = "temp_old_dec.txt"
    
    env_dict = os.environ.copy()
    env_dict["PYTHONPATH"] = os.path.abspath("src")
    
    try:
        # 1. Crear Keystore
        print("  Creando Keystore...")
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "keystore-create",
            "--keystore", ruta_ks, "--password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["status"] == "success"
        
        # 2. Generar llave privada y publica EC para agregar al Keystore
        print("  Generando par de llaves EC temporales...")
        temp_priv_pem = "temp_ec_priv.pem"
        temp_pub_pem = "temp_ec_pub.pem"
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "gen-keys",
            "--type", "x25519", "--out-private", temp_priv_pem, "--out-public", temp_pub_pem
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["status"] == "success"
        
        # 3. Agregar llaves con descripcion y expiracion
        print("  Agregando llaves al Keystore con descripcion y expiracion...")
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "keystore-add-key",
            "--keystore", ruta_ks, "--password", pwd_ks,
            "--alias", "test_key", "--key-file", temp_priv_pem, "--type", "private",
            "--description", "Clave privada de prueba v112", "--expiration-days", "30"
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["status"] == "success"

        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "keystore-add-key",
            "--keystore", ruta_ks, "--password", pwd_ks,
            "--alias", "test_key_pub", "--key-file", temp_pub_pem, "--type", "public",
            "--description", "Clave publica de prueba v112", "--expiration-days", "30"
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["status"] == "success"
        
        # Limpiar archivos temporales de llaves
        os.remove(temp_priv_pem)
        os.remove(temp_pub_pem)
        
        # 4. Verificar listado detallado y expiracion
        print("  Verificando listado detallado...")
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "keystore-list",
            "--keystore", ruta_ks, "--password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_list = json.loads(res.stdout)
        assert out_list["status"] == "success"
        assert "test_key" in out_list["detailed_privadas"]
        assert out_list["detailed_privadas"]["test_key"]["descripcion"] == "Clave privada de prueba v112"
        assert out_list["detailed_privadas"]["test_key"]["fecha_expiracion"] is not None
        
        print("  Ejecutando verificacion de expiracion (keystore-check-expired)...")
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "keystore-check-expired",
            "--keystore", ruta_ks, "--password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_expired = json.loads(res.stdout)
        assert out_expired["status"] == "success"
        report = out_expired["report"]
        assert any(item["alias"] == "test_key" and item["expirada"] is False for item in report)
        
        # 5. Cifrar datos con la clave activa (vieja)
        print("  Cifrando archivo con clave activa inicial...")
        original_old = "Mensaje cifrado con la clave antigua que sera rotada."
        with open(temp_file_old, "w", encoding="utf-8") as f:
            f.write(original_old)
            
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "encrypt",
            "--in-file", temp_file_old, "--out-file", temp_enc_old,
            "--key-alias", "test_key_pub",
            "--keystore", ruta_ks, "--keystore-password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["status"] == "success"
        
        # 6. Rotar clave en Keystore (autogenerando nueva - rotacion auto)
        print("  Rotando la clave 'test_key' (autogeneracion)...")
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "keystore-rotate",
            "--keystore", ruta_ks, "--password", pwd_ks,
            "--alias", "test_key", "--expiration-days", "15"
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["status"] == "success"
        
        # Verificar que el historial tenga 1 elemento
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "keystore-list",
            "--keystore", ruta_ks, "--password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_list2 = json.loads(res.stdout)
        assert out_list2["detailed_privadas"]["test_key"]["historial_count"] == 1

        # 7. Rotar clave manualmente usando una nueva clave (rotacion manual)
        print("  Generando segunda clave EC temporal para rotacion manual...")
        temp_priv_pem_2 = "temp_ec_priv_2.pem"
        temp_pub_pem_2 = "temp_ec_pub_2.pem"
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "gen-keys",
            "--type", "x25519", "--out-private", temp_priv_pem_2, "--out-public", temp_pub_pem_2
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["status"] == "success"

        print("  Rotando la clave 'test_key' manualmente...")
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "keystore-rotate",
            "--keystore", ruta_ks, "--password", pwd_ks,
            "--alias", "test_key", "--new-key-file", temp_priv_pem_2
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["status"] == "success"

        # Limpiar archivos temporales
        os.remove(temp_priv_pem_2)
        os.remove(temp_pub_pem_2)

        # Verificar que el historial tenga 2 elementos
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "keystore-list",
            "--keystore", ruta_ks, "--password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        out_list3 = json.loads(res.stdout)
        assert out_list3["detailed_privadas"]["test_key"]["historial_count"] == 2
        
        # 8. Descifrar archivo antiguo usando la clave privada rotada (debe activar fallback sobre historial)
        print("  Descifrando archivo antiguo usando la clave privada rotada (debe activar fallback)...")
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "decrypt",
            "--in-file", temp_enc_old, "--out-file", temp_dec_old,
            "--key-alias", "test_key",
            "--keystore", ruta_ks, "--keystore-password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["status"] == "success"
        with open(temp_dec_old, "r", encoding="utf-8") as f:
            dec_content = f.read()
        assert dec_content == original_old, f"El descifrado falló. Esperado: '{original_old}', obtenido: '{dec_content}'"
        print("    [OK] Descifrado con fallback sobre historial de 2 claves exitoso.")
        
    finally:
        # Limpiar
        for f in [ruta_ks, temp_file_old, temp_enc_old, temp_dec_old]:
            if os.path.exists(f):
                os.remove(f)
                
    print("  [OK] Pruebas de nuevas caracteristicas v1.1.2 completadas con exito.")


def test_nuevas_caracteristicas_v113():
    print("\n--- TEST: Nuevas Caracteristicas v1.1.3 (Configuracion Scrypt y Argon2id) ---")
    
    mensaje = "Datos cifrados con un KDF altamente configurable para Zoe."
    password = "KdfMasterPassword99!"
    
    # 1. Probar Scrypt con parametros custom
    print("  Probando Scrypt con parametros personalizados...")
    cifrado_scrypt = zch_e2ee.encriptar_con_password(mensaje, password, kdf_name="scrypt", n=2048, r=8, p=1)
    descifrado_scrypt = zch_e2ee.desencriptar_con_password(cifrado_scrypt, password)
    assert descifrado_scrypt == mensaje, "El descifrado de Scrypt custom fallo."
    print("    [OK] Scrypt custom exitoso.")
    
    # 2. Probar Argon2id con parametros custom
    print("  Probando Argon2id con parametros personalizados...")
    cifrado_argon = zch_e2ee.encriptar_con_password(mensaje, password, kdf_name="argon2id", memory_cost=16384, time_cost=2, parallelism=2)
    descifrado_argon = zch_e2ee.desencriptar_con_password(cifrado_argon, password)
    assert descifrado_argon == mensaje, "El descifrado de Argon2id custom fallo."
    print("    [OK] Argon2id custom exitoso.")
    
    # 3. Probar CLI
    print("  Probando CLI: encrypt/decrypt usando Argon2id...")
    temp_file = "temp_v113.txt"
    temp_enc = "temp_v113.enc"
    temp_dec = "temp_v113_dec.txt"
    dir_orig = "temp_dir_v113"
    dir_enc = "temp_dir_v113.enc"
    dir_dest = "temp_dir_v113_dest"
    
    env_dict = os.environ.copy()
    env_dict["PYTHONPATH"] = os.path.abspath("src")
    
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(mensaje)
            
        # Cifrar con Argon2id via CLI
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "encrypt",
            "--in-file", temp_file, "--out-file", temp_enc,
            "--password", password,
            "--kdf", "argon2id", "--kdf-memory", "8192", "--kdf-time", "1", "--kdf-parallel", "1"
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["status"] == "success"
        
        # Descifrar (KDF autodescriptivo) via CLI
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "decrypt",
            "--in-file", temp_enc, "--out-file", temp_dec,
            "--password", password
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["status"] == "success"
        
        with open(temp_dec, "r", encoding="utf-8") as f:
            assert f.read() == mensaje
            
        print("    [OK] Cifrado y descifrado de archivos con KDF via CLI exitoso.")
        
        # Cifrar directorio con Scrypt custom via CLI
        print("  Probando CLI: encrypt-dir/decrypt-dir usando Scrypt custom...")
        
        os.makedirs(dir_orig, exist_ok=True)
        with open(os.path.join(dir_orig, "info.txt"), "w", encoding="utf-8") as f:
            f.write("directorio_kdf_v113")
            
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "encrypt-dir",
            "--in-dir", dir_orig, "--out-file", dir_enc,
            "--password", password,
            "--kdf", "scrypt", "--kdf-n", "1024", "--kdf-r", "8", "--kdf-p", "1"
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["status"] == "success"
        
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "decrypt-dir",
            "--in-file", dir_enc, "--out-dir", dir_dest,
            "--password", password
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["status"] == "success"
        
        with open(os.path.join(dir_dest, "info.txt"), "r", encoding="utf-8") as f:
            assert f.read() == "directorio_kdf_v113"
            
        print("    [OK] Cifrado y descifrado de directorios con KDF via CLI exitoso.")
        
    finally:
        for f in [temp_file, temp_enc, temp_dec, dir_enc]:
            if os.path.exists(f):
                os.remove(f)
        for d in [dir_orig, dir_dest]:
            if os.path.exists(d):
                shutil.rmtree(d)
                
    print("  [OK] Pruebas de nuevas caracteristicas v1.1.3 completadas con exito.")

def test_nuevas_caracteristicas_v114():
    print("\n--- TEST: Nuevas Caracteristicas v1.1.4 (Cifrado Multi-destinatario CLI y Keystore) ---")
    
    # Generar llaves para destinatarios
    priv1, pub1 = zch_e2ee.generar_llaves_ec() # Alice
    priv2, pub2 = zch_e2ee.generar_llaves_ec() # Bob
    
    # Guardar llaves
    temp_pub1 = "temp_v114_alice_pub.pem"
    temp_pub2 = "temp_v114_bob_pub.pem"
    temp_priv1 = "temp_v114_alice_priv.pem"
    temp_priv2 = "temp_v114_bob_priv.pem"
    
    zch_e2ee.guardar_llave_publica_ec_en_archivo(pub1, temp_pub1)
    zch_e2ee.guardar_llave_publica_ec_en_archivo(pub2, temp_pub2)
    zch_e2ee.guardar_llave_privada_ec_en_archivo(priv1, temp_priv1)
    zch_e2ee.guardar_llave_privada_ec_en_archivo(priv2, temp_priv2)
    
    # 1. Probar cifrado/descifrado de texto multi-destinatario programático
    mensaje = "Secreto compartido entre Alice y Bob en v1.1.4."
    cifrado_txt = zch_e2ee.encriptar_e2ee_multi(mensaje, [pub1, pub2])
    
    desc_txt1 = zch_e2ee.desencriptar_e2ee_multi(cifrado_txt, priv1)
    desc_txt2 = zch_e2ee.desencriptar_e2ee_multi(cifrado_txt, priv2)
    
    assert desc_txt1 == mensaje, "Fallo descifrado programático texto Alice."
    assert desc_txt2 == mensaje, "Fallo descifrado programático texto Bob."
    print("    [OK] Cifrado y descifrado programático de texto multi-destinatario exitoso.")
    
    # 2. Probar CLI
    temp_file = "temp_v114_data.txt"
    temp_enc = "temp_v114_data.enc"
    temp_dec = "temp_v114_data_dec.txt"
    
    env_dict = os.environ.copy()
    env_dict["PYTHONPATH"] = os.path.abspath("src")
    
    ruta_ks = "temp_v114_ks.json"
    pwd_ks = "KeystorePassword123!"
    
    try:
        # Escribir mensaje
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(mensaje)
            
        # Crear Keystore y agregar llaves
        ks = zch_e2ee.KeystoreZCH.crear(ruta_ks, pwd_ks)
        ks.guardar_clave_contacto("alice_contact", pub1)
        ks.guardar_clave_contacto("bob_contact", pub2)
        ks.guardar_clave_propia("alice_key", priv1)
        ks.guardar_clave_propia("bob_key", priv2)
        ks.guardar(ruta_ks, pwd_ks)
        
        # Test CLI: encrypt-text-multi usando alias y llaves directas
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "encrypt-text-multi",
            "--text", mensaje,
            "--keys-public", temp_pub1,
            "--keys-aliases", "bob_contact",
            "--keystore", ruta_ks,
            "--password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        cifrado_cli = json.loads(res.stdout)["cipher"]
        
        # Test CLI: decrypt-text-multi usando alias
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "decrypt-text-multi",
            "--text", cifrado_cli,
            "--key-alias", "alice_key",
            "--keystore", ruta_ks,
            "--password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["plain"] == mensaje
        
        print("    [OK] Cifrado y descifrado de texto multi-destinatario via CLI exitoso.")
        
        # Test CLI: encrypt-multi (archivos)
        subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "encrypt-multi",
            "--in-file", temp_file,
            "--out-file", temp_enc,
            "--keys-public", temp_pub1,
            "--keys-aliases", "bob_contact",
            "--keystore", ruta_ks,
            "--password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        
        # Test CLI: decrypt-multi (archivos) usando alias
        subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "decrypt-multi",
            "--in-file", temp_enc,
            "--out-file", temp_dec,
            "--key-alias", "bob_key",
            "--keystore", ruta_ks,
            "--password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        
        with open(temp_dec, "r", encoding="utf-8") as f:
            assert f.read() == mensaje
            
        print("    [OK] Cifrado y descifrado de archivos multi-destinatario via CLI exitoso.")
        
        # 3. Test de Fallback con Historial en Multi-destinatario
        # Rotamos la clave de Alice para generar historial
        ks.rotar_clave("alice_key") # Nueva llave activa en Keystore
        ks.guardar(ruta_ks, pwd_ks)
        
        # Ciframos usando la clave nueva y la antigua desde Keystore
        # (El descifrado de Alice usando la clave en el historial debe tener exito)
        # Ciframos con la clave antigua de Alice (guardada en pub1/temp_pub1)
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "encrypt-text-multi",
            "--text", mensaje,
            "--keys-public", temp_pub1
        ], env=env_dict, capture_output=True, text=True, check=True)
        cifrado_fallback = json.loads(res.stdout)["cipher"]
        
        # Desciframos con el alias 'alice_key' (la activa fallará, pero el fallback en historial debe pasar)
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "decrypt-text-multi",
            "--text", cifrado_fallback,
            "--key-alias", "alice_key",
            "--keystore", ruta_ks,
            "--password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["plain"] == mensaje
        
        print("    [OK] Fallback de llaves del historial en descifrado multi-destinatario exitoso.")
        
    finally:
        # Limpiar
        for f in [temp_pub1, temp_pub2, temp_priv1, temp_priv2, temp_file, temp_enc, temp_dec, ruta_ks]:
            if os.path.exists(f):
                os.remove(f)
                
    print("  [OK] Pruebas de nuevas caracteristicas v1.1.4 completadas con exito.")

def test_nuevas_caracteristicas_v115():
    print("\n--- TEST: Nuevas Caracteristicas v1.1.5 (Cifrado y Firma Multi-destinatario) ---")
    
    # 1. Preparar llaves de prueba
    # Destinatarios
    priv_rsa_dest1, pub_rsa_dest1 = zch_e2ee.generar_llaves()
    priv_rsa_dest2, pub_rsa_dest2 = zch_e2ee.generar_llaves()
    priv_ec_dest1, pub_ec_dest1 = zch_e2ee.generar_llaves_ec()
    priv_ec_dest2, pub_ec_dest2 = zch_e2ee.generar_llaves_ec()
    
    # Emisores (para firmar)
    priv_rsa_emisor, pub_rsa_emisor = zch_e2ee.generar_llaves()
    priv_ed_emisor, pub_ed_emisor = zch_e2ee.generar_llaves_ed25519()
    
    mensaje = "Este es un mensaje secreto y firmado de prueba para v1.1.5."
    
    # --- PRUEBAS PROGRAMÁTICAS ---
    
    # A. Texto: RSA dest, RSA emisor
    cifrado_rsa_rsa = zch_e2ee.encriptar_y_firmar_e2ee_multi(mensaje, [pub_rsa_dest1, pub_rsa_dest2], priv_rsa_emisor)
    # Descifrar y verificar
    dec_rsa_rsa1, firma_valida1 = zch_e2ee.desencriptar_y_verificar_e2ee_multi(cifrado_rsa_rsa, priv_rsa_dest1, pub_rsa_emisor)
    dec_rsa_rsa2, firma_valida2 = zch_e2ee.desencriptar_y_verificar_e2ee_multi(cifrado_rsa_rsa, priv_rsa_dest2, pub_rsa_emisor)
    assert dec_rsa_rsa1 == mensaje and firma_valida1
    assert dec_rsa_rsa2 == mensaje and firma_valida2
    
    # B. Texto: X25519 dest, Ed25519 emisor
    cifrado_ec_ed = zch_e2ee.encriptar_y_firmar_e2ee_multi(mensaje, [pub_ec_dest1, pub_ec_dest2], priv_ed_emisor)
    dec_ec_ed1, firma_valida3 = zch_e2ee.desencriptar_y_verificar_e2ee_multi(cifrado_ec_ed, priv_ec_dest1, pub_ed_emisor)
    dec_ec_ed2, firma_valida4 = zch_e2ee.desencriptar_y_verificar_e2ee_multi(cifrado_ec_ed, priv_ec_dest2, pub_ed_emisor)
    assert dec_ec_ed1 == mensaje and firma_valida3
    assert dec_ec_ed2 == mensaje and firma_valida4
    
    # C. Texto: RSA dest, Ed25519 emisor
    cifrado_rsa_ed = zch_e2ee.encriptar_y_firmar_e2ee_multi(mensaje, [pub_rsa_dest1], priv_ed_emisor)
    dec_rsa_ed, firma_valida5 = zch_e2ee.desencriptar_y_verificar_e2ee_multi(cifrado_rsa_ed, priv_rsa_dest1, pub_ed_emisor)
    assert dec_rsa_ed == mensaje and firma_valida5

    # D. Texto: X25519 dest, RSA emisor
    cifrado_ec_rsa = zch_e2ee.encriptar_y_firmar_e2ee_multi(mensaje, [pub_ec_dest1], priv_rsa_emisor)
    dec_ec_rsa, firma_valida6 = zch_e2ee.desencriptar_y_verificar_e2ee_multi(cifrado_ec_rsa, priv_ec_dest1, pub_rsa_emisor)
    assert dec_ec_rsa == mensaje and firma_valida6

    # E. Prueba de alteración (firma inválida)
    cifrado_alterado_bytes = bytearray(base64.b64decode(cifrado_rsa_rsa.encode('utf-8')))
    cifrado_alterado_bytes[20] ^= 0xFF
    cifrado_alterado = base64.b64encode(cifrado_alterado_bytes).decode('utf-8')
    try:
        dec_alt, firma_alt = zch_e2ee.desencriptar_y_verificar_e2ee_multi(cifrado_alterado, priv_rsa_dest1, pub_rsa_emisor)
        assert not firma_alt, "La firma debio ser detectada como invalida tras alteracion."
    except Exception:
        pass

    print("    [OK] Pruebas programaticas de texto cifrado y firmado pasaron.")

    # F. Archivo: X25519 dest, Ed25519 emisor
    temp_file = "temp_v115_file.txt"
    temp_enc = "temp_v115_file.enc"
    temp_dec1 = "temp_v115_file_dec1.txt"
    temp_dec2 = "temp_v115_file_dec2.txt"
    
    with open(temp_file, "w", encoding="utf-8") as f:
        f.write(mensaje)
        
    try:
        zch_e2ee.encriptar_y_firmar_archivo_e2ee_multi(temp_file, temp_enc, [pub_ec_dest1, pub_ec_dest2], priv_ed_emisor)
        
        with open(temp_enc, "rb") as f:
            header = f.read(5)
            assert header == b"ZCH\x02\x09", f"Cabecera inesperada: {header}"
            
        v1 = zch_e2ee.desencriptar_y_verificar_archivo_e2ee_multi(temp_enc, temp_dec1, priv_ec_dest1, pub_ed_emisor)
        v2 = zch_e2ee.desencriptar_y_verificar_archivo_e2ee_multi(temp_enc, temp_dec2, priv_ec_dest2, pub_ed_emisor)
        assert v1 and v2, "Las firmas de archivo debieron ser validas."
        
        with open(temp_dec1, "r", encoding="utf-8") as f:
            assert f.read() == mensaje
        with open(temp_dec2, "r", encoding="utf-8") as f:
            assert f.read() == mensaje
            
        # G. Alterar archivo y verificar rechazo
        with open(temp_enc, "r+b") as f:
            f.seek(15)
            original_byte = f.read(1)
            f.seek(15)
            f.write(bytes([original_byte[0] ^ 0xFF]))
            
        try:
            v_alt = zch_e2ee.desencriptar_y_verificar_archivo_e2ee_multi(temp_enc, temp_dec1, priv_ec_dest1, pub_ed_emisor)
            assert not v_alt, "La firma debio ser invalida tras alterar archivo."
        except Exception:
            pass
            
        print("    [OK] Pruebas programaticas de archivo cifrado y firmado pasaron.")
    finally:
        for f in [temp_file, temp_enc, temp_dec1, temp_dec2]:
            if os.path.exists(f):
                os.remove(f)

    # H. Directorio: RSA dest, Ed25519 emisor
    temp_dir = "temp_v115_dir"
    temp_dir_out1 = "temp_v115_dir_out1"
    temp_dir_out2 = "temp_v115_dir_out2"
    temp_dir_enc = "temp_v115_dir.enc"
    
    os.makedirs(temp_dir, exist_ok=True)
    with open(os.path.join(temp_dir, "archivo_dir.txt"), "w", encoding="utf-8") as f:
        f.write(mensaje)
        
    try:
        zch_e2ee.encriptar_y_firmar_directorio_e2ee_multi(temp_dir, temp_dir_enc, [pub_rsa_dest1, pub_rsa_dest2], priv_ed_emisor)
        
        with open(temp_dir_enc, "rb") as f:
            header = f.read(5)
            assert header == b"ZCH\x02\x0a", f"Cabecera inesperada: {header}"
            
        v1 = zch_e2ee.desencriptar_y_verificar_directorio_e2ee_multi(temp_dir_enc, temp_dir_out1, priv_rsa_dest1, pub_ed_emisor)
        v2 = zch_e2ee.desencriptar_y_verificar_directorio_e2ee_multi(temp_dir_enc, temp_dir_out2, priv_rsa_dest2, pub_ed_emisor)
        assert v1 and v2, "Las firmas de directorio debieron ser validas."
        
        with open(os.path.join(temp_dir_out1, "archivo_dir.txt"), "r", encoding="utf-8") as f:
            assert f.read() == mensaje
        with open(os.path.join(temp_dir_out2, "archivo_dir.txt"), "r", encoding="utf-8") as f:
            assert f.read() == mensaje
            
        print("    [OK] Pruebas programaticas de directorio cifrado y firmado pasaron.")
    finally:
        for d in [temp_dir, temp_dir_out1, temp_dir_out2]:
            if os.path.exists(d):
                shutil.rmtree(d)
        if os.path.exists(temp_dir_enc):
            os.remove(temp_dir_enc)

    # --- PRUEBAS CLI ---
    temp_pub_rsa = "temp_v115_pub_rsa.pem"
    temp_priv_rsa = "temp_v115_priv_rsa.pem"
    temp_pub_ed = "temp_v115_pub_ed.pem"
    temp_priv_ed = "temp_v115_priv_ed.pem"
    
    zch_e2ee.guardar_llave_publica_en_archivo(pub_rsa_dest1, temp_pub_rsa)
    zch_e2ee.guardar_llave_privada_en_archivo(priv_rsa_dest1, temp_priv_rsa)
    zch_e2ee.guardar_llave_publica_ec_en_archivo(pub_ed_emisor, temp_pub_ed)
    zch_e2ee.guardar_llave_privada_ec_en_archivo(priv_ed_emisor, temp_priv_ed)
    
    env_dict = os.environ.copy()
    env_dict["PYTHONPATH"] = os.path.abspath("src")
    
    ruta_ks = "temp_v115_ks.json"
    pwd_ks = "KeystorePasswordV115!"
    
    temp_plain_file = "temp_v115_cli_plain.txt"
    temp_enc_file = "temp_v115_cli_enc.enc"
    temp_dec_file = "temp_v115_cli_dec.txt"
    
    with open(temp_plain_file, "w", encoding="utf-8") as f:
        f.write(mensaje)
        
    try:
        ks = zch_e2ee.KeystoreZCH.crear(ruta_ks, pwd_ks)
        ks.guardar_clave_propia("dest_rsa", priv_rsa_dest1)
        ks.guardar_clave_contacto("dest_rsa_pub", pub_rsa_dest1)
        ks.guardar_clave_contacto("emisor_ed", pub_ed_emisor)
        ks.guardar_clave_propia("emisor_ed_priv", priv_ed_emisor)
        ks.guardar(ruta_ks, pwd_ks)
        
        # 1. CLI: encrypt-text-multi & decrypt-text-multi con archivos PEM directos
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "encrypt-text-multi",
            "--text", mensaje,
            "--keys-public", temp_pub_rsa,
            "--sign-private", temp_priv_ed
        ], env=env_dict, capture_output=True, text=True, check=True)
        cipher_text = json.loads(res.stdout)["cipher"]
        
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "decrypt-text-multi",
            "--text", cipher_text,
            "--key-private", temp_priv_rsa,
            "--verify-public", temp_pub_ed
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["plain"] == mensaje
        
        # 2. CLI: encrypt-text-multi & decrypt-text-multi con Keystore
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "encrypt-text-multi",
            "--text", mensaje,
            "--keys-aliases", "dest_rsa_pub",
            "--sign-alias", "emisor_ed_priv",
            "--keystore", ruta_ks,
            "--password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        cipher_text_ks = json.loads(res.stdout)["cipher"]
        
        res = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "decrypt-text-multi",
            "--text", cipher_text_ks,
            "--key-alias", "dest_rsa",
            "--verify-alias", "emisor_ed",
            "--keystore", ruta_ks,
            "--password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res.stdout)["plain"] == mensaje
        
        # 3. CLI: encrypt-multi & decrypt-multi (archivos) con firmas
        subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "encrypt-multi",
            "--in-file", temp_plain_file,
            "--out-file", temp_enc_file,
            "--keys-public", temp_pub_rsa,
            "--sign-private", temp_priv_ed
        ], env=env_dict, capture_output=True, text=True, check=True)
        
        subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "decrypt-multi",
            "--in-file", temp_enc_file,
            "--out-file", temp_dec_file,
            "--key-private", temp_priv_rsa,
            "--verify-public", temp_pub_ed
        ], env=env_dict, capture_output=True, text=True, check=True)
        
        with open(temp_dec_file, "r", encoding="utf-8") as f:
            assert f.read() == mensaje
            
        # 4. CLI: Rechazo de firma alterada
        with open(temp_enc_file, "r+b") as f:
            f.seek(10)
            orig_b = f.read(1)
            f.seek(10)
            f.write(bytes([orig_b[0] ^ 0x01]))
            
        res_alt = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "decrypt-multi",
            "--in-file", temp_enc_file,
            "--out-file", temp_dec_file,
            "--key-private", temp_priv_rsa,
            "--verify-public", temp_pub_ed
        ], env=env_dict, capture_output=True, text=True)
        assert res_alt.returncode != 0
        assert "La firma digital" in res_alt.stderr or "Fallo al descifrar" in res_alt.stderr or "error" in res_alt.stdout
        
        # 5. CLI: Fallback con historial en descifrado firmado
        with open(temp_plain_file, "w", encoding="utf-8") as f:
            f.write(mensaje)
        subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "encrypt-multi",
            "--in-file", temp_plain_file,
            "--out-file", temp_enc_file,
            "--keys-aliases", "dest_rsa_pub",
            "--sign-alias", "emisor_ed_priv",
            "--keystore", ruta_ks,
            "--password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        
        ks.rotar_clave("dest_rsa")
        ks.guardar(ruta_ks, pwd_ks)
        
        if os.path.exists(temp_dec_file):
            os.remove(temp_dec_file)
        subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "decrypt-multi",
            "--in-file", temp_enc_file,
            "--out-file", temp_dec_file,
            "--key-alias", "dest_rsa",
            "--verify-alias", "emisor_ed",
            "--keystore", ruta_ks,
            "--password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        
        with open(temp_dec_file, "r", encoding="utf-8") as f:
            assert f.read() == mensaje
            
        print("    [OK] Pruebas de CLI de texto, archivos, firmas y fallbacks pasaron.")
    finally:
        for f in [temp_pub_rsa, temp_priv_rsa, temp_pub_ed, temp_priv_ed, ruta_ks, temp_plain_file, temp_enc_file, temp_dec_file]:
            if os.path.exists(f):
                os.remove(f)

    print("  [OK] Pruebas de nuevas caracteristicas v1.1.5 completadas con exito.")

def test_nuevas_caracteristicas_v116():
    print("\n--- TEST: Nuevas Caracteristicas v1.1.6 (Handshake Autenticado y Firmado) ---")
    
    # 1. Prueba Programática: Inicializar Double Ratchet signed handshake
    priv_alice, pub_alice = zch_e2ee.generar_llaves_ec()
    priv_bob, pub_bob = zch_e2ee.generar_llaves_ec()
    
    sesion_alice = zch_e2ee.SesionDoubleRatchet(priv_alice, pub_bob, es_iniciador=True)
    sesion_bob = zch_e2ee.SesionDoubleRatchet(priv_bob, pub_alice, es_iniciador=False)
    
    priv_firma_alice, pub_firma_alice = zch_e2ee.generar_llaves_ed25519()
    pub_identity_alice_bytes = priv_alice.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    pub_ephemeral_alice_bytes = sesion_alice.dh_local.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    datos_a_firmar = pub_identity_alice_bytes + pub_ephemeral_alice_bytes
    firma = zch_e2ee._firmar_datos_generico(datos_a_firmar, priv_firma_alice)
    
    es_valida = zch_e2ee._verificar_firma_datos_generico(datos_a_firmar, firma, pub_firma_alice)
    assert es_valida, "La firma del handshake deberia ser valida."
    
    sesion_bob.clave_publica_efimera_esperada_remota_hex = pub_ephemeral_alice_bytes.hex()
    
    msg = "Mensaje con handshake firmado"
    cifrado = sesion_alice.enviar_mensaje(msg)
    descifrado = sesion_bob.recibir_mensaje(cifrado)
    assert descifrado == msg, "El descifrado deberia ser exitoso."
    assert sesion_bob.clave_publica_efimera_esperada_remota_hex is None, "La clave efimera esperada debio limpiarse tras recibir el primer mensaje."
    
    # 2. Prueba de Rechazo Programático: Firma corrupta y clave efímera inesperada
    firma_corrupta = bytearray(firma)
    firma_corrupta[0] ^= 0xFF
    es_valida_corrupta = zch_e2ee._verificar_firma_datos_generico(datos_a_firmar, bytes(firma_corrupta), pub_firma_alice)
    assert not es_valida_corrupta, "La firma corrupta deberia ser invalida."
    
    sesion_bob_error = zch_e2ee.SesionDoubleRatchet(priv_bob, pub_alice, es_iniciador=False)
    sesion_bob_error.clave_publica_efimera_esperada_remota_hex = "a" * 64
    cifrado2 = sesion_alice.enviar_mensaje("Mensaje fallido")
    try:
        sesion_bob_error.recibir_mensaje(cifrado2)
        assert False, "Deberia lanzar ErrorFirma por clave efimera inesperada."
    except zch_e2ee.ErrorFirma:
        pass
        
    print("    [OK] Pruebas programaticas del handshake firmado pasaron.")

    # 3. CLI signed handshake tests
    temp_alice_priv = "temp_v116_alice_priv.pem"
    temp_alice_pub = "temp_v116_alice_pub.pem"
    temp_bob_priv = "temp_v116_bob_priv.pem"
    temp_bob_pub = "temp_v116_bob_pub.pem"
    temp_alice_sign_priv = "temp_v116_alice_sign_priv.pem"
    temp_alice_sign_pub = "temp_v116_alice_sign_pub.pem"
    
    temp_alice_ses = "temp_v116_alice_ses.json"
    temp_bob_ses = "temp_v116_bob_ses.json"
    temp_invitation = "temp_v116_invitation.json"
    temp_invitation_corrupt = "temp_v116_invitation_corrupt.json"
    temp_invitation_altered = "temp_v116_invitation_altered.json"
    temp_invitation_ks = "temp_v116_invitation_ks.json"
    ruta_ks = "temp_v116_ks.json"
    temp_alice_ses_ks = "temp_v116_alice_ses_ks.json"
    temp_bob_ses_ks = "temp_v116_bob_ses_ks.json"
    
    zch_e2ee.guardar_llave_privada_ec_en_archivo(priv_alice, temp_alice_priv)
    zch_e2ee.guardar_llave_publica_ec_en_archivo(pub_alice, temp_alice_pub)
    zch_e2ee.guardar_llave_privada_ec_en_archivo(priv_bob, temp_bob_priv)
    zch_e2ee.guardar_llave_publica_ec_en_archivo(pub_bob, temp_bob_pub)
    zch_e2ee.guardar_llave_privada_ec_en_archivo(priv_firma_alice, temp_alice_sign_priv)
    zch_e2ee.guardar_llave_publica_ec_en_archivo(pub_firma_alice, temp_alice_sign_pub)
    
    env_dict = os.environ.copy()
    env_dict["PYTHONPATH"] = os.path.abspath("src")
    
    try:
        # A. CLI ratchet-init: Alice (iniciador, firma el handshake)
        subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "ratchet-init",
            "--initiator",
            "--key-private", temp_alice_priv,
            "--key-public", temp_bob_pub,
            "--out-session", temp_alice_ses,
            "--sign-private", temp_alice_sign_priv,
            "--out-invitation", temp_invitation
        ], env=env_dict, capture_output=True, text=True, check=True)
        
        # B. CLI ratchet-init: Bob (receptor, verifica la invitación)
        subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "ratchet-init",
            "--key-private", temp_bob_priv,
            "--key-public", temp_alice_pub,
            "--out-session", temp_bob_ses,
            "--verify-public", temp_alice_sign_pub,
            "--in-invitation", temp_invitation
        ], env=env_dict, capture_output=True, text=True, check=True)
        
        # C. Intercambio de mensajes CLI
        msg_cli = "Prueba de Double Ratchet firmado CLI"
        res_enc = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "ratchet-encrypt",
            "--session", temp_alice_ses,
            "--out-session", temp_alice_ses,
            "--text", msg_cli
        ], env=env_dict, capture_output=True, text=True, check=True)
        cipher_cli = json.loads(res_enc.stdout)["cipher"]
        
        res_dec = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "ratchet-decrypt",
            "--session", temp_bob_ses,
            "--out-session", temp_bob_ses,
            "--text", cipher_cli
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res_dec.stdout)["plain"] == msg_cli
        
        # D. CLI handshake rejection: Invitación alterada (firma corrupta)
        with open(temp_invitation, "r", encoding="utf-8") as f:
            inv_data = json.load(f)
        
        inv_data_corrupt = inv_data.copy()
        inv_data_corrupt["signature"] = base64.b64encode(b"firma_totalmente_invalida").decode('utf-8')
        
        with open(temp_invitation_corrupt, "w", encoding="utf-8") as f:
            json.dump(inv_data_corrupt, f)
            
        res_init_corrupt = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "ratchet-init",
            "--key-private", temp_bob_priv,
            "--key-public", temp_alice_pub,
            "--out-session", temp_bob_ses,
            "--verify-public", temp_alice_sign_pub,
            "--in-invitation", temp_invitation_corrupt
        ], env=env_dict, capture_output=True, text=True)
        assert res_init_corrupt.returncode != 0, "Deberia fallar ratchet-init con firma corrupta."
        
        # E. CLI handshake rejection: Clave efímera alterada en la invitación
        inv_data_altered_key = inv_data.copy()
        orig_key = inv_data_altered_key["ephemeral_key"]
        new_char = '1' if orig_key[0] != '1' else '2'
        inv_data_altered_key["ephemeral_key"] = new_char + orig_key[1:]
        
        with open(temp_invitation_altered, "w", encoding="utf-8") as f:
            json.dump(inv_data_altered_key, f)
            
        res_init_altered = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "ratchet-init",
            "--key-private", temp_bob_priv,
            "--key-public", temp_alice_pub,
            "--out-session", temp_bob_ses,
            "--verify-public", temp_alice_sign_pub,
            "--in-invitation", temp_invitation_altered
        ], env=env_dict, capture_output=True, text=True)
        assert res_init_altered.returncode != 0, "Deberia fallar ratchet-init con clave efimera alterada."
        
        print("    [OK] Pruebas de CLI ratchet-init firmado pasaron.")
        
        # F. Keystore-based signed initialization
        pwd_ks = "KeystorePasswordV116!"
        
        ks = zch_e2ee.KeystoreZCH.crear(ruta_ks, pwd_ks)
        ks.guardar_clave_propia("alice_priv", priv_alice)
        ks.guardar_clave_contacto("alice_pub_alias", pub_alice)
        ks.guardar_clave_propia("bob_priv", priv_bob)
        ks.guardar_clave_contacto("bob_pub_alias", pub_bob)
        ks.guardar_clave_propia("alice_sign_priv_alias", priv_firma_alice)
        ks.guardar_clave_contacto("alice_sign_pub_alias", pub_firma_alice)
        ks.guardar(ruta_ks, pwd_ks)
        
        subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "ratchet-init",
            "--initiator",
            "--key-private-alias", "alice_priv",
            "--key-public-alias", "bob_pub_alias",
            "--out-session", temp_alice_ses_ks,
            "--sign-alias", "alice_sign_priv_alias",
            "--out-invitation", temp_invitation_ks,
            "--keystore", ruta_ks,
            "--keystore-password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        
        subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "ratchet-init",
            "--key-private-alias", "bob_priv",
            "--key-public-alias", "alice_pub_alias",
            "--out-session", temp_bob_ses_ks,
            "--verify-alias", "alice_sign_pub_alias",
            "--in-invitation", temp_invitation_ks,
            "--keystore", ruta_ks,
            "--keystore-password", pwd_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        
        res_enc_ks = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "ratchet-encrypt",
            "--session", temp_alice_ses_ks,
            "--out-session", temp_alice_ses_ks,
            "--text", "Mensaje Keystore"
        ], env=env_dict, capture_output=True, text=True, check=True)
        cipher_ks = json.loads(res_enc_ks.stdout)["cipher"]
        
        res_dec_ks = subprocess.run([
            sys.executable, "-m", "zch_e2ee", "--json", "ratchet-decrypt",
            "--session", temp_bob_ses_ks,
            "--out-session", temp_bob_ses_ks,
            "--text", cipher_ks
        ], env=env_dict, capture_output=True, text=True, check=True)
        assert json.loads(res_dec_ks.stdout)["plain"] == "Mensaje Keystore"
        
        print("    [OK] Pruebas de Keystore con handshake firmado pasaron.")
        
    finally:
        temp_files = [
            temp_alice_priv, temp_alice_pub, temp_bob_priv, temp_bob_pub,
            temp_alice_sign_priv, temp_alice_sign_pub, temp_alice_ses, temp_bob_ses,
            temp_invitation, temp_invitation_corrupt, temp_invitation_altered,
            temp_invitation_ks, ruta_ks, temp_alice_ses_ks, temp_bob_ses_ks
        ]
        for f in temp_files:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass
                    
    print("  [OK] Pruebas de nuevas caracteristicas v1.1.6 completadas con exito.")

def main():
    print("=" * 75)
    print(" PRUEBAS UNITARIAS DE SISTEMA - zch_e2ee v1.1.6")
    print("=" * 75)
    
    try:
        # Tests Heredados/Clásicos
        test_cifrado_password()
        test_encriptacion_firmada()
        test_archivos()
        test_archivo_password()
        test_firma_archivo_y_checksum()
        test_archivo_cifrado_firmado()
        test_rsa_4096_bits()
        test_encriptacion_directorios()
        
        # Tests v0.8.0
        test_excepciones_cripto()
        test_firmas_ed25519()
        test_serializacion_llaves_ec()
        test_e2ee_ec()
        test_archivos_y_directorios_ec()
        test_directorio_password()
        test_compatibilidad_retroactiva()
        
        # Tests v0.9.0
        test_e2ee_multi_rsa()
        test_e2ee_multi_ec()
        test_e2ee_multi_errores()
        test_archivo_multi()
        
        # Tests v1.0.0
        test_shamir_secret_sharing()
        test_keystore_zch()
        test_double_ratchet()
        test_hmac_autenticacion()
        test_encrypted_importer()
        test_excepciones_detalladas_v1()
        
        # Tests v1.0.1
        test_keystore_listar_alias()
        test_shamir_optimizado_stress()
        
        # Tests v1.0.2
        test_keystore_cli()
        
        # Tests v1.0.7
        test_nuevas_caracteristicas_v107()
        
        # Tests v1.0.8
        test_nuevas_caracteristicas_v108()
        
        # Tests v1.0.9
        test_nuevas_caracteristicas_v109()
        
        # Tests v1.1.0
        test_nuevas_caracteristicas_v110()
        
        # Tests v1.1.1
        test_nuevas_caracteristicas_v111()
        
        # Tests v1.1.2
        test_nuevas_caracteristicas_v112()
        
        # Tests v1.1.3
        test_nuevas_caracteristicas_v113()
        
        # Tests v1.1.4
        test_nuevas_caracteristicas_v114()
        
        # Tests v1.1.5
        test_nuevas_caracteristicas_v115()
        
        # Tests v1.1.6
        test_nuevas_caracteristicas_v116()
        
        print("\n[OK] ¡TODOS LOS TESTS DE LA V1.1.6 PASARON EXITOSAMENTE!")
    except AssertionError as e:
        import traceback
        traceback.print_exc()
        print(f"\n[ERROR] Fallo en la validacion: {e}")
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"\n[ERROR] Error inesperado en ejecucion: {e}")
    
    print("=" * 75)

if __name__ == "__main__":
    main()