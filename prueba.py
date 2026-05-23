import os
import shutil
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
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    import zlib
    
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
# MAIN RUNNER
# =====================================================================

def main():
    print("=" * 75)
    print(" PRUEBAS UNITARIAS DE SISTEMA - zch_e2ee v0.9.0")
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
        
        print("\n[OK] ¡TODOS LOS TESTS DE LA V0.9.0 PASARON EXITOSAMENTE!")
    except AssertionError as e:
        print(f"\n[ERROR] Fallo en la validacion: {e}")
    except Exception as e:
        print(f"\n[ERROR] Error inesperado en ejecucion: {e}")
    
    print("=" * 75)

if __name__ == "__main__":
    main()