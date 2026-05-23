import os
import zlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding, x25519, utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def generar_llaves(tamanio_clave: int = 2048):
    """
    Genera un par de llaves asimétricas RSA (privada y pública).
    """
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=tamanio_clave
    )
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica

def serializar_llave_privada(clave_privada) -> str:
    """
    Convierte la llave privada en formato PEM (texto).
    """
    pem = clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode('utf-8')

def serializar_llave_publica(clave_publica) -> str:
    """
    Convierte la llave pública en formato PEM (texto).
    """
    pem = clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')

def cargar_llave_privada(pem_str: str):
    """
    Carga una llave privada desde su representación en texto PEM.
    """
    return serialization.load_pem_private_key(
        pem_str.encode('utf-8'),
        password=None
    )

def cargar_llave_publica(pem_str: str):
    """
    Carga una llave pública desde su representación en texto PEM.
    """
    return serialization.load_pem_public_key(
        pem_str.encode('utf-8')
    )

def encriptar_e2ee(mensaje: str, clave_publica_destinatario) -> str:
    """
    Encripta un mensaje de texto para un destinatario usando su llave pública RSA.
    Usa encriptación híbrida (AES-GCM de 256 bits + RSA-OAEP con SHA-256).
    Retorna un string codificado en Base64 con el payload cifrado.
    """
    # 1. Convertir el mensaje a bytes y aplicar compresion zlib
    datos_mensaje = zlib.compress(mensaje.encode('utf-8'))

    # 2. Generar una clave simétrica temporal para AES-GCM
    clave_aes = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(clave_aes)
    
    # Generar un valor único de inicialización (nonce) de 12 bytes para AES-GCM
    nonce = os.urandom(12)
    
    # Encriptar el mensaje con AES-GCM
    texto_cifrado = aesgcm.encrypt(nonce, datos_mensaje, None)

    # 3. Encriptar la clave AES usando la llave pública RSA del destinatario
    clave_aes_encriptada = clave_publica_destinatario.encrypt(
        clave_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 4. Empaquetar todo en un solo string Base64 para su transmisión segura
    paquete_cifrado = clave_aes_encriptada + nonce + texto_cifrado
    return base64.b64encode(paquete_cifrado).decode('utf-8')

def desencriptar_e2ee(payload_b64: str, clave_privada_destinatario) -> str:
    """
    Desencripta un mensaje cifrado usando la llave privada RSA del destinatario.
    """
    # 1. Decodificar el paquete desde Base64
    paquete_cifrado = base64.b64decode(payload_b64.encode('utf-8'))

    # Para RSA-2048, la clave AES encriptada mide exactamente 256 bytes
    tamanio_rsa_key = 256
    tamanio_nonce = 12

    # 2. Extraer los componentes del paquete
    clave_aes_encriptada = paquete_cifrado[:tamanio_rsa_key]
    nonce = paquete_cifrado[tamanio_rsa_key : tamanio_rsa_key + tamanio_nonce]
    texto_cifrado = paquete_cifrado[tamanio_rsa_key + tamanio_nonce:]

    # 3. Desencriptar la clave AES usando la llave privada RSA
    clave_aes = clave_privada_destinatario.decrypt(
        clave_aes_encriptada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 4. Desencriptar el mensaje original usando AES-GCM y descomprimir
    aesgcm = AESGCM(clave_aes)
    datos_comprimidos = aesgcm.decrypt(nonce, texto_cifrado, None)
    datos_mensaje = zlib.decompress(datos_comprimidos)
    
    return datos_mensaje.decode('utf-8')

def firmar_mensaje(mensaje: str, clave_privada_emisor) -> str:
    """
    Firma digitalmente un mensaje de texto usando la llave privada del emisor.
    Retorna la firma codificada en Base64.
    """
    datos_mensaje = mensaje.encode('utf-8')
    firma = clave_privada_emisor.sign(
        datos_mensaje,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(firma).decode('utf-8')

def verificar_firma(mensaje: str, firma_b64: str, clave_publica_emisor) -> bool:
    """
    Verifica la autenticidad de un mensaje usando su firma digital y la llave pública del emisor.
    Retorna True si la firma es válida, False en caso contrario.
    """
    datos_mensaje = mensaje.encode('utf-8')
    firma = base64.b64decode(firma_b64.encode('utf-8'))
    try:
        clave_publica_emisor.verify(
            firma,
            datos_mensaje,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def guardar_llave_privada_en_archivo(clave_privada, ruta_archivo: str, password: str = None):
    """
    Guarda una llave privada en un archivo PEM. 
    Opcionalmente cifra la llave usando una contraseña.
    """
    if password:
        algoritmo_cifrado = serialization.BestAvailableEncryption(password.encode('utf-8'))
    else:
        algoritmo_cifrado = serialization.NoEncryption()
        
    pem = clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=algoritmo_cifrado
    )
    with open(ruta_archivo, 'wb') as f:
        f.write(pem)

def guardar_llave_publica_en_archivo(clave_publica, ruta_archivo: str):
    """
    Guarda una llave pública en un archivo PEM.
    """
    pem = clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(ruta_archivo, 'wb') as f:
        f.write(pem)

def cargar_llave_privada_desde_archivo(ruta_archivo: str, password: str = None):
    """
    Carga una llave privada desde un archivo PEM. 
    Requiere la contraseña si el archivo fue cifrado.
    """
    with open(ruta_archivo, 'rb') as f:
        pem_data = f.read()
    return serialization.load_pem_private_key(
        pem_data,
        password=password.encode('utf-8') if password else None
    )

def cargar_llave_publica_desde_archivo(ruta_archivo: str):
    """
    Carga una llave pública desde un archivo PEM.
    """
    with open(ruta_archivo, 'rb') as f:
        pem_data = f.read()
    return serialization.load_pem_public_key(pem_data)

def encriptar_archivo_e2ee(ruta_origen: str, ruta_destino: str, clave_publica_destinatario):
    """
    Encripta un archivo completo (de cualquier tipo) para un destinatario usando su llave publica.
    Guarda el archivo resultante en formato binario cifrado.
    """
    with open(ruta_origen, 'rb') as f:
        datos = f.read()
        
    # Comprimir datos del archivo
    datos_comprimidos = zlib.compress(datos)
        
    # Generar clave simetrica y nonce para AES-GCM
    clave_aes = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(clave_aes)
    nonce = os.urandom(12)
    datos_cifrados = aesgcm.encrypt(nonce, datos_comprimidos, None)
    
    # Cifrar clave AES con la publica RSA
    clave_aes_encriptada = clave_publica_destinatario.encrypt(
        clave_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Escribir el paquete binario: [clave_aes_encriptada (256 bytes)] + [nonce (12 bytes)] + [datos_cifrados]
    with open(ruta_destino, 'wb') as f:
        f.write(clave_aes_encriptada + nonce + datos_cifrados)

def desencriptar_archivo_e2ee(ruta_origen: str, ruta_destino: str, clave_privada_destinatario):
    """
    Desencripta un archivo cifrado con E2EE usando la llave privada del destinatario.
    Guarda el archivo descifrado en la ruta de destino.
    """
    with open(ruta_origen, 'rb') as f:
        paquete = f.read()
        
    tamanio_rsa_key = 256
    tamanio_nonce = 12
    
    # Extraer componentes del paquete binario
    clave_aes_encriptada = paquete[:tamanio_rsa_key]
    nonce = paquete[tamanio_rsa_key : tamanio_rsa_key + tamanio_nonce]
    datos_cifrados = paquete[tamanio_rsa_key + tamanio_nonce:]
    
    # Descifrar la clave AES con la privada RSA
    clave_aes = clave_privada_destinatario.decrypt(
        clave_aes_encriptada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Descifrar los datos con la clave AES y descomprimir
    aesgcm = AESGCM(clave_aes)
    datos_comprimidos = aesgcm.decrypt(nonce, datos_cifrados, None)
    datos_originales = zlib.decompress(datos_comprimidos)
    
    with open(ruta_destino, 'wb') as f:
        f.write(datos_originales)

def generar_llaves_ec():
    """
    Genera un par de llaves para curvas elípticas X25519 (privada y pública).
    Se utilizan para el acuerdo de claves Diffie-Hellman (ECDH).
    """
    clave_privada = x25519.X25519PrivateKey.generate()
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica

def derivar_clave_compartida(clave_privada_propia, clave_publica_destinatario) -> bytes:
    """
    Deriva una clave simétrica secreta compartida de 256 bits usando ECDH (X25519)
    y una función de derivación de claves (HKDF).
    """
    # Intercambio Diffie-Hellman
    secreto_compartido = clave_privada_propia.exchange(clave_publica_destinatario)
    
    # Derivación mediante HKDF
    clave_derivada = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'zch-e2ee ecdh key agreement'
    ).derive(secreto_compartido)
    
    return clave_derivada

def encriptar_con_password(mensaje: str, password: str) -> str:
    """
    Cifra un mensaje de texto usando una contraseña tradicional (cifrado simétrico).
    Deriva la clave de 256 bits usando Scrypt, y cifra con AES-GCM.
    Retorna un payload codificado en Base64.
    """
    # Comprimir mensaje
    datos_mensaje = zlib.compress(mensaje.encode('utf-8'))
    
    # Generar sal y nonce aleatorios
    sal = os.urandom(16)
    nonce = os.urandom(12)
    
    # Derivar clave AES con Scrypt
    kdf = Scrypt(
        salt=sal,
        length=32,
        n=2**14,
        r=8,
        p=1
    )
    clave_aes = kdf.derive(password.encode('utf-8'))
    
    # Cifrar usando AES-GCM
    aesgcm = AESGCM(clave_aes)
    texto_cifrado = aesgcm.encrypt(nonce, datos_mensaje, None)
    
    # Empaquetar: [sal (16 bytes)] + [nonce (12 bytes)] + [texto_cifrado]
    paquete = sal + nonce + texto_cifrado
    return base64.b64encode(paquete).decode('utf-8')

def desencriptar_con_password(payload_b64: str, password: str) -> str:
    """
    Descifra un mensaje cifrado con contraseña usando Scrypt y AES-GCM.
    """
    paquete = base64.b64decode(payload_b64.encode('utf-8'))
    
    tamanio_sal = 16
    tamanio_nonce = 12
    
    # Extraer componentes
    sal = paquete[:tamanio_sal]
    nonce = paquete[tamanio_sal : tamanio_sal + tamanio_nonce]
    texto_cifrado = paquete[tamanio_sal + tamanio_nonce:]
    
    # Derivar la misma clave usando la sal extraida
    kdf = Scrypt(
        salt=sal,
        length=32,
        n=2**14,
        r=8,
        p=1
    )
    clave_aes = kdf.derive(password.encode('utf-8'))
    
    # Descifrar usando AES-GCM y descomprimir
    aesgcm = AESGCM(clave_aes)
    datos_comprimidos = aesgcm.decrypt(nonce, texto_cifrado, None)
    datos_originales = zlib.decompress(datos_comprimidos)
    
    return datos_originales.decode('utf-8')

def encriptar_y_firmar_e2ee(mensaje: str, clave_publica_destinatario, clave_privada_emisor) -> str:
    """
    Cifra el mensaje para el destinatario (E2EE híbrido) y firma digitalmente
    el resultado con la clave privada del emisor. 
    Retorna el paquete completo (firma + mensaje cifrado) en Base64.
    """
    # 1. Cifrar usando la funcion base (genera un string base64)
    payload_cifrado_b64 = encriptar_e2ee(mensaje, clave_publica_destinatario)
    paquete_cifrado_bytes = base64.b64decode(payload_cifrado_b64.encode('utf-8'))
    
    # 2. Firmar los bytes cifrados (Encrypt-then-Sign) con la privada del emisor
    firma = clave_privada_emisor.sign(
        paquete_cifrado_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # 3. Empaquetar: [firma (256 bytes)] + [mensaje_cifrado_bytes]
    paquete_final = firma + paquete_cifrado_bytes
    return base64.b64encode(paquete_final).decode('utf-8')

def desencriptar_y_verificar_e2ee(payload_b64: str, clave_privada_destinatario, clave_publica_emisor) -> tuple[str, bool]:
    """
    Descifra un mensaje y verifica si la firma del emisor es valida.
    Retorna una tupla: (mensaje_desencriptado, firma_es_valida).
    """
    paquete_final = base64.b64decode(payload_b64.encode('utf-8'))
    
    tamanio_firma = 256 # Para RSA-2048 la firma mide 256 bytes
    
    # 1. Extraer firma y paquete cifrado
    firma = paquete_final[:tamanio_firma]
    paquete_cifrado_bytes = paquete_final[tamanio_firma:]
    
    # 2. Verificar la firma del emisor contra el texto cifrado
    try:
        clave_publica_emisor.verify(
            firma,
            paquete_cifrado_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        firma_valida = True
    except Exception:
        firma_valida = False
        
    # 3. Descifrar el mensaje
    payload_cifrado_b64 = base64.b64encode(paquete_cifrado_bytes).decode('utf-8')
    mensaje = desencriptar_e2ee(payload_cifrado_b64, clave_privada_destinatario)
    
    return mensaje, firma_valida

def encriptar_archivo_con_password(ruta_origen: str, ruta_destino: str, password: str):
    """
    Encripta un archivo completo de forma simetrica usando una contraseña.
    Aplica compresion zlib, deriva la clave mediante Scrypt y cifra usando AES-GCM.
    """
    with open(ruta_origen, 'rb') as f:
        datos = f.read()
        
    # Aplicar compresion
    datos_comprimidos = zlib.compress(datos)
    
    # Generar sal y nonce
    sal = os.urandom(16)
    nonce = os.urandom(12)
    
    # Derivar clave
    kdf = Scrypt(
        salt=sal,
        length=32,
        n=2**14,
        r=8,
        p=1
    )
    clave_aes = kdf.derive(password.encode('utf-8'))
    
    # Cifrar con AES-GCM
    aesgcm = AESGCM(clave_aes)
    datos_cifrados = aesgcm.encrypt(nonce, datos_comprimidos, None)
    
    # Escribir el archivo final: [sal (16 bytes)] + [nonce (12 bytes)] + [datos_cifrados]
    with open(ruta_destino, 'wb') as f:
        f.write(sal + nonce + datos_cifrados)

def desencriptar_archivo_con_password(ruta_origen: str, ruta_destino: str, password: str):
    """
    Descifra un archivo cifrado con contraseña usando Scrypt y AES-GCM,
    descomprimiendo los datos para recuperar el archivo original.
    """
    with open(ruta_origen, 'rb') as f:
        paquete = f.read()
        
    tamanio_sal = 16
    tamanio_nonce = 12
    
    # Extraer componentes
    sal = paquete[:tamanio_sal]
    nonce = paquete[tamanio_sal : tamanio_sal + tamanio_nonce]
    datos_cifrados = paquete[tamanio_sal + tamanio_nonce:]
    
    # Derivar la misma clave usando la sal
    kdf = Scrypt(
        salt=sal,
        length=32,
        n=2**14,
        r=8,
        p=1
    )
    clave_aes = kdf.derive(password.encode('utf-8'))
    
    # Descifrar y descomprimir
    aesgcm = AESGCM(clave_aes)
    datos_comprimidos = aesgcm.decrypt(nonce, datos_cifrados, None)
    datos_originales = zlib.decompress(datos_comprimidos)
    
    with open(ruta_destino, 'wb') as f:
        f.write(datos_originales)

def calcular_sha256(ruta_archivo: str) -> str:
    """
    Calcula el hash SHA-256 de cualquier archivo leyéndolo en bloques de 4KB.
    Retorna el hash en formato hexadecimal.
    """
    sha256_hash = hashes.Hash(hashes.SHA256())
    with open(ruta_archivo, "rb") as f:
        for bloque_bytes in iter(lambda: f.read(4096), b""):
            sha256_hash.update(bloque_bytes)
    return sha256_hash.finalize().hex()

def firmar_archivo(ruta_archivo: str, clave_privada_emisor) -> str:
    """
    Calcula el hash SHA-256 de un archivo y lo firma digitalmente con la clave privada del emisor.
    Retorna la firma codificada en Base64.
    """
    hash_bytes = bytes.fromhex(calcular_sha256(ruta_archivo))
    
    firma = clave_privada_emisor.sign(
        hash_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(hashes.SHA256())
    )
    return base64.b64encode(firma).decode('utf-8')

def verificar_firma_archivo(ruta_archivo: str, firma_b64: str, clave_publica_emisor) -> bool:
    """
    Verifica la firma digital de un archivo usando la llave pública del emisor.
    Retorna True si la firma es legítima y el archivo no ha sido alterado, False en caso contrario.
    """
    try:
        hash_bytes = bytes.fromhex(calcular_sha256(ruta_archivo))
        firma = base64.b64decode(firma_b64.encode('utf-8'))
        
        clave_publica_emisor.verify(
            firma,
            hash_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
        return True
    except Exception:
        return False

def encriptar_y_firmar_archivo_e2ee(ruta_origen: str, ruta_destino: str, clave_publica_destinatario, clave_privada_emisor):
    """
    Encripta un archivo completo para el destinatario (E2EE híbrido) y firma digitalmente
    el archivo cifrado resultante usando la clave privada del emisor.
    Escribe el paquete final binario: [firma (256 bytes)] + [paquete_cifrado]
    """
    # 1. Encriptar el archivo en la ruta de destino
    encriptar_archivo_e2ee(ruta_origen, ruta_destino, clave_publica_destinatario)
    
    # 2. Leer los datos cifrados recién generados
    with open(ruta_destino, 'rb') as f:
        datos_cifrados = f.read()
        
    # 3. Firmar los datos cifrados (Encrypt-then-Sign)
    hash_bytes = hashes.Hash(hashes.SHA256())
    hash_bytes.update(datos_cifrados)
    digest = hash_bytes.finalize()
    
    firma = clave_privada_emisor.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(hashes.SHA256())
    )
    
    # 4. Escribir el archivo final combinando firma y datos cifrados
    with open(ruta_destino, 'wb') as f:
        f.write(firma + datos_cifrados)

def desencriptar_y_verificar_archivo_e2ee(ruta_origen: str, ruta_destino: str, clave_privada_destinatario, clave_publica_emisor) -> bool:
    """
    Descifra un archivo y valida si la firma digital del emisor es legítima.
    Escribe el archivo desencriptado resultante en la ruta de destino.
    Retorna True si la firma es válida, False en caso contrario (aun si la firma es inválida, el archivo se descifra).
    """
    with open(ruta_origen, 'rb') as f:
        paquete_final = f.read()
        
    tamanio_firma = 256 # Firma RSA-2048
    
    # 1. Extraer componentes
    firma = paquete_final[:tamanio_firma]
    paquete_cifrado_bytes = paquete_final[tamanio_firma:]
    
    # 2. Verificar la firma del emisor contra el texto cifrado
    try:
        hash_bytes = hashes.Hash(hashes.SHA256())
        hash_bytes.update(paquete_cifrado_bytes)
        digest = hash_bytes.finalize()
        
        clave_publica_emisor.verify(
            firma,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
        firma_valida = True
    except Exception:
        firma_valida = False
        
    # 3. Descifrar el paquete cifrado
    tamanio_rsa_key = 256
    tamanio_nonce = 12
    
    clave_aes_encriptada = paquete_cifrado_bytes[:tamanio_rsa_key]
    nonce = paquete_cifrado_bytes[tamanio_rsa_key : tamanio_rsa_key + tamanio_nonce]
    datos_cifrados = paquete_cifrado_bytes[tamanio_rsa_key + tamanio_nonce:]
    
    clave_aes = clave_privada_destinatario.decrypt(
        clave_aes_encriptada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    aesgcm = AESGCM(clave_aes)
    datos_comprimidos = aesgcm.decrypt(nonce, datos_cifrados, None)
    datos_originales = zlib.decompress(datos_comprimidos)
    
    with open(ruta_destino, 'wb') as f:
        f.write(datos_originales)
        
    return firma_valida

