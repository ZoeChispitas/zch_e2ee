import os
import zlib
import base64
import tempfile
import zipfile
from cryptography.hazmat.primitives.asymmetric import rsa, padding, x25519, ed25519, utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# =====================================================================
# EXCEPCIONES PERSONALIZADAS
# =====================================================================

class CriptoError(Exception):
    """Excepción base para todos los errores en zch-e2ee."""
    pass

class ErrorDescifrado(CriptoError):
    """Se lanza cuando falla el descifrado (clave incorrecta, datos corruptos, etc.)."""
    pass

class ErrorFirma(CriptoError):
    """Se lanza cuando la verificación de firma digital falla."""
    pass

class ErrorClave(CriptoError):
    """Se lanza cuando una clave es inválida o no se puede cargar."""
    pass

# =====================================================================
# AUXILIARES INTERNOS
# =====================================================================

def _obtener_huella_publica(clave_publica) -> bytes:
    """
    Calcula una huella digital SHA-256 de 8 bytes de una clave pública (RSA o X25519).
    """
    try:
        if isinstance(clave_publica, rsa.RSAPublicKey):
            pem = clave_publica.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        elif isinstance(clave_publica, x25519.X25519PublicKey):
            pem = clave_publica.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        else:
            raise ErrorClave("Clave pública no soportada (debe ser RSA o X25519).")
        
        digest = hashes.Hash(hashes.SHA256())
        digest.update(pem)
        return digest.finalize()[:8]
    except Exception as e:
        if isinstance(e, CriptoError):
            raise
        raise ErrorClave(f"Error al calcular la huella de clave pública: {e}")

# =====================================================================
# APARTADO RSA: LLAVES, SERIALIZACIÓN Y HIGH-LEVEL E2EE
# =====================================================================

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
    try:
        pem = clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem.decode('utf-8')
    except Exception as e:
        raise ErrorClave(f"Error al serializar llave privada RSA: {e}")

def serializar_llave_publica(clave_publica) -> str:
    """
    Convierte la llave pública en formato PEM (texto).
    """
    try:
        pem = clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    except Exception as e:
        raise ErrorClave(f"Error al serializar llave pública RSA: {e}")

def cargar_llave_privada(pem_str: str):
    """
    Carga una llave privada desde su representación en texto PEM.
    """
    try:
        return serialization.load_pem_private_key(
            pem_str.encode('utf-8'),
            password=None
        )
    except Exception as e:
        raise ErrorClave(f"No se pudo cargar la llave privada: {e}")

def cargar_llave_publica(pem_str: str):
    """
    Carga una llave pública desde su representación en texto PEM.
    """
    try:
        return serialization.load_pem_public_key(
            pem_str.encode('utf-8')
        )
    except Exception as e:
        raise ErrorClave(f"No se pudo cargar la llave pública: {e}")

def encriptar_e2ee(mensaje: str, clave_publica_destinatario) -> str:
    """
    Encripta un mensaje de texto para un destinatario usando su llave pública RSA.
    Usa encriptación híbrida (AES-GCM de 256 bits + RSA-OAEP con SHA-256).
    Retorna un string codificado en Base64 con el payload cifrado.
    """
    try:
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
    except Exception as e:
        raise CriptoError(f"Error al encriptar E2EE: {e}")

def desencriptar_e2ee(payload_b64: str, clave_privada_destinatario) -> str:
    """
    Desencripta un mensaje cifrado usando la llave privada RSA del destinatario.
    """
    try:
        # 1. Decodificar el paquete desde Base64
        paquete_cifrado = base64.b64decode(payload_b64.encode('utf-8'))

        # Calcular el tamano de la clave RSA dinamicamente (key_size // 8)
        tamanio_rsa_key = clave_privada_destinatario.key_size // 8
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
    except Exception as e:
        raise ErrorDescifrado(f"Fallo al desencriptar el mensaje E2EE: {e}")

def firmar_mensaje(mensaje: str, clave_privada_emisor) -> str:
    """
    Firma digitalmente un mensaje de texto usando la llave privada del emisor.
    Retorna la firma codificada en Base64.
    """
    try:
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
    except Exception as e:
        raise CriptoError(f"Error al firmar mensaje: {e}")

def verificar_firma(mensaje: str, firma_b64: str, clave_publica_emisor) -> bool:
    """
    Verifica la autenticidad de un mensaje usando su firma digital y la llave pública del emisor.
    Retorna True si la firma es válida, False en caso contrario.
    """
    datos_mensaje = mensaje.encode('utf-8')
    try:
        firma = base64.b64decode(firma_b64.encode('utf-8'))
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
    try:
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
    except Exception as e:
        raise ErrorClave(f"Error al guardar llave privada RSA en archivo: {e}")

def guardar_llave_publica_en_archivo(clave_publica, ruta_archivo: str):
    """
    Guarda una llave pública en un archivo PEM.
    """
    try:
        pem = clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(ruta_archivo, 'wb') as f:
            f.write(pem)
    except Exception as e:
        raise ErrorClave(f"Error al guardar llave pública RSA en archivo: {e}")

def cargar_llave_privada_desde_archivo(ruta_archivo: str, password: str = None):
    """
    Carga una llave privada desde un archivo PEM. 
    Requiere la contraseña si el archivo fue cifrado.
    """
    try:
        with open(ruta_archivo, 'rb') as f:
            pem_data = f.read()
        return serialization.load_pem_private_key(
            pem_data,
            password=password.encode('utf-8') if password else None
        )
    except Exception as e:
        raise ErrorClave(f"No se pudo cargar la llave privada desde archivo: {e}")

def cargar_llave_publica_desde_archivo(ruta_archivo: str):
    """
    Carga una llave pública desde un archivo PEM.
    """
    try:
        with open(ruta_archivo, 'rb') as f:
            pem_data = f.read()
        return serialization.load_pem_public_key(pem_data)
    except Exception as e:
        raise ErrorClave(f"No se pudo cargar la llave pública desde archivo: {e}")

# =====================================================================
# APARTADO RSA COMPONENTES DE ARCHIVOS (CON CABECERA V2)
# =====================================================================

def encriptar_archivo_e2ee(ruta_origen: str, ruta_destino: str, clave_publica_destinatario):
    """
    Encripta un archivo completo (de cualquier tipo) para un destinatario usando su llave publica.
    Guarda el archivo resultante en formato binario cifrado con cabecera ZCH v2 (Modo 0x01).
    """
    try:
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
        
        # Escribir el paquete binario v2: [ZCH\x02\x01] + [clave_aes_encriptada] + [nonce] + [datos_cifrados]
        cabecera = b"ZCH\x02\x01"
        with open(ruta_destino, 'wb') as f:
            f.write(cabecera + clave_aes_encriptada + nonce + datos_cifrados)
    except Exception as e:
        raise CriptoError(f"Error al encriptar archivo: {e}")

def desencriptar_archivo_e2ee(ruta_origen: str, ruta_destino: str, clave_privada_destinatario):
    """
    Desencripta un archivo cifrado con E2EE usando la llave privada del destinatario.
    Guarda el archivo descifrado en la ruta de destino. Soporta cabecera ZCH v2 y formato legacy.
    """
    try:
        with open(ruta_origen, 'rb') as f:
            paquete = f.read()
            
        tamanio_rsa_key = clave_privada_destinatario.key_size // 8
        tamanio_nonce = 12
        
        if paquete.startswith(b"ZCH\x02"):
            modo = paquete[4]
            if modo != 0x01:
                raise ErrorClave(f"Modo de cifrado inesperado en archivo: {modo}")
            # Extraer componentes del paquete binario v2 (saltarse cabecera de 5 bytes)
            clave_aes_encriptada = paquete[5 : 5 + tamanio_rsa_key]
            nonce = paquete[5 + tamanio_rsa_key : 5 + tamanio_rsa_key + tamanio_nonce]
            datos_cifrados = paquete[5 + tamanio_rsa_key + tamanio_nonce:]
        else:
            # Formato legacy (v1)
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
    except Exception as e:
        if isinstance(e, CriptoError):
            raise
        raise ErrorDescifrado(f"Fallo al desencriptar el archivo: {e}")

# =====================================================================
# APARTADO CURVAS ELÍPTICAS (ECDH, X25519, Ed25519)
# =====================================================================

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
    try:
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
    except Exception as e:
        raise CriptoError(f"Error al derivar clave compartida: {e}")

# ----------------- ED25519 FIRMAS Y VERIFICACIÓN -----------------

def generar_llaves_ed25519():
    """
    Genera un par de llaves Ed25519 (privada y pública) para firmas digitales.
    """
    clave_privada = ed25519.Ed25519PrivateKey.generate()
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica

def firmar_mensaje_ed25519(mensaje: str, clave_privada_emisor) -> str:
    """
    Firma digitalmente un mensaje de texto usando la llave privada Ed25519.
    Retorna la firma codificada en Base64.
    """
    try:
        datos_mensaje = mensaje.encode('utf-8')
        firma = clave_privada_emisor.sign(datos_mensaje)
        return base64.b64encode(firma).decode('utf-8')
    except Exception as e:
        raise CriptoError(f"Error al firmar mensaje con Ed25519: {e}")

def verificar_firma_ed25519(mensaje: str, firma_b64: str, clave_publica_emisor) -> bool:
    """
    Verifica la firma Ed25519 de un mensaje usando la pública del emisor.
    Retorna True si es válida, False en caso contrario.
    """
    try:
        datos_mensaje = mensaje.encode('utf-8')
        firma = base64.b64decode(firma_b64.encode('utf-8'))
        clave_publica_emisor.verify(firma, datos_mensaje)
        return True
    except Exception:
        return False

# ----------------- SERIALIZACIÓN DE LLAVES EC -----------------

def serializar_llave_privada_ec(clave_privada, password: str = None) -> str:
    """
    Serializa una llave privada EC (X25519 o Ed25519) en formato PEM (texto).
    """
    try:
        if password:
            algoritmo_cifrado = serialization.BestAvailableEncryption(password.encode('utf-8'))
        else:
            algoritmo_cifrado = serialization.NoEncryption()
        pem = clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=algoritmo_cifrado
        )
        return pem.decode('utf-8')
    except Exception as e:
        raise ErrorClave(f"Error al serializar llave privada EC: {e}")

def serializar_llave_publica_ec(clave_publica) -> str:
    """
    Serializa una llave pública EC (X25519 o Ed25519) en formato PEM (texto).
    """
    try:
        pem = clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    except Exception as e:
        raise ErrorClave(f"Error al serializar llave pública EC: {e}")

def cargar_llave_privada_ec(pem_str: str, password: str = None):
    """
    Carga una llave privada EC (X25519 o Ed25519) desde su representación PEM.
    """
    try:
        return serialization.load_pem_private_key(
            pem_str.encode('utf-8'),
            password=password.encode('utf-8') if password else None
        )
    except Exception as e:
        raise ErrorClave(f"Error al cargar llave privada EC: {e}")

def cargar_llave_publica_ec(pem_str: str):
    """
    Carga una llave pública EC (X25519 o Ed25519) desde su representación PEM.
    """
    try:
        return serialization.load_pem_public_key(
            pem_str.encode('utf-8')
        )
    except Exception as e:
        raise ErrorClave(f"Error al cargar llave pública EC: {e}")

def guardar_llave_privada_ec_en_archivo(clave_privada, ruta_archivo: str, password: str = None):
    """
    Guarda una llave privada EC en un archivo PEM.
    """
    try:
        pem = serializar_llave_privada_ec(clave_privada, password)
        with open(ruta_archivo, 'w', encoding='utf-8') as f:
            f.write(pem)
    except Exception as e:
        raise ErrorClave(f"Error al guardar llave privada EC en archivo: {e}")

def guardar_llave_publica_ec_en_archivo(clave_publica, ruta_archivo: str):
    """
    Guarda una llave pública EC en un archivo PEM.
    """
    try:
        pem = serializar_llave_publica_ec(clave_publica)
        with open(ruta_archivo, 'w', encoding='utf-8') as f:
            f.write(pem)
    except Exception as e:
        raise ErrorClave(f"Error al guardar llave pública EC en archivo: {e}")

def cargar_llave_privada_ec_desde_archivo(ruta_archivo: str, password: str = None):
    """
    Carga una llave privada EC desde un archivo PEM.
    """
    try:
        with open(ruta_archivo, 'r', encoding='utf-8') as f:
            pem_str = f.read()
        return cargar_llave_privada_ec(pem_str, password)
    except Exception as e:
        raise ErrorClave(f"Error al cargar llave privada EC desde archivo: {e}")

def cargar_llave_publica_ec_desde_archivo(ruta_archivo: str):
    """
    Carga una llave pública EC desde un archivo PEM.
    """
    try:
        with open(ruta_archivo, 'r', encoding='utf-8') as f:
            pem_str = f.read()
        return cargar_llave_publica_ec(pem_str)
    except Exception as e:
        raise ErrorClave(f"Error al cargar llave pública EC desde archivo: {e}")

# ----------------- CIFRADO HÍBRIDO CON CURVAS ELÍPTICAS (EC E2EE) -----------------

def encriptar_e2ee_ec(mensaje: str, clave_publica_destinatario_x25519) -> str:
    """
    Encripta un mensaje usando curvas elípticas (X25519 + AES-GCM).
    Retorna un payload codificado en Base64 con el payload cifrado:
    [pub_bytes_efimera (32)] + [nonce (12)] + [texto_cifrado]
    """
    try:
        # 1. Comprimir mensaje
        datos_mensaje = zlib.compress(mensaje.encode('utf-8'))
        
        # 2. Generar par efímero X25519
        clave_privada_efimera = x25519.X25519PrivateKey.generate()
        clave_publica_efimera = clave_privada_efimera.public_key()
        
        # 3. Derivar clave simétrica compartida
        clave_aes = derivar_clave_compartida(clave_privada_efimera, clave_publica_destinatario_x25519)
        
        # 4. Cifrar con AES-GCM
        aesgcm = AESGCM(clave_aes)
        nonce = os.urandom(12)
        texto_cifrado = aesgcm.encrypt(nonce, datos_mensaje, None)
        
        # 5. Obtener bytes de la pública efímera (32 bytes)
        pub_bytes = clave_publica_efimera.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Paquete: [pub_bytes (32)] + [nonce (12)] + [texto_cifrado]
        paquete = pub_bytes + nonce + texto_cifrado
        return base64.b64encode(paquete).decode('utf-8')
    except Exception as e:
        raise CriptoError(f"Error al cifrar con curvas elípticas: {e}")

def desencriptar_e2ee_ec(payload_b64: str, clave_privada_destinatario_x25519) -> str:
    """
    Desencripta un mensaje cifrado con curvas elípticas (X25519 + AES-GCM).
    """
    try:
        paquete = base64.b64decode(payload_b64.encode('utf-8'))
        
        tamanio_pub = 32
        tamanio_nonce = 12
        
        # Extraer componentes
        pub_bytes = paquete[:tamanio_pub]
        nonce = paquete[tamanio_pub : tamanio_pub + tamanio_nonce]
        texto_cifrado = paquete[tamanio_pub + tamanio_nonce:]
        
        # Reconstruir la pública efímera
        clave_publica_efimera = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
        
        # Derivar la clave simétrica compartida
        clave_aes = derivar_clave_compartida(clave_privada_destinatario_x25519, clave_publica_efimera)
        
        # Descifrar y descomprimir
        aesgcm = AESGCM(clave_aes)
        datos_comprimidos = aesgcm.decrypt(nonce, texto_cifrado, None)
        datos_originales = zlib.decompress(datos_comprimidos)
        
        return datos_originales.decode('utf-8')
    except Exception as e:
        raise ErrorDescifrado(f"Fallo al desencriptar con curvas elípticas: {e}")

def encriptar_y_firmar_e2ee_ec(mensaje: str, clave_publica_destinatario_x25519, clave_privada_emisor_ed25519) -> str:
    """
    Cifra el mensaje para el destinatario (EC E2EE) y firma el resultado
    con la clave privada Ed25519 del emisor.
    Retorna el paquete completo (firma + mensaje cifrado) en Base64.
    """
    try:
        # 1. Cifrar usando la funcion base (genera un string base64)
        payload_cifrado_b64 = encriptar_e2ee_ec(mensaje, clave_publica_destinatario_x25519)
        paquete_cifrado_bytes = base64.b64decode(payload_cifrado_b64.encode('utf-8'))
        
        # 2. Firmar los bytes cifrados con la privada del emisor Ed25519
        firma = clave_privada_emisor_ed25519.sign(paquete_cifrado_bytes)
        
        # 3. Empaquetar: [firma (64 bytes)] + [mensaje_cifrado_bytes]
        paquete_final = firma + paquete_cifrado_bytes
        return base64.b64encode(paquete_final).decode('utf-8')
    except Exception as e:
        raise CriptoError(f"Error al cifrar y firmar con curvas elípticas: {e}")

def desencriptar_y_verificar_e2ee_ec(payload_b64: str, clave_privada_destinatario_x25519, clave_publica_emisor_ed25519) -> tuple[str, bool]:
    """
    Descifra un mensaje y verifica si la firma Ed25519 del emisor es valida.
    Retorna una tupla: (mensaje_desencriptado, firma_es_valida).
    """
    try:
        paquete_final = base64.b64decode(payload_b64.encode('utf-8'))
        
        tamanio_firma = 64
        
        # 1. Extraer firma y paquete cifrado
        firma = paquete_final[:tamanio_firma]
        paquete_cifrado_bytes = paquete_final[tamanio_firma:]
        
        # 2. Verificar la firma del emisor contra el texto cifrado
        try:
            clave_publica_emisor_ed25519.verify(firma, paquete_cifrado_bytes)
            firma_valida = True
        except Exception:
            firma_valida = False
            
        # 3. Descifrar el mensaje
        payload_cifrado_b64 = base64.b64encode(paquete_cifrado_bytes).decode('utf-8')
        mensaje = desencriptar_e2ee_ec(payload_cifrado_b64, clave_privada_destinatario_x25519)
        
        return mensaje, firma_valida
    except Exception as e:
        if isinstance(e, CriptoError):
            raise
        raise ErrorDescifrado(f"Fallo al desencriptar y verificar con curvas elípticas: {e}")

# ----------------- ARCHIVOS Y DIRECTORIOS CON CURVAS ELÍPTICAS -----------------

def encriptar_archivo_e2ee_ec(ruta_origen: str, ruta_destino: str, clave_publica_destinatario_x25519):
    """
    Encripta un archivo usando curvas elípticas (X25519 + AES-GCM).
    Guarda el archivo resultante con cabecera ZCH v2 (Modo 0x04).
    """
    try:
        with open(ruta_origen, 'rb') as f:
            datos = f.read()
            
        datos_comprimidos = zlib.compress(datos)
        
        clave_privada_efimera = x25519.X25519PrivateKey.generate()
        clave_publica_efimera = clave_privada_efimera.public_key()
        
        clave_aes = derivar_clave_compartida(clave_privada_efimera, clave_publica_destinatario_x25519)
        
        aesgcm = AESGCM(clave_aes)
        nonce = os.urandom(12)
        datos_cifrados = aesgcm.encrypt(nonce, datos_comprimidos, None)
        
        pub_bytes = clave_publica_efimera.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        cabecera = b"ZCH\x02\x04"
        with open(ruta_destino, 'wb') as f:
            f.write(cabecera + pub_bytes + nonce + datos_cifrados)
    except Exception as e:
        raise CriptoError(f"Error al encriptar archivo con curvas elípticas: {e}")

def desencriptar_archivo_e2ee_ec(ruta_origen: str, ruta_destino: str, clave_privada_destinatario_x25519):
    """
    Desencripta un archivo cifrado con curvas elípticas (X25519 + AES-GCM).
    """
    try:
        with open(ruta_origen, 'rb') as f:
            paquete = f.read()
            
        tamanio_pub = 32
        tamanio_nonce = 12
        
        if not paquete.startswith(b"ZCH\x02"):
            raise ErrorDescifrado("El archivo no contiene la cabecera válida ZCH v2.")
            
        modo = paquete[4]
        if modo != 0x04:
            raise ErrorClave(f"Modo de cifrado inesperado en archivo: {modo}")
            
        pub_bytes = paquete[5 : 5 + tamanio_pub]
        nonce = paquete[5 + tamanio_pub : 5 + tamanio_pub + tamanio_nonce]
        datos_cifrados = paquete[5 + tamanio_pub + tamanio_nonce:]
        
        clave_publica_efimera = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
        clave_aes = derivar_clave_compartida(clave_privada_destinatario_x25519, clave_publica_efimera)
        
        aesgcm = AESGCM(clave_aes)
        datos_comprimidos = aesgcm.decrypt(nonce, datos_cifrados, None)
        datos_originales = zlib.decompress(datos_comprimidos)
        
        with open(ruta_destino, 'wb') as f:
            f.write(datos_originales)
    except Exception as e:
        if isinstance(e, CriptoError):
            raise
        raise ErrorDescifrado(f"Fallo al descifrar archivo con curvas elípticas: {e}")

def encriptar_y_firmar_archivo_e2ee_ec(ruta_origen: str, ruta_destino: str, clave_publica_destinatario_x25519, clave_privada_emisor_ed25519):
    """
    Encripta un archivo usando curvas elípticas (X25519) y lo firma digitalmente con Ed25519.
    Guarda el archivo resultante con cabecera ZCH v2 (Modo 0x05).
    """
    try:
        with open(ruta_origen, 'rb') as f:
            datos = f.read()
            
        datos_comprimidos = zlib.compress(datos)
        
        clave_privada_efimera = x25519.X25519PrivateKey.generate()
        clave_publica_efimera = clave_privada_efimera.public_key()
        
        clave_aes = derivar_clave_compartida(clave_privada_efimera, clave_publica_destinatario_x25519)
        
        aesgcm = AESGCM(clave_aes)
        nonce = os.urandom(12)
        datos_cifrados = aesgcm.encrypt(nonce, datos_comprimidos, None)
        
        pub_bytes = clave_publica_efimera.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        paquete_cifrado = pub_bytes + nonce + datos_cifrados
        
        # Firmar con Ed25519
        firma = clave_privada_emisor_ed25519.sign(paquete_cifrado)
        
        cabecera = b"ZCH\x02\x05"
        with open(ruta_destino, 'wb') as f:
            f.write(cabecera + firma + paquete_cifrado)
    except Exception as e:
        raise CriptoError(f"Error al encriptar y firmar archivo con curvas elípticas: {e}")

def desencriptar_y_verificar_archivo_e2ee_ec(ruta_origen: str, ruta_destino: str, clave_privada_destinatario_x25519, clave_publica_emisor_ed25519) -> bool:
    """
    Descifra un archivo cifrado con curvas elípticas (X25519) y verifica la firma Ed25519.
    Retorna True si la firma es válida, False en caso contrario.
    """
    try:
        with open(ruta_origen, 'rb') as f:
            paquete_final = f.read()
            
        tamanio_firma = 64
        tamanio_pub = 32
        tamanio_nonce = 12
        
        if not paquete_final.startswith(b"ZCH\x02"):
            raise ErrorDescifrado("El archivo no contiene la cabecera válida ZCH v2.")
            
        modo = paquete_final[4]
        if modo != 0x05:
            raise ErrorClave(f"Modo de cifrado inesperado en archivo: {modo}")
            
        firma = paquete_final[5 : 5 + tamanio_firma]
        paquete_cifrado = paquete_final[5 + tamanio_firma:]
        
        # Verificar la firma Ed25519
        try:
            clave_publica_emisor_ed25519.verify(firma, paquete_cifrado)
            firma_valida = True
        except Exception:
            firma_valida = False
            
        # Descifrar
        pub_bytes = paquete_cifrado[:tamanio_pub]
        nonce = paquete_cifrado[tamanio_pub : tamanio_pub + tamanio_nonce]
        datos_cifrados = paquete_cifrado[tamanio_pub + tamanio_nonce:]
        
        clave_publica_efimera = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
        clave_aes = derivar_clave_compartida(clave_privada_destinatario_x25519, clave_publica_efimera)
        
        aesgcm = AESGCM(clave_aes)
        datos_comprimidos = aesgcm.decrypt(nonce, datos_cifrados, None)
        datos_originales = zlib.decompress(datos_comprimidos)
        
        with open(ruta_destino, 'wb') as f:
            f.write(datos_originales)
            
        return firma_valida
    except Exception as e:
        if isinstance(e, CriptoError):
            raise
        raise ErrorDescifrado(f"Fallo al descifrar y verificar archivo con curvas elípticas: {e}")

def encriptar_directorio_e2ee_ec(ruta_directorio: str, ruta_destino: str, clave_publica_destinatario_x25519):
    """
    Comprime un directorio completo en un archivo temporal ZIP y luego lo cifra
    usando la llave pública del destinatario X25519.
    """
    temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
    ruta_temp_zip = temp_zip.name
    temp_zip.close()
    
    try:
        with zipfile.ZipFile(ruta_temp_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for raiz, _, archivos in os.walk(ruta_directorio):
                for archivo in archivos:
                    ruta_completa = os.path.join(raiz, archivo)
                    ruta_relativa = os.path.relpath(ruta_completa, ruta_directorio)
                    zipf.write(ruta_completa, arcname=ruta_relativa)
                    
        encriptar_archivo_e2ee_ec(ruta_temp_zip, ruta_destino, clave_publica_destinatario_x25519)
    finally:
        if os.path.exists(ruta_temp_zip):
            os.remove(ruta_temp_zip)

def desencriptar_directorio_e2ee_ec(ruta_origen: str, ruta_directorio_destino: str, clave_privada_destinatario_x25519):
    """
    Descifra un paquete cifrado con la llave privada del destinatario X25519,
    obtiene el archivo ZIP temporal y lo descomprime en la carpeta de destino.
    """
    temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
    ruta_temp_zip = temp_zip.name
    temp_zip.close()
    
    try:
        desencriptar_archivo_e2ee_ec(ruta_origen, ruta_temp_zip, clave_privada_destinatario_x25519)
        os.makedirs(ruta_directorio_destino, exist_ok=True)
        with zipfile.ZipFile(ruta_temp_zip, 'r') as zipf:
            zipf.extractall(ruta_directorio_destino)
    finally:
        if os.path.exists(ruta_temp_zip):
            os.remove(ruta_temp_zip)

# =====================================================================
# NOVEDADES V0.9.0: CIFRADO MULTI-DESTINATARIO (RSA / X25519)
# =====================================================================

def encriptar_e2ee_multi(mensaje: str, claves_publicas: list) -> str:
    """
    Cifra un mensaje de texto para múltiples destinatarios (RSA o X25519).
    Retorna un payload Base64 con la clave simétrica cifrada para cada destinatario.
    """
    try:
        if not claves_publicas:
            raise ErrorClave("Se requiere al menos una clave pública para encriptar.")
            
        datos_mensaje = zlib.compress(mensaje.encode('utf-8'))
        clave_aes = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(clave_aes)
        nonce = os.urandom(12)
        texto_cifrado = aesgcm.encrypt(nonce, datos_mensaje, None)
        
        primera_clave = claves_publicas[0]
        es_ec = isinstance(primera_clave, x25519.X25519PublicKey)
        
        bloque_claves = bytearray()
        
        # Escribir número de destinatarios (2 bytes)
        bloque_claves.extend(len(claves_publicas).to_bytes(2, byteorder='big'))
        
        # Escribir tipo de claves (1 byte): 0x01 = RSA, 0x02 = EC (X25519)
        tipo_clave = 0x02 if es_ec else 0x01
        bloque_claves.append(tipo_clave)
        
        for pub_key in claves_publicas:
            huella = _obtener_huella_publica(pub_key)
            bloque_claves.extend(huella)
            
            if es_ec:
                priv_efimera = x25519.X25519PrivateKey.generate()
                pub_efimera = priv_efimera.public_key()
                secreto = derivar_clave_compartida(priv_efimera, pub_key)
                
                nonce_ec = os.urandom(12)
                aesgcm_ec = AESGCM(secreto)
                clave_aes_encriptada = aesgcm_ec.encrypt(nonce_ec, clave_aes, None)
                
                pub_efimera_bytes = pub_efimera.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                
                bloque_destinatario = pub_efimera_bytes + nonce_ec + clave_aes_encriptada
                bloque_claves.extend(len(bloque_destinatario).to_bytes(2, byteorder='big'))
                bloque_claves.extend(bloque_destinatario)
            else:
                clave_aes_encriptada = pub_key.encrypt(
                    clave_aes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                bloque_claves.extend(len(clave_aes_encriptada).to_bytes(2, byteorder='big'))
                bloque_claves.extend(clave_aes_encriptada)
                
        paquete_completo = bytes(bloque_claves) + nonce + texto_cifrado
        return base64.b64encode(paquete_completo).decode('utf-8')
    except Exception as e:
        if isinstance(e, CriptoError):
            raise
        raise CriptoError(f"Error al encriptar multi-destinatario: {e}")

def desencriptar_e2ee_multi(payload_b64: str, clave_privada_destinatario) -> str:
    """
    Descifra un mensaje cifrado para múltiples destinatarios usando la clave privada correspondiente.
    """
    try:
        paquete = base64.b64decode(payload_b64.encode('utf-8'))
        
        num_dest = int.from_bytes(paquete[:2], byteorder='big')
        tipo_clave = paquete[2]
        
        clave_publica_propia = clave_privada_destinatario.public_key()
        huella_propia = _obtener_huella_publica(clave_publica_propia)
        
        offset = 3
        clave_aes = None
        
        for _ in range(num_dest):
            huella_recip = paquete[offset : offset + 8]
            offset += 8
            
            tamanio_bloque = int.from_bytes(paquete[offset : offset + 2], byteorder='big')
            offset += 2
            
            bloque_datos = paquete[offset : offset + tamanio_bloque]
            offset += tamanio_bloque
            
            if huella_recip == huella_propia:
                if tipo_clave == 0x02:
                    pub_efimera_bytes = bloque_datos[:32]
                    nonce_ec = bloque_datos[32 : 32 + 12]
                    clave_aes_encriptada = bloque_datos[32 + 12:]
                    
                    pub_efimera = x25519.X25519PublicKey.from_public_bytes(pub_efimera_bytes)
                    secreto = derivar_clave_compartida(clave_privada_destinatario, pub_efimera)
                    
                    aesgcm_ec = AESGCM(secreto)
                    clave_aes = aesgcm_ec.decrypt(nonce_ec, clave_aes_encriptada, None)
                else:
                    clave_aes = clave_privada_destinatario.decrypt(
                        bloque_datos,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
        
        if clave_aes is None:
            raise ErrorDescifrado("La clave privada proporcionada no pertenece a ningún destinatario de este mensaje.")
            
        nonce = paquete[offset : offset + 12]
        texto_cifrado = paquete[offset + 12:]
        
        aesgcm = AESGCM(clave_aes)
        datos_comprimidos = aesgcm.decrypt(nonce, texto_cifrado, None)
        datos_mensaje = zlib.decompress(datos_comprimidos)
        return datos_mensaje.decode('utf-8')
    except Exception as e:
        if isinstance(e, CriptoError):
            raise
        raise ErrorDescifrado(f"Fallo al desencriptar el mensaje multi-destinatario: {e}")

def encriptar_archivo_e2ee_multi(ruta_origen: str, ruta_destino: str, claves_publicas: list):
    """
    Encripta un archivo completo para múltiples destinatarios (RSA o X25519).
    Guarda el archivo resultante con cabecera ZCH v2 (Modo 0x06 para RSA, Modo 0x07 para EC).
    """
    try:
        if not claves_publicas:
            raise ErrorClave("Se requiere al menos una clave pública para encriptar.")
            
        with open(ruta_origen, 'rb') as f:
            datos = f.read()
            
        datos_comprimidos = zlib.compress(datos)
        clave_aes = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(clave_aes)
        nonce = os.urandom(12)
        datos_cifrados = aesgcm.encrypt(nonce, datos_comprimidos, None)
        
        primera_clave = claves_publicas[0]
        es_ec = isinstance(primera_clave, x25519.X25519PublicKey)
        
        bloque_claves = bytearray()
        bloque_claves.extend(len(claves_publicas).to_bytes(2, byteorder='big'))
        
        tipo_clave = 0x02 if es_ec else 0x01
        bloque_claves.append(tipo_clave)
        
        for pub_key in claves_publicas:
            huella = _obtener_huella_publica(pub_key)
            bloque_claves.extend(huella)
            
            if es_ec:
                priv_efimera = x25519.X25519PrivateKey.generate()
                pub_efimera = priv_efimera.public_key()
                secreto = derivar_clave_compartida(priv_efimera, pub_key)
                
                nonce_ec = os.urandom(12)
                aesgcm_ec = AESGCM(secreto)
                clave_aes_encriptada = aesgcm_ec.encrypt(nonce_ec, clave_aes, None)
                
                pub_efimera_bytes = pub_efimera.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                
                bloque_destinatario = pub_efimera_bytes + nonce_ec + clave_aes_encriptada
                bloque_claves.extend(len(bloque_destinatario).to_bytes(2, byteorder='big'))
                bloque_claves.extend(bloque_destinatario)
            else:
                clave_aes_encriptada = pub_key.encrypt(
                    clave_aes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                bloque_claves.extend(len(clave_aes_encriptada).to_bytes(2, byteorder='big'))
                bloque_claves.extend(clave_aes_encriptada)
                
        modo = b"\x07" if es_ec else b"\x06"
        cabecera = b"ZCH\x02" + modo
        
        with open(ruta_destino, 'wb') as f:
            f.write(cabecera + bytes(bloque_claves) + nonce + datos_cifrados)
    except Exception as e:
        raise CriptoError(f"Error al encriptar archivo multi-destinatario: {e}")

def desencriptar_archivo_e2ee_multi(ruta_origen: str, ruta_destino: str, clave_privada_destinatario):
    """
    Desencripta un archivo cifrado para múltiples destinatarios usando la clave privada correspondiente.
    """
    try:
        with open(ruta_origen, 'rb') as f:
            paquete_final = f.read()
            
        if not paquete_final.startswith(b"ZCH\x02"):
            raise ErrorDescifrado("El archivo no contiene la cabecera válida ZCH v2.")
            
        modo = paquete_final[4]
        if modo not in (0x06, 0x07):
            raise ErrorClave(f"Modo de cifrado inesperado en archivo multi-destinatario: {modo}")
            
        paquete = paquete_final[5:]
        
        num_dest = int.from_bytes(paquete[:2], byteorder='big')
        tipo_clave = paquete[2]
        
        clave_publica_propia = clave_privada_destinatario.public_key()
        huella_propia = _obtener_huella_publica(clave_publica_propia)
        
        offset = 3
        clave_aes = None
        
        for _ in range(num_dest):
            huella_recip = paquete[offset : offset + 8]
            offset += 8
            
            tamanio_bloque = int.from_bytes(paquete[offset : offset + 2], byteorder='big')
            offset += 2
            
            bloque_datos = paquete[offset : offset + tamanio_bloque]
            offset += tamanio_bloque
            
            if huella_recip == huella_propia:
                if tipo_clave == 0x02:
                    pub_efimera_bytes = bloque_datos[:32]
                    nonce_ec = bloque_datos[32 : 32 + 12]
                    clave_aes_encriptada = bloque_datos[32 + 12:]
                    
                    pub_efimera = x25519.X25519PublicKey.from_public_bytes(pub_efimera_bytes)
                    secreto = derivar_clave_compartida(clave_privada_destinatario, pub_efimera)
                    
                    aesgcm_ec = AESGCM(secreto)
                    clave_aes = aesgcm_ec.decrypt(nonce_ec, clave_aes_encriptada, None)
                else:
                    clave_aes = clave_privada_destinatario.decrypt(
                        bloque_datos,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
        
        if clave_aes is None:
            raise ErrorDescifrado("La clave privada proporcionada no pertenece a ningún destinatario de este archivo.")
            
        nonce = paquete[offset : offset + 12]
        datos_cifrados = paquete[offset + 12:]
        
        aesgcm = AESGCM(clave_aes)
        datos_comprimidos = aesgcm.decrypt(nonce, datos_cifrados, None)
        datos_originales = zlib.decompress(datos_comprimidos)
        
        with open(ruta_destino, 'wb') as f:
            f.write(datos_originales)
    except Exception as e:
        if isinstance(e, CriptoError):
            raise
        raise ErrorDescifrado(f"Fallo al descifrar archivo multi-destinatario: {e}")

# =====================================================================
# APARTADO CONTRASEÑA TRADICIONAL (SIMÉTRICA - SCRYPT + AES-GCM)
# =====================================================================

def encriptar_con_password(mensaje: str, password: str) -> str:
    """
    Cifra un mensaje de texto usando una contraseña tradicional (cifrado simétrico).
    Deriva la clave de 256 bits usando Scrypt, y cifra con AES-GCM.
    Retorna un payload codificado en Base64.
    """
    try:
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
    except Exception as e:
        raise CriptoError(f"Error al encriptar con contraseña: {e}")

def desencriptar_con_password(payload_b64: str, password: str) -> str:
    """
    Descifra un mensaje cifrado con contraseña usando Scrypt y AES-GCM.
    """
    try:
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
    except Exception as e:
        raise ErrorDescifrado(f"Fallo al desencriptar el mensaje con contraseña: {e}")

def encriptar_y_firmar_e2ee(mensaje: str, clave_publica_destinatario, clave_privada_emisor) -> str:
    """
    Cifra el mensaje para el destinatario (E2EE híbrido) y firma digitalmente
    el resultado con la clave privada del emisor. 
    Retorna el paquete completo (firma + mensaje cifrado) en Base64.
    """
    try:
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
    except Exception as e:
        raise CriptoError(f"Error al cifrar y firmar E2EE: {e}")

def desencriptar_y_verificar_e2ee(payload_b64: str, clave_privada_destinatario, clave_publica_emisor) -> tuple[str, bool]:
    """
    Descifra un mensaje y verifica si la firma del emisor es valida.
    Retorna una tupla: (mensaje_desencriptado, firma_es_valida).
    """
    try:
        paquete_final = base64.b64decode(payload_b64.encode('utf-8'))
        
        tamanio_firma = clave_publica_emisor.key_size // 8
        
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
    except Exception as e:
        if isinstance(e, CriptoError):
            raise
        raise ErrorDescifrado(f"Fallo al desencriptar y verificar E2EE: {e}")

# ----------------- ARCHIVOS Y DIRECTORIOS CON CONTRASEÑA -----------------

def encriptar_archivo_con_password(ruta_origen: str, ruta_destino: str, password: str):
    """
    Encripta un archivo completo de forma simetrica usando una contraseña.
    Aplica compresion zlib, deriva la clave mediante Scrypt y cifra usando AES-GCM.
    Usa el formato con cabecera ZCH v2 (Modo 0x03).
    """
    try:
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
        
        # Escribir el archivo final v2: [ZCH\x02\x03] + [sal (16 bytes)] + [nonce (12 bytes)] + [datos_cifrados]
        cabecera = b"ZCH\x02\x03"
        with open(ruta_destino, 'wb') as f:
            f.write(cabecera + sal + nonce + datos_cifrados)
    except Exception as e:
        raise CriptoError(f"Error al encriptar archivo con contraseña: {e}")

def desencriptar_archivo_con_password(ruta_origen: str, ruta_destino: str, password: str):
    """
    Descifra un archivo cifrado con contraseña usando Scrypt y AES-GCM,
    descomprimiendo los datos para recuperar el archivo original.
    Soporta cabecera ZCH v2 y formato legacy.
    """
    try:
        with open(ruta_origen, 'rb') as f:
            paquete = f.read()
            
        tamanio_sal = 16
        tamanio_nonce = 12
        
        if paquete.startswith(b"ZCH\x02"):
            modo = paquete[4]
            if modo != 0x03:
                raise ErrorClave(f"Modo de cifrado inesperado en archivo: {modo}")
            sal = paquete[5 : 5 + tamanio_sal]
            nonce = paquete[5 + tamanio_sal : 5 + tamanio_sal + tamanio_nonce]
            datos_cifrados = paquete[5 + tamanio_sal + tamanio_nonce:]
        else:
            # Legacy (v1)
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
    except Exception as e:
        if isinstance(e, CriptoError):
            raise
        raise ErrorDescifrado(f"Fallo al desencriptar el archivo con contraseña: {e}")

def encriptar_directorio_con_password(ruta_directorio: str, ruta_destino: str, password: str):
    """
    Comprime un directorio completo en un archivo temporal ZIP y luego lo cifra
    usando una contraseña simétrica.
    """
    temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
    ruta_temp_zip = temp_zip.name
    temp_zip.close()
    
    try:
        with zipfile.ZipFile(ruta_temp_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for raiz, _, archivos in os.walk(ruta_directorio):
                for archivo in archivos:
                    ruta_completa = os.path.join(raiz, archivo)
                    ruta_relativa = os.path.relpath(ruta_completa, ruta_directorio)
                    zipf.write(ruta_completa, arcname=ruta_relativa)
                    
        encriptar_archivo_con_password(ruta_temp_zip, ruta_destino, password)
    finally:
        if os.path.exists(ruta_temp_zip):
            os.remove(ruta_temp_zip)

def desencriptar_directorio_con_password(ruta_origen: str, ruta_directorio_destino: str, password: str):
    """
    Descifra un paquete cifrado con contraseña, obtiene el archivo ZIP temporal
    y lo descomprime en la carpeta de destino.
    """
    temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
    ruta_temp_zip = temp_zip.name
    temp_zip.close()
    
    try:
        desencriptar_archivo_con_password(ruta_origen, ruta_temp_zip, password)
        os.makedirs(ruta_directorio_destino, exist_ok=True)
        with zipfile.ZipFile(ruta_temp_zip, 'r') as zipf:
            zipf.extractall(ruta_directorio_destino)
    finally:
        if os.path.exists(ruta_temp_zip):
            os.remove(ruta_temp_zip)

# =====================================================================
# AUXILIARES DE ARCHIVO, CHECKSUMS Y FIRMAS DE ARCHIVOS COMBINADAS
# =====================================================================

def calcular_sha256(ruta_archivo: str) -> str:
    """
    Calcula el hash SHA-256 de cualquier archivo leyéndolo en bloques de 4KB.
    Retorna el hash en formato hexadecimal.
    """
    try:
        sha256_hash = hashes.Hash(hashes.SHA256())
        with open(ruta_archivo, "rb") as f:
            for bloque_bytes in iter(lambda: f.read(4096), b""):
                sha256_hash.update(bloque_bytes)
        return sha256_hash.finalize().hex()
    except Exception as e:
        raise CriptoError(f"Error al calcular hash SHA-256 de archivo: {e}")

def firmar_archivo(ruta_archivo: str, clave_privada_emisor) -> str:
    """
    Calcula el hash SHA-256 de un archivo y lo firma digitalmente con la clave privada del emisor.
    Retorna la firma codificada en Base64.
    """
    try:
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
    except Exception as e:
        raise CriptoError(f"Error al firmar archivo: {e}")

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
    Escribe el paquete final binario con cabecera ZCH v2 (Modo 0x02).
    """
    try:
        with open(ruta_origen, 'rb') as f:
            datos = f.read()
            
        datos_comprimidos = zlib.compress(datos)
        
        clave_aes = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(clave_aes)
        nonce = os.urandom(12)
        datos_cifrados = aesgcm.encrypt(nonce, datos_comprimidos, None)
        
        clave_aes_encriptada = clave_publica_destinatario.encrypt(
            clave_aes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        paquete_cifrado_sin_firma = clave_aes_encriptada + nonce + datos_cifrados
        
        # Firmar los datos cifrados (Encrypt-then-Sign)
        hash_bytes = hashes.Hash(hashes.SHA256())
        hash_bytes.update(paquete_cifrado_sin_firma)
        digest = hash_bytes.finalize()
        
        firma = clave_privada_emisor.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
        
        # Cabecera v2
        cabecera = b"ZCH\x02\x02"
        with open(ruta_destino, 'wb') as f:
            f.write(cabecera + firma + paquete_cifrado_sin_firma)
    except Exception as e:
        raise CriptoError(f"Error al encriptar y firmar archivo: {e}")

def desencriptar_y_verificar_archivo_e2ee(ruta_origen: str, ruta_destino: str, clave_privada_destinatario, clave_publica_emisor) -> bool:
    """
    Descifra un archivo y valida si la firma digital del emisor es legítima.
    Escribe el archivo desencriptado resultante en la ruta de destino.
    Soporta cabecera ZCH v2 y formato legacy.
    Retorna True si la firma es válida, False en caso contrario.
    """
    try:
        with open(ruta_origen, 'rb') as f:
            paquete_final = f.read()
            
        tamanio_firma = clave_publica_emisor.key_size // 8
        tamanio_rsa_key = clave_privada_destinatario.key_size // 8
        tamanio_nonce = 12
        
        if paquete_final.startswith(b"ZCH\x02"):
            modo = paquete_final[4]
            if modo != 0x02:
                raise ErrorClave(f"Modo de cifrado inesperado en archivo: {modo}")
            firma = paquete_final[5 : 5 + tamanio_firma]
            paquete_cifrado_bytes = paquete_final[5 + tamanio_firma:]
        else:
            # Legacy (v1)
            firma = paquete_final[:tamanio_firma]
            paquete_cifrado_bytes = paquete_final[tamanio_firma:]
            
        # Verificar la firma
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
            
        # Descifrar
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
    except Exception as e:
        if isinstance(e, CriptoError):
            raise
        raise ErrorDescifrado(f"Fallo al desencriptar y verificar el archivo: {e}")

def encriptar_directorio_e2ee(ruta_directorio: str, ruta_destino: str, clave_publica_destinatario):
    """
    Comprime un directorio completo en un archivo temporal ZIP y luego lo cifra
    usando la llave pública del destinatario RSA.
    """
    temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
    ruta_temp_zip = temp_zip.name
    temp_zip.close()
    
    try:
        with zipfile.ZipFile(ruta_temp_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for raiz, _, archivos in os.walk(ruta_directorio):
                for archivo in archivos:
                    ruta_completa = os.path.join(raiz, archivo)
                    ruta_relativa = os.path.relpath(ruta_completa, ruta_directorio)
                    zipf.write(ruta_completa, arcname=ruta_relativa)
                    
        encriptar_archivo_e2ee(ruta_temp_zip, ruta_destino, clave_publica_destinatario)
    finally:
        if os.path.exists(ruta_temp_zip):
            os.remove(ruta_temp_zip)

def desencriptar_directorio_e2ee(ruta_origen: str, ruta_directorio_destino: str, clave_privada_destinatario):
    """
    Descifra un paquete cifrado con la llave privada del destinatario RSA,
    obtiene el archivo ZIP temporal y lo descomprime en la carpeta de destino.
    """
    temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
    ruta_temp_zip = temp_zip.name
    temp_zip.close()
    
    try:
        desencriptar_archivo_e2ee(ruta_origen, ruta_temp_zip, clave_privada_destinatario)
        os.makedirs(ruta_directorio_destino, exist_ok=True)
        with zipfile.ZipFile(ruta_temp_zip, 'r') as zipf:
            zipf.extractall(ruta_directorio_destino)
    finally:
        if os.path.exists(ruta_temp_zip):
            os.remove(ruta_temp_zip)
