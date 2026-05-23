import sys
import os
import importlib.abc
import importlib.machinery
import zch_e2ee

class EncryptedModuleLoader(importlib.abc.SourceLoader):
    """
    Cargador personalizado que lee un archivo .py.enc cifrado,
    lo descifra en memoria usando la contraseña maestra y lo ejecuta como módulo.
    """
    def __init__(self, fullname, path, password):
        self.fullname = fullname
        self.path = path
        self.password = password

    def get_filename(self, fullname):
        return self.path

    def get_data(self, path):
        with open(path, 'rb') as f:
            paquete = f.read()
            
        if not paquete.startswith(b"ZCH\x02"):
            raise zch_e2ee.ErrorDescifrado("El archivo del módulo no contiene la cabecera válida ZCH v2.")
            
        modo = paquete[4]
        if modo != 0x03:
            raise zch_e2ee.ErrorClave(f"Modo de cifrado inesperado en archivo de módulo: {modo}")
            
        tamanio_sal = 16
        tamanio_nonce = 12
        
        sal = paquete[5 : 5 + tamanio_sal]
        nonce = paquete[5 + tamanio_sal : 5 + tamanio_sal + tamanio_nonce]
        kvv = paquete[5 + tamanio_sal + tamanio_nonce : 5 + tamanio_sal + tamanio_nonce + 4]
        datos_cifrados = paquete[5 + tamanio_sal + tamanio_nonce + 4:]
        
        # Derivar clave
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import zlib
        
        kdf = Scrypt(
            salt=sal,
            length=32,
            n=2**14,
            r=8,
            p=1
        )
        clave_aes = kdf.derive(self.password.encode('utf-8'))
        
        # Verificar KVV
        kvv_calculado = zch_e2ee.calcular_hmac(b"verifier", clave_aes)[:4]
        if kvv_calculado != kvv:
            raise zch_e2ee.ErrorContrasenaIncorrecta("La contraseña para descifrar el módulo es incorrecta.")
            
        # Descifrar y descomprimir
        try:
            aesgcm = AESGCM(clave_aes)
            datos_comprimidos = aesgcm.decrypt(nonce, datos_cifrados, None)
            datos_originales = zlib.decompress(datos_comprimidos)
        except Exception as e:
            raise zch_e2ee.ErrorDatosCorruptos(f"El módulo cifrado está dañado o corrupto: {e}")
            
        return datos_originales

class EncryptedModuleFinder(importlib.abc.MetaPathFinder):
    """
    Buscador personalizado que intercepta la importación de módulos y busca
    archivos con extensión .py.enc en la ruta de búsqueda de sys.path.
    """
    def __init__(self, password):
        self.password = password

    def find_spec(self, fullname, path, target=None):
        name = fullname.split(".")[-1]
        paths = path or sys.path
        for p in paths:
            ruta_enc = os.path.join(p, f"{name}.py.enc")
            if os.path.exists(ruta_enc):
                loader = EncryptedModuleLoader(fullname, ruta_enc, self.password)
                return importlib.machinery.ModuleSpec(fullname, loader, origin=ruta_enc)
        return None

def registrar_importador_cifrado(password: str):
    """
    Registra el hook de importación en sys.meta_path para descifrar módulos al vuelo en memoria.
    """
    finder = EncryptedModuleFinder(password)
    sys.meta_path.insert(0, finder)
    return finder

def encriptar_modulo_python(ruta_py: str, ruta_destino_enc: str, password: str):
    """
    Cifra un archivo de código fuente .py y lo guarda como un archivo cifrado .py.enc.
    """
    if not os.path.exists(ruta_py):
        raise FileNotFoundError(f"No se encontró el archivo de origen: {ruta_py}")
    zch_e2ee.encriptar_archivo_con_password(ruta_py, ruta_destino_enc, password)
