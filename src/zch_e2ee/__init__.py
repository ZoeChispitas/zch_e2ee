from .zch_e2ee import (
    # Excepciones
    CriptoError,
    ErrorDescifrado,
    ErrorContrasenaIncorrecta,
    ErrorDatosCorruptos,
    ErrorFirma,
    ErrorClave,
    
    # RSA
    generar_llaves,
    serializar_llave_privada,
    serializar_llave_publica,
    cargar_llave_privada,
    cargar_llave_publica,
    encriptar_e2ee,
    desencriptar_e2ee,
    firmar_mensaje,
    verificar_firma,
    guardar_llave_privada_en_archivo,
    guardar_llave_publica_en_archivo,
    cargar_llave_privada_desde_archivo,
    cargar_llave_publica_desde_archivo,
    encriptar_archivo_e2ee,
    desencriptar_archivo_e2ee,
    encriptar_y_firmar_e2ee,
    desencriptar_y_verificar_e2ee,
    encriptar_y_firmar_archivo_e2ee,
    desencriptar_y_verificar_archivo_e2ee,
    encriptar_directorio_e2ee,
    desencriptar_directorio_e2ee,
    
    # EC (Curvas Elípticas X25519 / Ed25519)
    generar_llaves_ec,
    derivar_clave_compartida,
    generar_llaves_ed25519,
    firmar_mensaje_ed25519,
    verificar_firma_ed25519,
    serializar_llave_privada_ec,
    serializar_llave_publica_ec,
    cargar_llave_privada_ec,
    cargar_llave_publica_ec,
    guardar_llave_privada_ec_en_archivo,
    guardar_llave_publica_ec_en_archivo,
    cargar_llave_privada_ec_desde_archivo,
    cargar_llave_publica_ec_desde_archivo,
    encriptar_e2ee_ec,
    desencriptar_e2ee_ec,
    encriptar_y_firmar_e2ee_ec,
    desencriptar_y_verificar_e2ee_ec,
    encriptar_archivo_e2ee_ec,
    desencriptar_archivo_e2ee_ec,
    encriptar_y_firmar_archivo_e2ee_ec,
    desencriptar_y_verificar_archivo_e2ee_ec,
    encriptar_directorio_e2ee_ec,
    desencriptar_directorio_e2ee_ec,
    
    # Multi-destinatario (RSA / X25519)
    encriptar_e2ee_multi,
    desencriptar_e2ee_multi,
    encriptar_archivo_e2ee_multi,
    desencriptar_archivo_e2ee_multi,
    encriptar_directorio_e2ee_multi,
    desencriptar_directorio_e2ee_multi,
    encriptar_y_firmar_e2ee_multi,
    desencriptar_y_verificar_e2ee_multi,
    encriptar_y_firmar_archivo_e2ee_multi,
    desencriptar_y_verificar_archivo_e2ee_multi,
    encriptar_y_firmar_directorio_e2ee_multi,
    desencriptar_y_verificar_directorio_e2ee_multi,
    
    # Password (Simétrico)
    encriptar_con_password,
    desencriptar_con_password,
    encriptar_archivo_con_password,
    desencriptar_archivo_con_password,
    encriptar_directorio_con_password,
    desencriptar_directorio_con_password,
    
    # Auxiliares
    calcular_sha256,
    firmar_archivo,
    verificar_firma_archivo,
    
    # Criptografía de Umbral (Shamir)
    dividir_secreto_shamir,
    reconstruir_secreto_shamir,
    
    # Llavero Seguro (Keystore)
    KeystoreZCH,
    
    # Autenticación Simétrica (HMAC)
    calcular_hmac,
    verificar_hmac,
    
    # Protocolos (Double Ratchet)
    SesionDoubleRatchet
)

# Importer se expone mediante su propio módulo para evitar imports circulares pesados
from .importer import (
    registrar_importador_cifrado,
    encriptar_modulo_python
)
