# zch-e2ee

[[Read English version]](README_EN.md)

Módulo de Python de alto nivel para encriptación de extremo a extremo (E2EE) y firmas digitales.

## Características principales

*   **Cifrado Asimétrico RSA:** Encriptación híbrida usando RSA-2048 y AES-GCM.
*   **Cifrado Simétrico por Contraseña:** Cifrado fuerte derivando claves con Scrypt + AES-GCM.
*   **Acuerdo de claves elípticas:** Intercambio de claves seguro Diffie-Hellman sobre curvas elípticas (ECDH X25519).
*   **Firmas digitales:** Autenticación y no repudio mediante firmas RSA-PSS.
*   **Compresión automática:** Integración transparente de compresión zlib antes de cifrar.
*   **Cifrado de archivos:** Soporte para encriptar cualquier tipo de archivo usando claves o contraseñas.

## Instalación

```bash
pip install zch-e2ee
```

## Uso Básico

Aquí tienes un ejemplo de cómo cifrar y descifrar un texto usando llaves asimétricas:

```python
import zch_e2ee

# 1. Generar par de llaves criptográficas
privada, publica = zch_e2ee.generar_llaves()

# 2. Cifrar un mensaje para el destinatario
cifrado = zch_e2ee.encriptar_e2ee("Hola, este es un mensaje seguro", publica)

# 3. Descifrar el mensaje recibido
original = zch_e2ee.desencriptar_e2ee(cifrado, privada)
print(original)  # "Hola, este es un mensaje seguro"
```
