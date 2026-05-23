# zch-e2ee

Modulo en Python de encriptacion de extremo a extremo (E2EE) y firmas digitales usando RSA y AES-GCM.

## Instalacion

```bash
pip install zch-e2ee
```

## Uso Basico

```python
import zch_e2ee

# 1. Generar claves
privada, publica = zch_e2ee.generar_llaves()

# 2. Encriptar un mensaje para un destinatario
mensaje_encriptado = zch_e2ee.encriptar_e2ee("Hola mundo", publica)

# 3. Desencriptar el mensaje
mensaje_original = zch_e2ee.desencriptar_e2ee(mensaje_encriptado, privada)
print(mensaje_original) # Hola mundo
```
