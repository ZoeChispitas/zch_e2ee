# Guía: Cómo Publicar tu Módulo en PyPI (`zch-e2ee`)

Para que cualquiera en el mundo pueda instalar tu importador usando `pip install zch-e2ee`, debes subir el código al **Python Package Index (PyPI)**. A continuación, tienes el proceso paso a paso.

---

## Paso 1: Recuperar y Obtener un Nuevo Token en PyPI

Como perdiste tu token anterior, haz esto:
1. Inicia sesión en [pypi.org](https://pypi.org/).
2. Ve a **Account settings** (Configuración de la cuenta).
3. Busca la sección **API tokens** y elimina (*Revoke*) el token viejo que perdiste por seguridad.
4. Haz clic en **Add API token**.
5. Ponle un nombre (ej. "Laptop de Zoe") y selecciona si es para todos los proyectos o uno específico.
6. Haz clic en **Generate token**.
7. **Copia el token generado** (comienza con `pypi-`) y guárdalo temporalmente en un lugar seguro. *¡Solo se mostrará una vez!*

---

## Paso 2: Estructurar los Archivos para Empaquetar

Para empaquetar tu código de forma moderna, se recomienda la estructura estándar de origen (`src/`):

Crea la siguiente estructura de carpetas en tu proyecto:
```text
import_python/
├── pyproject.toml
├── README.md
├── LICENSE
├── src/
│   └── zch_e2ee/
│       ├── __init__.py
│       └── zch_e2ee.py
```

### Contenido de los Archivos Clave:

#### 1. `pyproject.toml`
Define la configuración del paquete, su nombre en PyPI y sus dependencias. Crea este archivo con el siguiente contenido:

```toml
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "zch-e2ee"  # El nombre que la gente usará en: pip install zch-e2ee
version = "0.1.0"
authors = [
  { name="Zoe CH", email="tu-email@correo.com" },
]
description = "Modulo de encriptacion extremo a extremo (E2EE) usando RSA y AES-GCM."
readme = "README.md"
requires-python = ">=3.7"
classifiers = [
    "Programming Language :: Python :: 3",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
]
dependencies = [
    "cryptography>=40.0.0",  # Indica que requiere esta librería para funcionar
]

[tool.setuptools.packages.find]
where = ["src"]
```

#### 2. `src/zch_e2ee/__init__.py`
Este archivo expone las funciones de tu módulo cuando alguien lo importe. Debe contener lo siguiente:

```python
from .zch_e2ee import (
    generar_llaves,
    serializar_llave_privada,
    serializar_llave_publica,
    cargar_llave_privada,
    cargar_llave_publica,
    encriptar_e2ee,
    desencriptar_e2ee,
    firmar_mensaje,
    verificar_firma
)
```

#### 3. `src/zch_e2ee/zch_e2ee.py`
Mueve el código que programamos de `zch_e2ee.py` dentro de esta nueva carpeta `src/zch_e2ee/`.

#### 4. `README.md`
Escribe una pequeña descripción de tu proyecto para que se vea en la web de PyPI.

---

## Paso 3: Construir el Paquete (Build)

Instala las herramientas necesarias para empaquetar y subir el código:

```powershell
pip install build twine
```

Una vez instaladas, abre la terminal en la raíz de tu proyecto (donde está `pyproject.toml`) y ejecuta:

```powershell
python -m build
```

Esto generará una carpeta llamada `dist/` con dos archivos dentro (un archivo `.tar.gz` y un `.whl`). Estos son los archivos empaquetados listos para subirse.

---

## Paso 4: Subir a PyPI con Twine

Para subir tus archivos a PyPI, ejecuta el siguiente comando:

```powershell
python -m twine upload dist/*
```

La consola te pedirá dos datos:
1. **Enter your username:** Escribe exactamente `__token__` (con los guiones bajos).
2. **Enter your password:** Pega el token de API completo que copiaste en el **Paso 1** (incluyendo el prefijo `pypi-`). *Nota: no verás caracteres en pantalla al pegar la contraseña por seguridad, solo presiona Enter.*

¡Y listo! Una vez que finalice la subida, cualquiera podrá escribir en su consola:
```powershell
pip install zch-e2ee
```
Y luego en su código Python:
```python
import zch_e2ee
```
