# zch-e2ee

High-level Python module for end-to-end encryption (E2EE) and digital signatures.

[[Leer versión en Español]](README.md)

---

## Key Features

*   **Asymmetric Encryption (RSA):** Hybrid E2EE using RSA-2048/4096 and 256-bit AES-GCM.
*   **Symmetric Password Encryption:** Strong password-based encryption with Scrypt key derivation, AES-GCM, and fast Key Verification Value (KVV) validation.
*   **Threshold Cryptography (Shamir's Secret Sharing):** Divide a secret into $N$ shares, requiring a minimum threshold $T$ of them to reconstruct, computed over Galois Field $GF(256)$ with table-based optimization.
*   **Encrypted Local Keystore (`KeystoreZCH`):** Secure storage container to save and retrieve private/public keys, protected with Scrypt + AES-GCM.
*   **Perfect Forward Secrecy (Double Ratchet):** Interaction session protocol using continuous Diffie-Hellman (X25519) and symmetric (HKDF-SHA256) ratchets.
*   **Message Authentication:** Compute and verify symmetric message authentication codes using HMAC-SHA256.
*   **In-Memory Encrypted Loader (`importer.py`):** Python import hook intercepting `.py.enc` modules to decrypt and execute them directly in memory without writing decrypted files to disk.

---

## Installation

```bash
pip install zch-e2ee
```

---

## Quick Start

### 1. Hybrid RSA E2EE Encryption
```python
import zch_e2ee

# Generate RSA key pair
private_key, public_key = zch_e2ee.generar_llaves()

# Encrypt message with public key
encrypted = zch_e2ee.encriptar_e2ee("Hello, this is a secure message", public_key)

# Decrypt message with private key
original = zch_e2ee.desencriptar_e2ee(encrypted, private_key)
print(original)  # "Hello, this is a secure message"
```

### 2. Shamir's Secret Sharing
```python
import zch_e2ee

secret = b"MyMasterPassword"
# Split the secret into 5 shares with a threshold of 3
shares = zch_e2ee.dividir_secreto_shamir(secret, n=5, t=3)

# Reconstruct using any 3 shares
recovered = zch_e2ee.reconstruir_secreto_shamir([shares[0], shares[2], shares[4]])
print(recovered.decode('utf-8'))  # "MyMasterPassword"
```

### 3. Double Ratchet Conversation Session
```python
from zch_e2ee import SesionDoubleRatchet, generar_llaves_ec

# Generate ephemeral X25519 keys
priv_alice, pub_alice = generar_llaves_ec()
priv_bob, pub_bob = generar_llaves_ec()

# Initialize sessions
session_alice = SesionDoubleRatchet(priv_alice, pub_bob, es_iniciador=True)
session_bob = SesionDoubleRatchet(priv_bob, pub_alice, es_iniciador=False)

# Alice sends encrypted message
ciphertext = session_alice.enviar_mensaje("Hello Bob, PFS is active!")

# Bob decrypts message
decrypted = session_bob.recibir_mensaje(ciphertext)
print(decrypted)  # "Hello Bob, PFS is active!"
```

### 4. Importing Encrypted Code Modules
```python
import zch_e2ee

# Encrypt your secret python module
zch_e2ee.encriptar_modulo_python("my_module.py", "my_module.py.enc", "MyModulePassword123")

# Register the encrypted importer hook
zch_e2ee.registrar_importador_cifrado("MyModulePassword123")

# Import the encrypted module directly into memory (no decrypted file written on disk)
import my_module
my_module.run_secret_task()
```
