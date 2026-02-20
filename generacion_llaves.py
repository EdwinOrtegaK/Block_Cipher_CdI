"""
Generador de claves criptográficamente seguras.

--- Uso de IA ---
Prompt utilizado para generar la estructura base del código:

"Necesito ayuda para implementar el archivo generacion_llaves.py en Python.
Debo crear funciones para generar claves criptográficamente seguras para DES
(8 bytes), 3DES (16 o 24 bytes según opción), AES (128, 192 o 256 bits) y un
vector de inicialización del tamaño de bloque correspondiente. Quiero que se
use la librería secrets, que se incluyan validaciones de parámetros y que el
código quede limpio y reutilizable para el resto del laboratorio."
"""
import secrets
import random

def generate_des_key() -> bytes:
    """
    Genera una clave DES aleatoria de 8 bytes (64 bits).
    
    Nota: DES usa efectivamente 56 bits (los otros 8 son de paridad),
    pero la clave es de 8 bytes.

    """
    return secrets.token_bytes(8)


def generate_3des_key(key_option: int = 2) -> bytes:
    """
    Genera una clave 3DES aleatoria.

    key_option:
        2 -> 16 bytes (2-key 3DES: K1 || K2, con K3 = K1)
        3 -> 24 bytes (3-key 3DES: K1 || K2 || K3)
    """
    if key_option not in (2, 3):
        raise ValueError("key_option debe ser 2 (16 bytes) o 3 (24 bytes)")

    key_len = 16 if key_option == 2 else 24
    return secrets.token_bytes(key_len)


def generate_aes_key(key_size: int = 256) -> bytes:
    """
    Genera una clave AES aleatoria.
    
    key_size debe ser 128, 192 o 256 (bits).
    """
    if key_size not in (128, 192, 256):
        raise ValueError("key_size debe ser 128, 192 o 256 bits")

    key_len_bytes = key_size // 8
    return secrets.token_bytes(key_len_bytes)


def generate_iv(block_size: int = 8) -> bytes:
    """
    Genera un vector de inicialización (IV) aleatorio.

    Importante:
    - En DES/3DES (bloque de 8 bytes): block_size = 8
    - En AES (bloque de 16 bytes): block_size = 16
    """
    if not isinstance(block_size, int) or block_size <= 0:
        raise ValueError("block_size debe ser un entero positivo")

    return secrets.token_bytes(block_size)

if __name__ == "__main__":
    print("DES:", len(generate_des_key()), "bytes")
    print("3DES (2-key):", len(generate_3des_key(2)), "bytes")
    print("3DES (3-key):", len(generate_3des_key(3)), "bytes")
    print("AES-128:", len(generate_aes_key(128)), "bytes")
    print("AES-192:", len(generate_aes_key(192)), "bytes")
    print("AES-256:", len(generate_aes_key(256)), "bytes")
    print("IV DES/3DES:", len(generate_iv(8)), "bytes")
    print("IV AES:", len(generate_iv(16)), "bytes")