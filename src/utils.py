import secrets
import random

def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data debe ser bytes o bytearray")
    if not isinstance(block_size, int) or block_size <= 0 or block_size > 255:
        raise ValueError("block_size debe ser un entero entre 1 y 255")

    padding_len = block_size - (len(data) % block_size)
    if padding_len == 0:
        padding_len = block_size

    padding = bytes([padding_len]) * padding_len
    
    return bytes(data) + padding


def pkcs7_unpad(data: bytes, block_size: int = 8) -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data debe ser bytes o bytearray")
    if len(data) == 0:
        raise ValueError("data no puede ser vacío")
    if not isinstance(block_size, int) or block_size <= 0 or block_size > 255:
        raise ValueError("block_size debe ser un entero entre 1 y 255")
    if len(data) % block_size != 0:
        raise ValueError("Longitud inválida: no es múltiplo del tamaño de bloque")

    padding_len = data[-1]

    if padding_len < 1 or padding_len > block_size:
        raise ValueError("Padding inválido (longitud fuera de rango)")

    if data[-padding_len:] != bytes([padding_len]) * padding_len:
        raise ValueError("Padding inválido (bytes no coinciden)")

    return data[:-padding_len]

def generate_des_key() -> bytes:
    return secrets.token_bytes(8)


def generate_3des_key(key_option: int = 2) -> bytes:
    if key_option not in (2, 3):
        raise ValueError("key_option debe ser 2 (16 bytes) o 3 (24 bytes)")

    key_len = 16 if key_option == 2 else 24
    return secrets.token_bytes(key_len)


def generate_aes_key(key_size: int = 256) -> bytes:
    if key_size not in (128, 192, 256):
        raise ValueError("key_size debe ser 128, 192 o 256 bits")

    key_len_bytes = key_size // 8
    return secrets.token_bytes(key_len_bytes)


def generate_iv(block_size: int = 8) -> bytes:
    if not isinstance(block_size, int) or block_size <= 0:
        raise ValueError("block_size debe ser un entero positivo")

    return secrets.token_bytes(block_size)