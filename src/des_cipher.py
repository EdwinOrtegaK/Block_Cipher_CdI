from Crypto.Cipher import DES
from src.utils import pkcs7_pad, pkcs7_unpad

BLOCK_SIZE = 8

def _validate_des_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key debe ser bytes o bytearray")
    if len(key) != BLOCK_SIZE:
        raise ValueError("La clave DES debe ser de 8 bytes (64 bits)")


def encrypt_des_ecb(plaintext: bytes, key: bytes) -> bytes:
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("Plaintext debe ser bytes o bytearray")

    _validate_des_key(key)

    padded = pkcs7_pad(bytes(plaintext), BLOCK_SIZE)
    cipher = DES.new(bytes(key), DES.MODE_ECB)
    ciphertext = cipher.encrypt(padded)
    return ciphertext


def decrypt_des_ecb(ciphertext: bytes, key: bytes) -> bytes:
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("Ciphertext debe ser bytes o bytearray")
    if len(ciphertext) == 0 or (len(ciphertext) % BLOCK_SIZE != 0):
        raise ValueError("Ciphertext inválido: debe ser múltiplo de 8 y no vacío")

    _validate_des_key(key)

    cipher = DES.new(bytes(key), DES.MODE_ECB)
    padded_plaintext = cipher.decrypt(bytes(ciphertext))
    plaintext = pkcs7_unpad(padded_plaintext, BLOCK_SIZE)
    return plaintext
