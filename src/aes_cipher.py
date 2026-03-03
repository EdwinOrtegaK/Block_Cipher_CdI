from __future__ import annotations
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image
from src.utils import generate_aes_key, generate_iv

BLOCK_SIZE = 16

def _validate_aes_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("Key debe ser bytes o bytearray")
    if len(key) not in (16, 24, 32):
        raise ValueError("La clave AES debe ser de 16, 24 o 32 bytes")


def _validate_iv(iv: bytes) -> None:
    if not isinstance(iv, (bytes, bytearray)):
        raise TypeError("iv debe ser bytes o bytearray")
    if len(iv) != BLOCK_SIZE:
        raise ValueError("El IV para AES-CBC debe ser de 16 bytes")

# AES ECB / CBC (texto/bytes)
def encrypt_aes_ecb(plaintext: bytes, key: bytes) -> bytes:
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("Plaintext debe ser bytes o bytearray")
    _validate_aes_key(key)

    cipher = AES.new(bytes(key), AES.MODE_ECB)
    padded = pad(bytes(plaintext), BLOCK_SIZE)
    return cipher.encrypt(padded)

def decrypt_aes_ecb(ciphertext: bytes, key: bytes) -> bytes:
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("Ciphertext debe ser bytes o bytearray")
    if len(ciphertext) == 0 or (len(ciphertext) % BLOCK_SIZE != 0):
        raise ValueError("Ciphertext inválido: debe ser múltiplo de 16 y no vacío")

    _validate_aes_key(key)

    cipher = AES.new(bytes(key), AES.MODE_ECB)
    padded_plaintext = cipher.decrypt(bytes(ciphertext))
    return unpad(padded_plaintext, BLOCK_SIZE)

def encrypt_aes_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("Plaintext debe ser bytes o bytearray")

    _validate_aes_key(key)
    _validate_iv(iv)

    cipher = AES.new(bytes(key), AES.MODE_CBC, iv=bytes(iv))
    padded = pad(bytes(plaintext), BLOCK_SIZE)
    return cipher.encrypt(padded)

def decrypt_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("Ciphertext debe ser bytes o bytearray")
    if len(ciphertext) == 0 or (len(ciphertext) % BLOCK_SIZE != 0):
        raise ValueError("Ciphertext inválido: debe ser múltiplo de 16 y no vacío")

    _validate_aes_key(key)
    _validate_iv(iv)

    cipher = AES.new(bytes(key), AES.MODE_CBC, iv=bytes(iv))
    padded_plaintext = cipher.decrypt(bytes(ciphertext))
    return unpad(padded_plaintext, BLOCK_SIZE)

# AES sobre imágenes 
def _load_image_rgb_bytes(path: str) -> tuple[Image.Image, bytes]:
    # Convierte imagen a RGB y devuelve (imagen_rgb, bytes_pixels)
    img = Image.open(path).convert("RGB")
    pixel_bytes = img.tobytes()
    return img, pixel_bytes

def _save_image_from_rgb_bytes(template_img: Image.Image, pixel_bytes: bytes, out_path: str) -> None:
    # Guarda una imagen RGB usando el tamaño de template_img
    out_img = Image.frombytes("RGB", template_img.size, pixel_bytes)
    out_img.save(out_path)


def encrypt_image_aes_ecb(in_path: str, out_path: str, key: bytes) -> None:
    # Cifra los bytes de pixeles de una imagen con AES-ECB
    img, pixel_bytes = _load_image_rgb_bytes(in_path)

    ct = encrypt_aes_ecb(pixel_bytes, key)
    ct_pixels = ct[: len(pixel_bytes)]

    _save_image_from_rgb_bytes(img, ct_pixels, out_path)

def encrypt_image_aes_cbc(in_path: str, out_path: str, key: bytes, iv: bytes) -> None:
    # Cifra los bytes de pixeles de una imagen con AES-CBC
    img, pixel_bytes = _load_image_rgb_bytes(in_path)

    ct = encrypt_aes_cbc(pixel_bytes, key, iv)

    ct_pixels = ct[: len(pixel_bytes)]
    _save_image_from_rgb_bytes(img, ct_pixels, out_path)

def generate_ecb_cbc_image_outputs(
    original_path: str,
    out_ecb_path: str,
    out_cbc_path: str,
    key_size_bits: int = 256,
) -> dict:
    # Genera outputs de imagen para comparar ECB vs CBC.
    if key_size_bits not in (128, 192, 256):
        raise ValueError("key_size_bits debe ser 128, 192 o 256")

    key = generate_aes_key(key_size_bits)
    iv = generate_iv(16)

    encrypt_image_aes_ecb(original_path, out_ecb_path, key)
    encrypt_image_aes_cbc(original_path, out_cbc_path, key, iv)

    return {
        "key_size_bits": key_size_bits,
        "key_hex": key.hex(),
        "iv_hex": iv.hex(),
        "original_path": original_path,
        "ecb_path": out_ecb_path,
        "cbc_path": out_cbc_path,
    }