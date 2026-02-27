from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from generacion_llaves import generate_3des_key, generate_iv

BLOCK_SIZE = 8

def validate_3des_key_and_iv(key: bytes, iv: bytes) -> None:
    if not isinstance (key, (bytes, bytearray)):
        raise TypeError ("Key debe ser bytes o bytearray")
    if len(key) not in (16, 24):
        raise TypeError ("La clave 3DES debe ser de 16 o 24 bytes")
    
    if not isinstance (iv, (bytes, bytearray)):
        raise TypeError ("iv debe ser bytes o bytearray")
    if len(iv) != BLOCK_SIZE:
        raise TypeError ("El iv para 3DES-CBC debe ser de 8 bytes")
    
    try:
        DES3.adjust_key_parity(bytes(key))
    except ValueError as e:
        raise ValueError (f"Clave 3DES es invalida: {e}") from e

def encrypt_3des_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """    
    Example:
        >>> key = generate_3des_key(2)
        >>> iv = generate_iv(8)
        >>> plaintext = b"Mensaje secreto para 3DES"
        >>> ciphertext = encrypt_3des_cbc(plaintext, key, iv)
        >>> len(ciphertext) % 8
        0  # Debe ser múltiplo de 8 (tamaño de bloque de DES)
    """
    if not isinstance (plaintext, (bytes, bytearray)):
        raise TypeError("Plaintext debe ser en bytes o bytearray")
    
    validate_3des_key_and_iv(key, iv)

    key = DES3.adjust_key_parity(bytes(key))
    padded = pad(bytes(plaintext), BLOCK_SIZE)
    cipher = DES3.new(key, DES3.MODE_CBC, iv=bytes(iv))
    ciphertext = cipher.encrypt(padded)
    return ciphertext

def decrypt_3des_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """    
    Example:
        >>> key = generate_3des_key(2)
        >>> iv = generate_iv(8)
        >>> plaintext = b"Mensaje secreto"
        >>> ciphertext = encrypt_3des_cbc(plaintext, key, iv)
        >>> decrypted = decrypt_3des_cbc(ciphertext, key, iv)
        >>> decrypted == plaintext
        True
    """
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("Ciphertext debe ser bytes o bytearray")
    if len(ciphertext) == 0 or (len(ciphertext) % BLOCK_SIZE != 0):
        raise ValueError("Ciphertext invalido: debe ser múltiplo de 8 y no vacío")

    validate_3des_key_and_iv(key, iv)

    key = DES3.adjust_key_parity(bytes(key))

    cipher = DES3.new(key, DES3.MODE_CBC, iv=bytes(iv))
    padded_plaintext = cipher.decrypt(bytes(ciphertext))
    plaintext = unpad(padded_plaintext, BLOCK_SIZE)
    return plaintext
