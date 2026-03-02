"""
Módulo de padding PKCS#7 para cifrados de bloque.
Implementación manual sin usar bibliotecas externas.
"""

def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    """
    Implementa padding PKCS#7 según RFC 5652.
    
    Regla: Si faltan N bytes para completar el bloque,
    agregar N bytes, cada uno con el valor N (recuerden seguir la regla de pkcs#7).
    
    Importante: Si el mensaje es múltiplo exacto del tamaño
    de bloque, se agrega un bloque completo de padding.
    
    Examples:
        >>> pkcs7_pad(b"HOLA", 8).hex()
        '484f4c4104040404'  # HOLA + 4 bytes con valor 0x04
        
        >>> pkcs7_pad(b"12345678", 8).hex()  # Exactamente 8 bytes
        '31323334353637380808080808080808'  # + bloque completo
    """
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
    """
    Elimina padding PKCS#7 de los datos.
    
    Examples:
        >>> padded = pkcs7_pad(b"HOLA", 8)
        >>> pkcs7_unpad(padded)
        b'HOLA'
    """

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

if __name__ == "__main__":
    print(pkcs7_pad(b"HOLA", 8).hex())
    print(pkcs7_pad(b"12345678", 8).hex())

    p = pkcs7_pad(b"HOLA", 8)
    print(pkcs7_unpad(p))