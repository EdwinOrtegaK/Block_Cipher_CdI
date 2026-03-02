import pytest

from src.utils import generate_des_key, generate_3des_key, generate_iv
from src.des_cipher import encrypt_des_ecb, decrypt_des_ecb
from src.tripledes_cipher import encrypt_3des_cbc, decrypt_3des_cbc

# Helpers
PLAINTEXTS = [
    b"",  # caso borde: vacío (padding)
    b"A",
    b"1234567",          # 7 bytes
    b"12345678",         # 8 bytes
    b"hola mundo",
    b"Mensaje de prueba para cifrado por bloques.",
    b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09",  # bytes arbitrarios
]


# 1.1 DES ECB
"""
Prompt utilizado con IA: 
Genera tests en pytest para funciones encrypt_des_ecb y decrypt_des_ecb que 
validen round-trip correcto, que el ciphertext sea múltiplo de 8 bytes, que 
se rechacen claves inválidas y que se lance excepción si el ciphertext no es 
múltiplo del bloque.
"""
@pytest.mark.parametrize("plaintext", PLAINTEXTS)
def test_des_ecb_roundtrip(plaintext: bytes):
    key = generate_des_key()
    ciphertext = encrypt_des_ecb(plaintext, key)
    recovered = decrypt_des_ecb(ciphertext, key)
    assert recovered == plaintext


def test_des_ecb_ciphertext_is_multiple_of_block_size():
    key = generate_des_key()
    plaintext = b"Hola DES ECB! Probando padding manual."
    ciphertext = encrypt_des_ecb(plaintext, key)
    assert len(ciphertext) % 8 == 0
    assert len(ciphertext) > 0


def test_des_ecb_rejects_bad_key_length():
    plaintext = b"test"
    bad_key = b"1234567"  # 7 bytes
    with pytest.raises(ValueError):
        encrypt_des_ecb(plaintext, bad_key)


def test_des_ecb_rejects_non_bytes_plaintext():
    key = generate_des_key()
    with pytest.raises(TypeError):
        encrypt_des_ecb("hola", key)


def test_des_ecb_rejects_invalid_ciphertext_length():
    key = generate_des_key()
    bad_ciphertext = b"\x00" * 7
    with pytest.raises(ValueError):
        decrypt_des_ecb(bad_ciphertext, key)


# 1.2 3DES CBC
"""
Prompt utilizado con IA: 
Genera tests en pytest para funciones encrypt_3des_cbc y decrypt_3des_cbc que
validen round-trip, múltiplos de bloque, rechazo de clave inválida (no 16 o 24 bytes),
rechazo de IV inválido (no 8 bytes) y que el mismo plaintext con IV diferente
produzca ciphertext distinto.
"""
@pytest.mark.parametrize("plaintext", PLAINTEXTS)
@pytest.mark.parametrize("key_option", [2, 3])
def test_3des_cbc_roundtrip(plaintext: bytes, key_option: int):
    key = generate_3des_key(key_option)
    iv = generate_iv(8)
    ciphertext = encrypt_3des_cbc(plaintext, key, iv)
    recovered = decrypt_3des_cbc(ciphertext, key, iv)
    assert recovered == plaintext


def test_3des_cbc_ciphertext_is_multiple_of_block_size():
    key = generate_3des_key(2)
    iv = generate_iv(8)
    plaintext = b"Mensaje de prueba para 3DES CBC"
    ciphertext = encrypt_3des_cbc(plaintext, key, iv)
    assert len(ciphertext) % 8 == 0
    assert len(ciphertext) > 0


def test_3des_cbc_same_plaintext_same_key_different_iv_changes_ciphertext():
    key = generate_3des_key(2)
    plaintext = b"Mensaje fijo"
    iv1 = generate_iv(8)
    iv2 = generate_iv(8)
    c1 = encrypt_3des_cbc(plaintext, key, iv1)
    c2 = encrypt_3des_cbc(plaintext, key, iv2)
    assert c1 != c2


def test_3des_cbc_rejects_bad_iv_length():
    key = generate_3des_key(2)
    bad_iv = generate_iv(16)
    with pytest.raises(TypeError):
        encrypt_3des_cbc(b"test", key, bad_iv)


def test_3des_cbc_rejects_bad_key_length():
    bad_key = b"\x01" * 15
    iv = generate_iv(8)
    with pytest.raises(ValueError):
        encrypt_3des_cbc(b"test", bad_key, iv)


def test_3des_cbc_rejects_invalid_ciphertext_length():
    key = generate_3des_key(2)
    iv = generate_iv(8)
    bad_ciphertext = b"\x00" * 7
    with pytest.raises(ValueError):
        decrypt_3des_cbc(bad_ciphertext, key, iv)