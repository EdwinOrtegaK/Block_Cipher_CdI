"""
Necesito crear un script en Python llamado security_experiments.py dentro 
de la carpeta scripts/
El script debe generar evidencia en consola para el análisis de seguridad 
del laboratorio, incluyendo:

Mostrar tamaños de clave para DES, 3DES y AES usando mis funciones existentes 
en src.utils

Demostrar la vulnerabilidad de ECB cifrando un mensaje repetido y mostrando los 
bloques en hexadecimal, comparándolo con CBC

Implementar un experimento de IV en CBC mostrando que con el mismo IV el ciphertext 
es igual y con IVs distintos es diferente

Mostrar ejemplos de padding PKCS7 manual con mensajes de 5, 8 y 10 bytes, explicando 
los bytes agregados y verificando que unpad recupera el original
El código debe reutilizar mis funciones ya implementadas en src/ y formatear la salida
"""
from __future__ import annotations
from textwrap import wrap
from src.utils import (
    generate_des_key,
    generate_3des_key,
    generate_aes_key,
    generate_iv,
    pkcs7_pad,
    pkcs7_unpad,
)
from src.des_cipher import encrypt_des_ecb
from src.tripledes_cipher import encrypt_3des_cbc
from src.aes_cipher import encrypt_aes_ecb, encrypt_aes_cbc

# Helpers
def chunk_bytes(data: bytes, block_size: int) -> list[bytes]:
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]


def hex_blocks(data: bytes, block_size: int) -> list[str]:
    return [b.hex() for b in chunk_bytes(data, block_size)]


def print_blocks(label: str, data: bytes, block_size: int, max_blocks: int = 12) -> None:
    blocks = hex_blocks(data, block_size)
    print(f"\n{label} (block_size={block_size}, total_blocks={len(blocks)})")
    for i, hx in enumerate(blocks[:max_blocks]):
        print(f"  B{i:02d}: {hx}")
    if len(blocks) > max_blocks:
        print(f"  ... ({len(blocks) - max_blocks} bloques más)")


def main() -> None:
    print("SECURITY EXPERIMENTS")

    # Tamaños de clave
    print("\nTamaños de clave (bits/bytes) + snippet")
    des_key = generate_des_key()
    des3_key_16 = generate_3des_key(2)
    des3_key_24 = generate_3des_key(3)
    aes_128 = generate_aes_key(128)
    aes_192 = generate_aes_key(192)
    aes_256 = generate_aes_key(256)

    print("DES key len:", len(des_key), "bytes =", len(des_key) * 8, "bits (DES: 56 bits efectivos + paridad)")
    print("3DES 2-key len:", len(des3_key_16), "bytes =", len(des3_key_16) * 8, "bits")
    print("3DES 3-key len:", len(des3_key_24), "bytes =", len(des3_key_24) * 8, "bits")
    print("AES-128 len:", len(aes_128), "bytes =", len(aes_128) * 8, "bits")
    print("AES-192 len:", len(aes_192), "bytes =", len(aes_192) * 8, "bits")
    print("AES-256 len:", len(aes_256), "bytes =", len(aes_256) * 8, "bits")

    print("\nSnippet sugerido para README (generación y longitudes):")
    print("------------------------------------------------------------")
    print("from src.utils import generate_des_key, generate_3des_key, generate_aes_key\n"
          "print(len(generate_des_key()))\n"
          "print(len(generate_3des_key(2)), len(generate_3des_key(3)))\n"
          "print(len(generate_aes_key(128)), len(generate_aes_key(192)), len(generate_aes_key(256)))")
    print("------------------------------------------------------------")

    # Padding (PKCS#7 manual)
    print("\nPadding PKCS#7 manual (DES block = 8)")
    block_size = 8
    msgs = {
        "5 bytes": b"ABCDE",
        "8 bytes": b"ABCDEFGH",
        "10 bytes": b"ABCDEFGHIJ",
    }

    for name, msg in msgs.items():
        padded = pkcs7_pad(msg, block_size)
        recovered = pkcs7_unpad(padded, block_size)

        pad_len = padded[-1]
        pad_bytes = padded[-pad_len:]

        print(f"\nCaso {name}:")
        print("  Mensaje original (hex):", msg.hex())
        print("  Longitud original:", len(msg))
        print("  Padded (hex):", padded.hex())
        print("  Longitud padded:", len(padded))
        print("  padding_len:", pad_len)
        print("  bytes agregados:", pad_bytes.hex(), f"(son {pad_len} bytes iguales a 0x{pad_len:02x})")
        print("  Unpad recupera original?:", recovered == msg)

    # Vulnerabilidad ECB (bloques repetidos)
    print("\nVulnerabilidad ECB: bloques idénticos => cifrados idénticos")
    repeated_block = b"A" * 16
    repeated_msg = repeated_block * 8
    print("Mensaje repetido:", repeated_msg)

    # ECB (AES ECB)
    key_aes = generate_aes_key(128)
    ct_ecb = encrypt_aes_ecb(repeated_msg, key_aes)

    # CBC (AES CBC)
    iv_aes = generate_iv(16)
    ct_cbc = encrypt_aes_cbc(repeated_msg, key_aes, iv_aes)

    print_blocks("AES-ECB ciphertext", ct_ecb, 16, max_blocks=16)
    print_blocks("AES-CBC ciphertext", ct_cbc, 16, max_blocks=16)

    # Revisión automática de repetición de bloques en ECB:
    ecb_blocks = hex_blocks(ct_ecb, 16)
    duplicates = len(ecb_blocks) - len(set(ecb_blocks))
    print("\nECB: bloques duplicados detectados?:", duplicates > 0, f"(duplicados={duplicates})")
    print("CBC: normalmente NO verás duplicados, porque se encadena con IV + C(i-1).")

    # IV (mismo IV vs IVs diferentes) usando 3DES CBC
    print("\nExperimento IV en CBC (3DES-CBC)")
    msg_iv = b"Mensaje fijo para experimento IV"
    key_3des = generate_3des_key(2)

    iv_same = generate_iv(8)
    c_same_1 = encrypt_3des_cbc(msg_iv, key_3des, iv_same)
    c_same_2 = encrypt_3des_cbc(msg_iv, key_3des, iv_same)

    iv_diff_1 = generate_iv(8)
    iv_diff_2 = generate_iv(8)
    c_diff_1 = encrypt_3des_cbc(msg_iv, key_3des, iv_diff_1)
    c_diff_2 = encrypt_3des_cbc(msg_iv, key_3des, iv_diff_2)

    print("Mensaje:", msg_iv)
    print("Mismo IV => ciphertext igual?:", c_same_1 == c_same_2)
    print("IV diferente => ciphertext diferente?:", c_diff_1 != c_diff_2)

    print("IV same:", iv_same.hex())
    print("C same 1:", c_same_1.hex())
    print("C same 2:", c_same_2.hex())

    print("IV diff 1:", iv_diff_1.hex())
    print("C diff 1:", c_diff_1.hex())
    print("IV diff 2:", iv_diff_2.hex())
    print("C diff 2:", c_diff_2.hex())


if __name__ == "__main__":
    main()