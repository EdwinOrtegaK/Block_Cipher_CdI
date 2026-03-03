from src.aes_cipher import generate_ecb_cbc_image_outputs

def main():
    info = generate_ecb_cbc_image_outputs(
        original_path="images/original.png",
        out_ecb_path="images/aes_ecb.png",
        out_cbc_path="images/aes_cbc.png",
        key_size_bits=256,
    )

    print("=== Imagenes generadas ===")
    print("Key (hex):", info["key_hex"])
    print("IV  (hex):", info["iv_hex"])

if __name__ == "__main__":
    main()