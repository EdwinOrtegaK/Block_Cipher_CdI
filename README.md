# Ejercicio Block – Cifrados de Información


## Descripción

Este laboratorio implementa y analiza algoritmos de cifrado de bloque:

- DES (ECB)
- 3DES (CBC)
- AES-256 (ECB y CBC, análisis visual con imágenes)

Incluye pruebas unitarias, experimentos de seguridad y comparación visual entre modos de operación.

## Instalación de dependencias

```bash
pip install -r requirements.txt
```

### Estructura del Proyecto

```
src/
    utils.py
    des_cipher.py
    tripledes_cipher.py
    aes_cipher.py

scripts/
    generate_images.py
    security_experiments.py

images/
    original.png
    aes_ecb.png
    aes_cbc.png

test/
    test_ciphers.py
```

## Ejecución

### DES ECB

```bash
python -m src.des_cipher
```

### 3DES CBC

```bash
python -m src.tripledes_cipher
```

### Generar imágenes AES (ECB vs CBC)

```bash
python -m scripts.generate_images
```

### Experimentos de seguridad

```bash
python -m scripts.security_experiments
```

### Ejecutar pruebas

```bash
pytest -q
```


## Respuestas Parte 2 – Análisis de Seguridad

### 2.1 Tamaños de Clave

En esta implementación se utilizaron claves de 8 bytes (64 bits, 56 efectivos) para DES, 16 y 24 bytes para 3DES (128 y 192 bits), y hasta 32 bytes (256 bits) para AES. DES se considera inseguro porque su espacio real de búsqueda es de 2^54 combinaciones, lo que puede romperse mediante fuerza bruta con hardware moderno en un tiempo relativamente corto usando GPUs o sistemas distribuidos. En contraste, AES-256 posee un espacio de búsqueda de 2^256, lo que lo hace computacionalmente inalcanzable con tecnología actual y por ello es el estándar moderno.

### 2.2 Comparación ECB vs CBC

ECB cifra cada bloque de manera independiente, mientras que CBC encadena cada bloque con el anterior usando un IV. Esto provoca que en ECB bloques iguales produzcan cifrados iguales, conservando patrones del mensaje original. En el experimento con imágenes, ECB mantiene estructura visible, mientras que CBC produce una salida visualmente aleatoria, demostrando mayor seguridad estructural.

### 2.3 Vulnerabilidad de ECB

ECB no debe utilizarse en datos sensibles porque no oculta patrones repetidos. En el experimento realizado, bloques idénticos del plaintext generaron bloques idénticos en el ciphertext en modo ECB, mientras que en CBC todos los bloques fueron diferentes. Esto puede filtrar información estructural, como regiones repetidas en imágenes o campos constantes en registros, incluso sin conocer la clave.

### 2.4 Vector de Inicialización (IV)

El IV es un valor aleatorio usado en CBC para asegurar que mensajes iguales produzcan cifrados diferentes. Cuando se reutiliza el mismo IV, el ciphertext resultante es idéntico; al usar IVs distintos, el resultado cambia completamente. Reutilizar IVs permite correlacionar mensajes y debilita la seguridad. ECB no utiliza IV porque no encadena bloques.

### 2.5 Padding

El padding es necesario cuando el mensaje no es múltiplo del tamaño de bloque. En PKCS#7 se agregan N bytes con valor N para completar el bloque. Si el mensaje ya es múltiplo exacto, se agrega un bloque completo adicional. Esto permite que el receptor identifique correctamente cuántos bytes eliminar al descifrar y recuperar el mensaje original.

### 2.6 Recomendaciones

ECB no se recomienda por su vulnerabilidad estructural. CBC puede usarse en sistemas legacy, pero requiere manejo seguro del IV y padding. CTR ofrece mejor rendimiento y paralelización, pero no autentica. El modo recomendado actualmente es GCM, ya que proporciona confidencialidad e integridad (AEAD) y está disponible en bibliotecas modernas como implementación segura por defecto.
