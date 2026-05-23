# Reto Final — El Triángulo de Hierro 🔺

**Sistemas Operativos — Universidad EAFIT, 2026-1**

Pipeline de memoria en C que integra compresión RLE y cifrado RC4 simétrico para proteger datos en reposo (*Data at Rest*), demostrando el equilibrio entre espacio, tiempo y seguridad.

---

## Tabla de Contenidos

1. [Contexto y Arquitectura](#contexto-y-arquitectura)
2. [Estructura del Proyecto](#estructura-del-proyecto)
3. [Compilación y Uso paso a paso](#compilación-y-uso-paso-a-paso)
4. [Por qué Comprimir ANTES de Cifrar](#por-qué-comprimir-antes-de-cifrar)
5. [Justificación de Algoritmos](#justificación-de-algoritmos)
6. [Seguridad de Llave en RAM](#seguridad-de-llave-en-ram)
7. [Benchmark: Resultados](#benchmark-resultados)
8. [Respuestas a Preguntas de Sustentación](#respuestas-a-preguntas-de-sustentación)

---

## Contexto y Arquitectura

El reto integra tres tensiones del mundo real — **Espacio, Tiempo y Seguridad** — en un único pipeline de memoria:

```
ESCRITURA:
  stdin → [leer_stdin()]  → RAM
        → [RLE compress]  → buffer comprimido en RAM
        → [RC4 encrypt]   → buffer cifrado en RAM   (in-place, sin copia extra)
        → [write() × N]   → disco  (chunks de 4096 bytes = PAGE_SIZE)

LECTURA:
  disco → [fread()]       → buffer cifrado en RAM
        → [RC4 decrypt]   → buffer comprimido en RAM  (in-place, simétrico)
        → [RLE decompress]→ datos originales en RAM
        → [write(stdout)] → salida
```

**Todo el procesamiento ocurre en RAM.** El disco solo ve los bytes finales: comprimidos y cifrados.

---

## Estructura del Proyecto

```
RetoFinal-SistemasOperativos/
├── src/
│   ├── editor.c        # Programa principal — orquesta el pipeline
│   ├── compress.c      # RLE (Run-Length Encoding) — implementación propia
│   ├── compress.h      # Declaraciones públicas de compresión
│   ├── crypto.c        # RC4 stream cipher — implementación propia
│   └── crypto.h        # Declaraciones públicas de cifrado + typedef RC4_CTX
├── Makefile
├── benchmark.sh        # Benchmark automatizado con time + strace
└── README.md
```

---

## Compilación y Uso paso a paso

### 1. Requisitos

```bash
sudo apt install gcc make time strace    # Ubuntu/Debian/WSL
```

### 2. Compilar

```bash
make
```

Deberías ver exactamente esto, sin errores ni warnings:

```
gcc -Wall -Wextra -O2 -std=c11 -g -c -o src/editor.o src/editor.c
gcc -Wall -Wextra -O2 -std=c11 -g -c -o src/compress.o src/compress.c
gcc -Wall -Wextra -O2 -std=c11 -g -c -o src/crypto.o src/crypto.c
gcc -Wall -Wextra -O2 -std=c11 -g -o editor src/editor.o src/compress.o src/crypto.o
```

Esto genera el binario `editor` en la raíz del proyecto.

### 3. Cifrar y comprimir un archivo

```bash
./editor write archivo_cifrado.bin < mi_archivo.txt
```

El programa pedirá una llave en la terminal (no se muestra mientras escribes):

```
[pipeline] Modo escritura: archivo_cifrado.bin
[pipeline] 1/4 Leyendo datos de stdin...
[pipeline]     Leídos 9179 bytes
[pipeline] 2/4 Comprimiendo con RLE...
[pipeline]     9179 → 18022 bytes (-96.3% reducción)
Ingrese la llave de encriptación: ********
[pipeline] 3/4 Cifrando con RC4...
[pipeline]     Cifrado completado
[pipeline] 4/4 Escribiendo a disco...
[pipeline] ✓ Listo. Tamaño en disco: 18022 bytes
```

### 4. Descifrar y descomprimir

```bash
./editor read archivo_cifrado.bin
```

Usa **exactamente la misma llave** que usaste al cifrar. Si la llave es incorrecta, los datos saldrán corruptos.

### 5. Guardar el resultado en un archivo

```bash
./editor read archivo_cifrado.bin > archivo_recuperado.txt
```

### 6. Verificar integridad

```bash
diff mi_archivo.txt archivo_recuperado.txt && echo "✓ Integridad OK"
```

Si `diff` no imprime nada y aparece `✓ Integridad OK`, los datos recuperados son **bit a bit idénticos** al original.

### 7. Limpiar archivos compilados

```bash
make clean
```

### 8. Ejecutar el benchmark oficial

```bash
chmod +x benchmark.sh
./benchmark.sh
```

---

## Por qué Comprimir ANTES de Cifrar

Este es el concepto central del reto. El orden de las operaciones **no es arbitrario** — determina si el pipeline funciona o falla.

### El concepto clave: Entropía

**Entropía** mide qué tan "aleatorios" o impredecibles son los bytes de un archivo:

- **Datos normales** (texto, código, imágenes) → entropía **baja** → hay patrones repetitivos
- **Datos cifrados** → entropía **alta** → parecen completamente aleatorios, sin patrones

### Lo que hace cada algoritmo

**RLE** busca exactamente patrones repetitivos (*runs*):
```
AAAAAABBBBBB  →  [6][A][6][B]   ← comprime bien, aprovecha los runs
```

**RC4** destruye todos los patrones aplicando XOR con un keystream pseudoaleatorio:
```
AAAAAABBBBBB  →  x9Fk2#mQ@1z!   ← alta entropía, sin ningún patrón
```

### ✅ Orden correcto: Comprimir → Cifrar

```
datos originales  →  [RLE]  →  datos comprimidos  →  [RC4]  →  datos cifrados
    50 MB                  →       ~410 KB                 →      ~410 KB
  (con patrones)       aprovecha los runs             pequeño y seguro
```

RLE ve los patrones originales y los reduce. RC4 cifra el resultado ya reducido.

### ❌ Orden incorrecto: Cifrar → Comprimir

```
datos originales  →  [RC4]  →  datos pseudoaleatorios  →  [RLE]  →  sin cambio / más grande
    50 MB                  →         50 MB (sin patrones)        →   RLE no puede hacer nada
```

RC4 destruye todos los patrones primero. Cuando RLE intenta comprimir, no encuentra ningún *run* — en el peor caso codifica cada byte como `[1][byte]`, **duplicando** el tamaño del archivo.

### Demostración práctica

Puedes verificarlo tú mismo. Con datos altamente repetitivos:

```bash
# Generar archivo con muchos runs (comprimible con RLE)
python3 -c "import sys; sys.stdout.buffer.write(b'A'*10000 + b'B'*5000)" > datos.txt

# Orden correcto → comprime bien
EDITOR_KEY="test" ./editor write correcto.bin < datos.txt 2>/dev/null
echo "Correcto (RLE→RC4): $(wc -c < correcto.bin) bytes"
# Resultado: ~120 bytes (99% de reducción)
```

Si invirtieras el orden manualmente, RC4 primero produciría ~15000 bytes de datos pseudoaleatorios, y RLE los codificaría como ~30000 bytes — el doble del original.

### Nota sobre texto natural (lorem ipsum)

Con texto variado como lorem ipsum, RLE tampoco comprime bien porque el texto tiene poca repetición byte a byte. En ese caso el archivo crece (~96% de expansión). Esto es esperado: **RLE está diseñado para datos binarios estructurados** con runs largos, no para texto natural. El benchmark usa datos binarios con campos fijos para demostrar el caso favorable.

---

## Justificación de Algoritmos

### RLE (Run-Length Encoding) — ¿Por qué este algoritmo?

RLE codifica secuencias de bytes iguales como `[cantidad][byte]`:
```
AAAAAABBBB  →  [6][A][4][B]   (10 bytes → 4 bytes)
```

**Se eligió RLE porque:**
- Es implementable desde cero en ~50 líneas de C sin librerías externas
- No tiene padding — el output es exactamente tan largo como los datos lo requieren
- Es O(n) en tiempo y espacio — predecible y eficiente
- La rúbrica permite algoritmos propios y RLE es suficiente para demostrar el concepto

**Favorable cuando:**
- Datos binarios con campos fijos (bases de datos, imágenes BMP monocromáticas)
- Archivos con mucho padding de ceros (logs, registros de longitud fija)
- Cualquier archivo con runs largos de bytes repetidos

**Desfavorable cuando:**
- Texto natural (lorem ipsum, código fuente) — poca repetición byte a byte
- Datos ya comprimidos o pseudoaleatorios — entropía alta, no hay runs
- Archivos multimedia (JPEG, MP3) — ya tienen compresión interna

### RC4 — ¿Por qué este algoritmo?

RC4 es un *stream cipher* que genera un keystream pseudoaleatorio y aplica XOR byte a byte:

```c
// KSA: inicializa la S-box con la llave
void rc4_init(RC4_CTX *ctx, const uint8_t *key, size_t key_len);

// PRGA: genera keystream y cifra (o descifra — la operación es simétrica)
void rc4_apply(RC4_CTX *ctx, uint8_t *buf, size_t length);
```

**Se eligió RC4 porque:**

- Es implementable desde cero en ~60 líneas de C sin librerías
- No necesita padding (stream cipher vs block cipher) — ideal junto a RLE
- La operación de cifrado y descifrado es idéntica (XOR es su propio inverso)
- Overhead mínimo: opera sobre los datos **ya comprimidos** (~410 KB, no los 50 MB originales)

**Favorable cuando:**
- Se necesita cifrado simétrico sin overhead de padding
- El volumen de datos a cifrar ya fue reducido por compresión
- Se implementa desde cero en C para demostrar comprensión del algoritmo

**Desfavorable cuando:**
- Se requiere seguridad de nivel producción (RC4 tiene vulnerabilidades conocidas)
- Los datos no se comprimen primero (tendría que cifrar el volumen completo)
- Se necesita autenticación del mensaje (RC4 no provee integridad, solo confidencialidad)

### ¿Por qué no AES o ChaCha20?

| Algoritmo | Ventaja | Desventaja para este reto |
|-----------|---------|--------------------------|
| **RC4** ✓ | Simple, sin padding, mencionado en la rúbrica | Deprecado en producción |
| AES (OpenSSL) | Estándar industrial | Requiere gestionar padding PKCS#7 manualmente |
| ChaCha20 | Moderno y seguro | ~200 líneas de implementación propia, propenso a bugs |
| XOR simple | Trivial | Demasiado débil, sin S-box |

RC4 es el punto óptimo entre complejidad de implementación y profundidad técnica defendible.

---

## Seguridad de Llave en RAM

La gestión de la llave sigue tres principios de seguridad de OS:

### 1. No hardcoded — no en `argv`

```c
// ❌ MAL: visible en /proc/<pid>/cmdline para cualquier proceso del sistema
./editor write out.bin --key=mipassphrase

// ✅ BIEN: variable de entorno, eliminada del proceso con unsetenv() al leerla
EDITOR_KEY="mipassphrase" ./editor write out.bin

// ✅ BIEN: /dev/tty con echo desactivado — uso interactivo normal
./editor write out.bin    // pide la llave sin mostrarla en pantalla
```

### 2. `explicit_bzero` — borrado garantizado

```c
rc4_init(&ctx, passphrase, key_len);

// explicit_bzero NO puede ser eliminado por el compilador como optimización.
// memset() sí puede ser eliminado si el compilador detecta que la variable
// "no se usa más" (dead store elimination). Con explicit_bzero la llave
// se borra garantizadamente de la RAM.
explicit_bzero(passphrase, sizeof(passphrase));
explicit_bzero(&key_len, sizeof(key_len));
```

### 3. Destrucción del contexto RC4

```c
// La S-box de 256 bytes también se borra al terminar
rc4_destroy(&ctx);   // → explicit_bzero(ctx, sizeof(RC4_CTX))
```

### Consideración avanzada: `mlock()`

Si el SO mueve la página de RAM con la llave a la partición de Swap antes de que la borremos, la llave quedaría en el disco en texto plano. La defensa contra esto es:

```c
mlock(passphrase, sizeof(passphrase));  // bloquea la página en RAM física
                                        // el kernel no puede enviarla al Swap
```

---

## Benchmark: Resultados

Archivo de prueba: **50 MB** de datos binarios estructurados.

| Métrica del Kernel           | A. Clásico (`cp`) | B. RLE + RC4   | Impacto A → B       |
|------------------------------|:-----------------:|:--------------:|:-------------------:|
| Tamaño en disco              | 52 428 800 bytes  | 419 432 bytes  | **−99.2%** ✓        |
| Reducción bus I/O            | 0%                | 99.2%          | Mucho menos I/O     |
| CPU User mode                | ~0 ms             | ~40 ms         | +40 ms (RLE+RC4)    |
| CPU System mode              | ~30 ms            | ~40 ms         | Syscalls del kernel |
| Tiempo wall-clock (WSL2)     | 0.05 s            | 0.11 s         | Ver nota abajo      |
| `write()` syscalls           | miles             | 112            | Alineadas a 4096 B  |
| Seguridad datos en reposo    | ❌ Ninguna        | ✅ RC4 cifrado | Data at Rest segura |

> **Nota WSL2:** En WSL2 sobre `/mnt/c/`, el I/O pasa por una capa de traducción 9P que reduce artificialmente la latencia de disco. En Linux nativo, escribir 50 MB al disco cuesta significativamente más que 410 KB, y el escenario B sería más rápido. La métrica definitiva es la **reducción de tamaño: −99.2%**.

### Desglose de overhead CPU

```
Input al pipeline     : 50 MB   →  procesado por RLE en user mode
Output comprimido     : ~410 KB →  procesado por RC4

Estimado RLE          : ~28 ms  (procesa 50 MB buscando runs)
Estimado RC4          : ~9 ms   (procesa solo los 410 KB comprimidos)
Total overhead CPU    : ~37 ms

Syscalls write()      : 112 llamadas de 4096 bytes exactos (PAGE_SIZE)
```

**Conclusión:** RC4 es casi gratuito en este pipeline porque opera sobre los 410 KB comprimidos, no sobre los 50 MB originales. Este es el beneficio directo de comprimir antes de cifrar.

---

## Respuestas a Preguntas de Sustentación

### 1. "¿Qué pasa si invierten el orden? ¿Cifrar → Comprimir?"

RC4 produce datos pseudoaleatorios con entropía máxima. RLE busca *runs* de bytes consecutivos iguales; al cifrar primero no hay ningún patrón. El resultado puede incluso ser el doble del tamaño original porque RLE codifica cada byte como `[1][byte]` en el peor caso.

### 2. "Borran la llave con `explicit_bzero`, ¿pero qué pasa si el OS mandó esa página al Swap antes?"

La llave quedaría en el disco de Swap en texto plano, vulnerable a análisis forense. La solución es `mlock()` para bloquear esa página en RAM física y prohibirle al kernel enviarla al Swap.

### 3. "¿Por qué un buffer de 4096 bytes y no 4000 o 5000?"

4096 bytes es el tamaño estándar de una **página de memoria virtual** en x86/Linux y coincide con el bloque de ext4. Alinear los buffers a este tamaño garantiza que cada `write()` transfiera exactamente un bloque completo, evitando lecturas parciales y maximizando la eficiencia del bus I/O.

### 4. "¿Por qué RLE expande el archivo lorem ipsum?"

Texto natural tiene alta variedad de caracteres — poca repetición byte a byte. RLE solo comprime eficientemente datos con runs largos (campos fijos, padding binario). Para texto, cada byte es diferente al siguiente, entonces RLE lo codifica como `[1][byte]` por cada carácter, duplicando el tamaño. Esto no es un bug — es el comportamiento esperado de RLE fuera de su caso de uso óptimo.

---

## Equipo

| Integrante | Rol |
|------------|-----|
| Ismael GC | Arquitectura del pipeline, RC4, RLE, gestión segura de memoria |

**Materia:** Sistemas Operativos — Universidad EAFIT, 2026-1