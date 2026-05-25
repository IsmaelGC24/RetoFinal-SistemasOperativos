# Reto Final - El Triangulo de Hierro

**Sistemas Operativos - Universidad EAFIT**
## Equipo

- Ismael Garcia Ceballos
- Juan Pablo Parra El-Masri

Proyecto en C que demuestra el equilibrio entre **espacio, tiempo y seguridad** usando un pipeline propio en memoria:

```text
WRITE:
stdin -> RLE compress -> RC4 encrypt in RAM -> write() to disk

READ:
read file -> RC4 decrypt in RAM -> RLE decompress -> stdout
```

El disco solo recibe el resultado final. Todo el procesamiento ocurre en buffers en RAM.

## Estructura

```text
src/
  editor.c      Programa principal y modos de benchmark
  compress.c    RLE propio
  compress.h
  crypto.c      RC4 propio
  crypto.h
Makefile
benchmark.sh
README.md
```

## Compilacion

```bash
make clean && make
```

El proyecto compila con:

```text
-Wall -Wextra -O2 -std=c11 -g
```

## Uso principal

Modo interactivo: la llave se lee desde `/dev/tty` con echo desactivado.

```bash
./editor write protegido.bin < input.dat
./editor read protegido.bin > recovered.dat
diff input.dat recovered.dat
```

Modo automatizado para pruebas y benchmark:

```bash
EDITOR_KEY="secretkey123" ./editor write protegido.bin < input.dat
EDITOR_KEY="secretkey123" ./editor read protegido.bin > recovered.dat
diff input.dat recovered.dat
```

La llave no esta hardcoded y no se pasa por `argv`.

## Modos para benchmark

Estos comandos existen para aislar cargas reales:

```bash
./editor compress-only out.rle < input.dat
./editor decompress-only out.rle > recovered.dat

EDITOR_KEY="secretkey123" ./editor encrypt-only out.rc4 < out.rle
EDITOR_KEY="secretkey123" ./editor decrypt-only out.rc4 > out.rle.recovered
```

El pipeline completo sigue siendo:

```bash
EDITOR_KEY="secretkey123" ./editor write out.enc < input.dat
EDITOR_KEY="secretkey123" ./editor read out.enc > recovered.dat
```

## Test de integridad

```bash
make test
```

El target genera un archivo repetitivo, ejecuta:

```bash
EDITOR_KEY="secretkey123" ./editor write test_output.bin < test_input.txt
EDITOR_KEY="secretkey123" ./editor read test_output.bin > test_recovered.txt
diff test_input.txt test_recovered.txt
```

Si `diff` no imprime diferencias, la recuperacion es bit a bit identica.

## Benchmark

```bash
chmod +x benchmark.sh
./benchmark.sh
```

El benchmark genera un archivo binario estructurado de 50 MB y mide con GNU `time` y `strace`:

| Escenario | Comando |
|---|---|
| A. Clasico plano | `cp archivo_50MB out_plain.dat` |
| B. Solo compresion | `./editor compress-only out.rle < archivo_50MB` |
| C. Compresion + encriptacion | `EDITOR_KEY="$KEY" ./editor write out.enc < archivo_50MB` |
| D. Solo cifrado sobre buffer comprimido | `EDITOR_KEY="$KEY" ./editor encrypt-only out.rc4 < out.rle` |

La tabla final del script reporta:

- Tamano transmitido I/O
- Reduccion I/O
- CPU User mode
- CPU System mode
- Wall-clock
- Memoria maxima
- Numero de `read()` y `write()` capturado con `strace`
- Conclusion de espacio, tiempo y seguridad

### Tabla final para la sustentacion

Con el generador incluido en `benchmark.sh`, el tamano de entrada es 50 MB. Los tiempos exactos dependen de la maquina, pero la relacion de espacio es estable:

| Metrica | A. Clasico | B. Solo Compresion | C. Compresion + Encriptacion | Impacto A vs C |
|---|---:|---:|---:|---|
| Tamano transmitido I/O | 52,428,800 bytes | ~512,000 bytes | ~512,000 bytes | C reduce ~99.0% del I/O |
| Reduccion I/O | 0% | ~99.0% | ~99.0% | Menos trafico hacia disco |
| CPU User mode | Muy bajo | Sube por RLE | Sube por RLE + RC4 | Se pagan ciclos de CPU |
| CPU System mode | Depende del `cp` | Menos escritura efectiva | Menos escritura efectiva | Menos bytes llegan al kernel |
| Wall-clock | Base | Depende del CPU/disco | Depende del CPU/disco | Puede ganar si el disco es cuello de botella |
| Seguridad en reposo | Ninguna | Ninguna | RC4 sobre salida comprimida | C agrega confidencialidad |

Conclusion: el escenario C gana **espacio** y **seguridad** frente a A. El costo es **tiempo de CPU** adicional. Ese costo es el triangulo de hierro: no hay mejora gratis, se intercambian recursos.

## Por que comprimir antes de cifrar

RLE comprime buscando runs de bytes repetidos:

```text
AAAAAABBBB -> [6][A][4][B]
```

RC4 cifra aplicando XOR con un keystream pseudoaleatorio. Despues de cifrar, los datos tienen alta entropia: parecen aleatorios y casi no tienen patrones repetidos.

Orden correcto:

```text
datos con patrones -> RLE -> datos pequenos -> RC4 -> datos pequenos cifrados
```

Orden incorrecto:

```text
datos con patrones -> RC4 -> datos pseudoaleatorios -> RLE -> no comprime o crece
```

Por eso cifrar antes de comprimir falla por entropia. El compresor ya no encuentra redundancia; en el peor caso RLE representa cada byte como `[1][byte]` y duplica el tamano.

## Seguridad de la llave

La llave se obtiene de dos formas:

- `/dev/tty` con echo desactivado para uso interactivo.
- `EDITOR_KEY` solo para automatizacion y benchmark.

No se acepta llave por argumento de linea de comandos porque `argv` puede verse en `/proc/<pid>/cmdline`.

Flujo de memoria de la passphrase:

```c
uint8_t passphrase[MAX_KEY_LEN];
mlock(passphrase, sizeof(passphrase));          // si falla, warning y continua
obtener_passphrase(passphrase, sizeof(passphrase));
rc4_init(&ctx, passphrase, key_len);
explicit_bzero(passphrase, sizeof(passphrase)); // borrar despues de rc4_init()
munlock(passphrase, sizeof(passphrase));        // desbloquear despues del borrado
```

Si `mlock()` falla, el programa no aborta. Muestra un warning claro porque la operacion puede fallar por limites del usuario o permisos del sistema. La razon de usar `mlock()` es evitar que el kernel mande la pagina que contiene la passphrase a swap antes de que el programa la borre.

El contexto RC4 tambien se destruye:

```c
rc4_destroy(&ctx); // explicit_bzero(ctx, sizeof(RC4_CTX))
```

`explicit_bzero()` se usa en vez de `memset()` porque el compilador no puede eliminarlo como una escritura muerta. Esto ayuda a garantizar que la llave y la S-box no queden en RAM despues de usarse.

## Por que PAGE_SIZE = 4096

`PAGE_SIZE` se define como 4096 bytes porque 4 KiB es el tamano tipico de pagina de memoria virtual en x86/Linux y tambien una unidad natural para I/O en muchos sistemas de archivos. El programa escribe en chunks de 4096 bytes con `write()`, lo que facilita analizar el comportamiento con `strace` y conectar la implementacion con conceptos de SO: paginas, buffers, syscalls y transferencia hacia disco.

## Limitacion de RC4

RC4 no es seguro para produccion moderna. Tiene sesgos conocidos en su keystream y esta deprecado para protocolos reales. En este proyecto se mantiene porque:

- Es una implementacion propia en C, sin OpenSSL ni librerias externas.
- Sirve para demostrar cifrado simetrico y gestion de memoria de llaves.
- No requiere padding, por ser stream cipher.
- Encaja con la rubrica academica del reto.

Para produccion se usaria un algoritmo moderno como AES-GCM o ChaCha20-Poly1305 con autenticacion, nonces correctos y una libreria criptografica auditada.

## Defensa oral rapida

- Espacio: RLE reduce mucho cuando hay runs largos.
- Tiempo: RLE y RC4 agregan CPU user mode.
- Seguridad: RC4 cifra los datos en reposo, y la passphrase se borra de RAM.
- Orden: comprimir antes de cifrar conserva patrones para RLE; cifrar antes destruye esos patrones.
- Sistema operativo: `read()`, `write()`, buffers en RAM, `mlock()`, `munlock()`, `PAGE_SIZE` y `strace` conectan el proyecto con el kernel.


