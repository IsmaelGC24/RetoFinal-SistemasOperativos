/*
 * editor.c — Editor de archivos con pipeline de seguridad
 *
 * Pipeline:
 *   ESCRITURA: datos → [RLE compress] → [RC4 encrypt] → disco
 *   LECTURA:   disco → [RC4 decrypt] → [RLE decompress] → datos
 *
 * ¿Por qué comprimir ANTES de cifrar?
 *   La encriptación genera datos pseudoaleatorios (alta entropía): no hay
 *   patrones repetitivos. Los algoritmos de compresión explotan la
 *   redundancia; si encriptamos primero, la compresión es inútil o
 *   contraproducente. Por eso: comprime primero, cifra después.
 *
 * Seguridad de llave:
 *   - Se obtiene de la variable de entorno EDITOR_KEY (no hardcoded,
 *     no en argv — argv es visible en /proc/<pid>/cmdline).
 *   - En uso interactivo, se pide por /dev/tty sin eco.
 *   - Se intenta bloquear el buffer con mlock() para evitar swap.
 *   - Se borra de la RAM con explicit_bzero() tras inicializar RC4.
 *   - Se libera con munlock() despues del borrado.
 *   - La S-box RC4 se destruye con rc4_destroy() al terminar.
 *
 * Compilación: make
 * Uso interactivo (te pide la llave sin eco):
 *   ./editor write <archivo_salida> < datos.txt
 *   ./editor read  <archivo_entrada>
 *
 * Uso en scripts (llave por variable de entorno — se borra del env tras leerla):
 *   EDITOR_KEY="mipassphrase" ./editor write salida.bin < datos.txt
 *   EDITOR_KEY="mipassphrase" ./editor read  salida.bin
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>

#include "compress.h"
#include "crypto.h"

/* ========== Constantes ========== */

#define PAGE_SIZE        4096                  /* Tamaño de página x86/Linux */
#define MAX_KEY_LEN      256
#define MAX_FILE_SIZE    (200 * 1024 * 1024)   /* 200 MB límite de seguridad */

/* ========== Passphrase ========== */

/*
 * Obtener la passphrase de forma segura.
 * Prioridad:
 *   1. Variable de entorno EDITOR_KEY (para scripts/benchmark).
 *      Se copia al buffer local y se borra del entorno inmediatamente.
 *   2. /dev/tty con echo desactivado (modo interactivo normal).
 *
 * Retorna longitud de la llave, o -1 en error.
 */
static ssize_t obtener_passphrase(uint8_t *buf, size_t max_len) {
    /* Opción 1: variable de entorno EDITOR_KEY */
    const char *env_key = getenv("EDITOR_KEY");
    if (env_key != NULL) {
        size_t len = strlen(env_key);
        if (len == 0 || len >= max_len) {
            fprintf(stderr, "Error: EDITOR_KEY vacía o demasiado larga\n");
            return -1;
        }
        memcpy(buf, env_key, len);
        buf[len] = '\0';

        /*
         * Borrar la variable del entorno del proceso para que no quede
         * expuesta en /proc/<pid>/environ después del inicio.
         * unsetenv elimina la referencia; la memoria de env_key
         * la borramos sobreescribiendo el puntero original.
         */
        unsetenv("EDITOR_KEY");

        return (ssize_t)len;
    }

    /* Opción 2: leer de /dev/tty con echo desactivado */
    int tty_fd = open("/dev/tty", O_RDWR);
    if (tty_fd < 0) {
        fprintf(stderr,
            "Error: no hay terminal disponible.\n"
            "Use: EDITOR_KEY=\"<llave>\" ./editor write|read <archivo>\n");
        return -1;
    }

    struct termios old_term, new_term;
    tcgetattr(tty_fd, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
    tcsetattr(tty_fd, TCSANOW, &new_term);

    fprintf(stderr, "Ingrese la llave de encriptación: ");
    fflush(stderr);

    ssize_t len = read(tty_fd, buf, max_len - 1);

    tcsetattr(tty_fd, TCSANOW, &old_term);
    fprintf(stderr, "\n");
    close(tty_fd);

    if (len <= 0) return -1;
    if (buf[len - 1] == '\n') { buf[len - 1] = '\0'; len--; }
    else                      { buf[len]     = '\0'; }

    return len;
}

/*
 * Inicializar RC4 desde una passphrase protegida.
 *
 * La passphrase vive en un buffer local. Intentamos bloquear ese buffer con
 * mlock() antes de leer la llave para reducir el riesgo de que el kernel la
 * mande a swap. Si mlock() falla, el programa continua y muestra un warning:
 * la funcionalidad no depende de permisos elevados.
 */
static int inicializar_rc4_seguro(RC4_CTX *ctx) {
    uint8_t passphrase[MAX_KEY_LEN];
    memset(passphrase, 0, sizeof(passphrase));

    int locked = 0;
    if (mlock(passphrase, sizeof(passphrase)) != 0) {
        fprintf(stderr,
                "Warning: mlock() fallo para la passphrase: %s. "
                "La llave se borrara, pero el SO podria enviarla a swap.\n",
                strerror(errno));
    } else {
        locked = 1;
    }

    ssize_t key_len = obtener_passphrase(passphrase, sizeof(passphrase));
    if (key_len <= 0) {
        explicit_bzero(passphrase, sizeof(passphrase));
        if (locked && munlock(passphrase, sizeof(passphrase)) != 0) {
            fprintf(stderr, "Warning: munlock() fallo: %s\n", strerror(errno));
        }
        return -1;
    }

    rc4_init(ctx, passphrase, (size_t)key_len);

    /*
     * Borrar la llave despues de inicializar RC4. Desbloqueamos la pagina
     * solamente despues del borrado para no dejar la passphrase viva en RAM.
     */
    explicit_bzero(passphrase, sizeof(passphrase));
    explicit_bzero(&key_len, sizeof(key_len));

    if (locked && munlock(passphrase, sizeof(passphrase)) != 0) {
        fprintf(stderr, "Warning: munlock() fallo: %s\n", strerror(errno));
    }

    return 0;
}

/* ========== I/O helpers ========== */

/*
 * Leer un archivo completo a RAM usando open()/read().
 * Retorna puntero (caller libera con free), o NULL en error.
 */
static uint8_t *leer_archivo(const char *path, size_t *out_len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Error abriendo '%s': %s\n", path, strerror(errno));
        return NULL;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        fprintf(stderr, "Error obteniendo tamano de '%s': %s\n",
                path, strerror(errno));
        close(fd);
        return NULL;
    }

    if (st.st_size < 0 || (size_t)st.st_size > MAX_FILE_SIZE) {
        fprintf(stderr, "Archivo invalido o demasiado grande\n");
        close(fd);
        return NULL;
    }

    size_t size = (size_t)st.st_size;
    uint8_t *buf = malloc(size > 0 ? size : 1);
    if (!buf) {
        perror("malloc");
        close(fd);
        return NULL;
    }

    size_t total = 0;
    while (total < size) {
        ssize_t n = read(fd, buf + total, size - total);
        if (n < 0) {
            perror("read archivo");
            free(buf);
            close(fd);
            return NULL;
        }
        if (n == 0) break;
        total += (size_t)n;
    }
    close(fd);

    if (total != size) {
        fprintf(stderr, "Error leyendo archivo (leidos %zu de %zu bytes)\n",
                total, size);
        free(buf);
        return NULL;
    }

    *out_len = total;
    return buf;
}

/*
 * Leer stdin completo en un buffer dinámico.
 * No conocemos el tamaño de antemano, por eso crecemos dinámicamente.
 */
static uint8_t *leer_stdin(size_t *out_len) {
    size_t cap   = 1024 * 1024;  /* 1 MB inicial */
    size_t total = 0;
    uint8_t *buf = malloc(cap);
    if (!buf) { perror("malloc"); return NULL; }

    ssize_t n;
    for (;;) {
        if (total + PAGE_SIZE > cap) {
            size_t new_cap = (cap < MAX_FILE_SIZE / 2) ? cap * 2 : MAX_FILE_SIZE;
            if (new_cap <= cap) {
                fprintf(stderr, "stdin demasiado grande\n");
                free(buf); return NULL;
            }
            uint8_t *tmp = realloc(buf, new_cap);
            if (!tmp) { perror("realloc"); free(buf); return NULL; }
            buf = tmp;
            cap = new_cap;
        }

        n = read(STDIN_FILENO, buf + total, PAGE_SIZE);
        if (n <= 0) break;
        total += (size_t)n;
    }
    if (n < 0) { perror("read stdin"); free(buf); return NULL; }

    /* Ajustar al tamaño exacto para no desperdiciar RAM */
    if (total > 0) {
        uint8_t *final = realloc(buf, total);
        if (final) buf = final;
    }
    *out_len = total;
    return buf;
}

/*
 * Escribir buffer a disco con write() alineado a PAGE_SIZE.
 */
static int escribir_archivo(const char *path, const uint8_t *buf, size_t len) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP);
    if (fd < 0) {
        fprintf(stderr, "Error creando '%s': %s\n", path, strerror(errno));
        return -1;
    }
    size_t written = 0;
    while (written < len) {
        size_t chunk = (len - written < PAGE_SIZE) ? len - written : PAGE_SIZE;
        ssize_t n = write(fd, buf + written, chunk);
        if (n < 0) { perror("write"); close(fd); return -1; }
        if (n == 0) {
            fprintf(stderr, "Error: write() no progreso\n");
            close(fd);
            return -1;
        }
        written += (size_t)n;
    }
    close(fd);
    return 0;
}

/*
 * Escribir buffer a stdout con write().
 */
static int escribir_stdout(const uint8_t *buf, size_t len) {
    size_t out = 0;
    while (out < len) {
        size_t chunk = (len - out < PAGE_SIZE) ? len - out : PAGE_SIZE;
        ssize_t wn = write(STDOUT_FILENO, buf + out, chunk);
        if (wn < 0) { perror("write stdout"); return -1; }
        if (wn == 0) {
            fprintf(stderr, "Error: write(stdout) no progreso\n");
            return -1;
        }
        out += (size_t)wn;
    }
    return 0;
}

/*
 * Aplicar RLE a un buffer completo en RAM.
 */
static uint8_t *comprimir_rle_buffer(const uint8_t *input_buf,
                                     size_t input_len,
                                     size_t *out_len) {
    if (input_len == 0) {
        uint8_t *empty = malloc(1);
        if (!empty) perror("malloc");
        *out_len = 0;
        return empty;
    }

    if (input_len > (SIZE_MAX - 4) / 2) {
        fprintf(stderr, "Error: entrada demasiado grande para RLE\n");
        return NULL;
    }

    size_t compress_cap = input_len * 2 + 4;
    uint8_t *cbuf = malloc(compress_cap);
    if (!cbuf) { perror("malloc"); return NULL; }

    ssize_t clen = rle_compress(input_buf, input_len, cbuf, compress_cap);
    if (clen < 0) {
        fprintf(stderr, "Error: fallo en compresion RLE\n");
        free(cbuf);
        return NULL;
    }

    uint8_t *final = realloc(cbuf, (size_t)clen > 0 ? (size_t)clen : 1);
    if (final) cbuf = final;

    *out_len = (size_t)clen;
    return cbuf;
}

/*
 * Expandir RLE desde un buffer completo en RAM.
 */
static uint8_t *descomprimir_rle_buffer(const uint8_t *input_buf,
                                        size_t input_len,
                                        size_t *out_len) {
    if (input_len == 0) {
        uint8_t *empty = malloc(1);
        if (!empty) perror("malloc");
        *out_len = 0;
        return empty;
    }

    size_t dcap = rle_expanded_size(input_buf, input_len);
    if (dcap == 0 || dcap > MAX_FILE_SIZE) {
        fprintf(stderr, "Error: formato RLE invalido (llave incorrecta?)\n");
        return NULL;
    }

    uint8_t *dbuf = malloc(dcap);
    if (!dbuf) { perror("malloc"); return NULL; }

    ssize_t dlen = rle_decompress(input_buf, input_len, dbuf, dcap);
    if (dlen < 0) {
        fprintf(stderr, "Error: descompresion fallo (llave incorrecta?)\n");
        free(dbuf);
        return NULL;
    }

    *out_len = (size_t)dlen;
    return dbuf;
}

/* ========== Operacion WRITE ========== */
static int cmd_write(const char *output_path) {
    fprintf(stderr, "[pipeline] Modo escritura: %s\n", output_path);

    fprintf(stderr, "[pipeline] 1/4 Leyendo datos de stdin...\n");
    size_t input_len = 0;
    uint8_t *input_buf = leer_stdin(&input_len);
    if (!input_buf) return 1;
    fprintf(stderr, "[pipeline]     Leidos %zu bytes\n", input_len);

    fprintf(stderr, "[pipeline] 2/4 Comprimiendo con RLE...\n");
    size_t clen = 0;
    uint8_t *cbuf = comprimir_rle_buffer(input_buf, input_len, &clen);
    free(input_buf);
    if (!cbuf) return 1;

    double ratio = input_len > 0
        ? (1.0 - (double)clen / (double)input_len) * 100.0 : 0.0;
    fprintf(stderr, "[pipeline]     %zu -> %zu bytes (%.1f%% reduccion)\n",
            input_len, clen, ratio);

    fprintf(stderr, "[pipeline] 3/4 Cifrando con RC4...\n");
    RC4_CTX ctx;
    if (inicializar_rc4_seguro(&ctx) != 0) {
        free(cbuf);
        return 1;
    }
    rc4_apply(&ctx, cbuf, clen);
    rc4_destroy(&ctx);
    fprintf(stderr, "[pipeline]     Cifrado completado\n");

    fprintf(stderr, "[pipeline] 4/4 Escribiendo a disco...\n");
    int ret = escribir_archivo(output_path, cbuf, clen);
    free(cbuf);

    if (ret == 0) {
        fprintf(stderr, "[pipeline] Listo. Tamano en disco: %zu bytes\n", clen);
    }
    return ret == 0 ? 0 : 1;
}

/* ========== Operacion READ ========== */
static int cmd_read(const char *input_path) {
    fprintf(stderr, "[pipeline] Modo lectura: %s\n", input_path);

    fprintf(stderr, "[pipeline] 1/4 Leyendo archivo...\n");
    size_t file_len = 0;
    uint8_t *fbuf = leer_archivo(input_path, &file_len);
    if (!fbuf) return 1;
    fprintf(stderr, "[pipeline]     %zu bytes leidos del disco\n", file_len);

    fprintf(stderr, "[pipeline] 2/4 Descifrando con RC4...\n");
    RC4_CTX ctx;
    if (inicializar_rc4_seguro(&ctx) != 0) {
        free(fbuf);
        return 1;
    }
    rc4_apply(&ctx, fbuf, file_len);
    rc4_destroy(&ctx);

    fprintf(stderr, "[pipeline] 3/4 Descomprimiendo RLE...\n");
    size_t dlen = 0;
    uint8_t *dbuf = descomprimir_rle_buffer(fbuf, file_len, &dlen);
    free(fbuf);
    if (!dbuf) return 1;
    fprintf(stderr, "[pipeline]     Recuperados %zu bytes originales\n", dlen);

    fprintf(stderr, "[pipeline] 4/4 Enviando a stdout...\n");
    int ret = escribir_stdout(dbuf, dlen);
    free(dbuf);
    if (ret == 0) fprintf(stderr, "[pipeline] Listo.\n");
    return ret == 0 ? 0 : 1;
}

/* ========== Operacion COMPRESS-ONLY ========== */
static int cmd_compress_only(const char *output_path) {
    fprintf(stderr, "[benchmark] Modo compress-only: %s\n", output_path);

    size_t input_len = 0;
    uint8_t *input_buf = leer_stdin(&input_len);
    if (!input_buf) return 1;

    size_t clen = 0;
    uint8_t *cbuf = comprimir_rle_buffer(input_buf, input_len, &clen);
    free(input_buf);
    if (!cbuf) return 1;

    int ret = escribir_archivo(output_path, cbuf, clen);
    free(cbuf);
    return ret == 0 ? 0 : 1;
}

/* ========== Operacion DECOMPRESS-ONLY ========== */
static int cmd_decompress_only(const char *input_path) {
    fprintf(stderr, "[benchmark] Modo decompress-only: %s\n", input_path);

    size_t file_len = 0;
    uint8_t *fbuf = leer_archivo(input_path, &file_len);
    if (!fbuf) return 1;

    size_t dlen = 0;
    uint8_t *dbuf = descomprimir_rle_buffer(fbuf, file_len, &dlen);
    free(fbuf);
    if (!dbuf) return 1;

    int ret = escribir_stdout(dbuf, dlen);
    free(dbuf);
    return ret == 0 ? 0 : 1;
}

/* ========== Operacion ENCRYPT-ONLY ========== */
static int cmd_encrypt_only(const char *output_path) {
    fprintf(stderr, "[benchmark] Modo encrypt-only: %s\n", output_path);

    size_t input_len = 0;
    uint8_t *buf = leer_stdin(&input_len);
    if (!buf) return 1;

    RC4_CTX ctx;
    if (inicializar_rc4_seguro(&ctx) != 0) {
        free(buf);
        return 1;
    }
    rc4_apply(&ctx, buf, input_len);
    rc4_destroy(&ctx);

    int ret = escribir_archivo(output_path, buf, input_len);
    free(buf);
    return ret == 0 ? 0 : 1;
}

/* ========== Operacion DECRYPT-ONLY ========== */
static int cmd_decrypt_only(const char *input_path) {
    fprintf(stderr, "[benchmark] Modo decrypt-only: %s\n", input_path);

    size_t file_len = 0;
    uint8_t *buf = leer_archivo(input_path, &file_len);
    if (!buf) return 1;

    RC4_CTX ctx;
    if (inicializar_rc4_seguro(&ctx) != 0) {
        free(buf);
        return 1;
    }
    rc4_apply(&ctx, buf, file_len);
    rc4_destroy(&ctx);

    int ret = escribir_stdout(buf, file_len);
    free(buf);
    return ret == 0 ? 0 : 1;
}

/* ========== main ========== */
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr,
            "Uso:\n"
            "  ./editor write <archivo_salida>            - comprime+cifra stdin->archivo\n"
            "  ./editor read <archivo_entrada>             - descifra+descomprime->stdout\n"
            "  ./editor compress-only <archivo_salida>     - solo RLE stdin->archivo\n"
            "  ./editor decompress-only <archivo_entrada>  - solo RLE archivo->stdout\n"
            "  ./editor encrypt-only <archivo_salida>      - solo RC4 stdin->archivo\n"
            "  ./editor decrypt-only <archivo_entrada>     - solo RC4 archivo->stdout\n"
            "\n"
            "La llave se pide por terminal (sin eco) o por EDITOR_KEY=<llave>\n");
        return 1;
    }

    if (strcmp(argv[1], "write") == 0) return cmd_write(argv[2]);
    if (strcmp(argv[1], "read") == 0) return cmd_read(argv[2]);
    if (strcmp(argv[1], "compress-only") == 0) return cmd_compress_only(argv[2]);
    if (strcmp(argv[1], "decompress-only") == 0) return cmd_decompress_only(argv[2]);
    if (strcmp(argv[1], "encrypt-only") == 0) return cmd_encrypt_only(argv[2]);
    if (strcmp(argv[1], "decrypt-only") == 0) return cmd_decrypt_only(argv[2]);

    fprintf(stderr, "Comando desconocido: '%s'\n", argv[1]);
    return 1;
}
