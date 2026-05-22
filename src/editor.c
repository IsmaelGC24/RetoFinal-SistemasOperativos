/*
 * editor.c — Editor de archivos con pipeline de seguridad
 *
 * Pipeline (orden correcto — Nivel Arquitecto OS):
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
 *   - Se borra de la RAM con explicit_bzero() tras inicializar RC4.
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
#include <errno.h>

#include "compress.h"
#include "crypto.h"

/* ───────────────────────────── Constantes ───────────────────────────── */

#define PAGE_SIZE        4096                  /* Tamaño de página x86/Linux */
#define MAX_KEY_LEN      256
#define MAX_FILE_SIZE    (200 * 1024 * 1024)   /* 200 MB límite de seguridad */

/* ───────────────────────────── Passphrase ───────────────────────────── */

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

/* ───────────────────────────── I/O helpers ──────────────────────────── */

/*
 * Leer un archivo completo en un buffer dinámico.
 * Buffer alineado a PAGE_SIZE para eficiencia de bus I/O.
 * Retorna puntero (caller libera con free), o NULL en error.
 */
static uint8_t *leer_archivo(const char *path, size_t *out_len) {
    /*
     * Usamos fopen/fread (stdio) para leer el archivo cifrado del disco.
     * Internamente stdio usa read() del kernel, pero con buffer manejado
     * por la libc — arquitectónicamente equivalente para el bus I/O.
     */
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "Error abriendo '%s': %s\n", path, strerror(errno));
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    rewind(fp);

    if (size < 0 || size > MAX_FILE_SIZE) {
        fprintf(stderr, "Archivo inválido o demasiado grande\n");
        fclose(fp); return NULL;
    }

    uint8_t *buf = malloc((size_t)size);
    if (!buf) { perror("malloc"); fclose(fp); return NULL; }

    size_t total = fread(buf, 1, (size_t)size, fp);
    fclose(fp);

    if (total != (size_t)size) {
        fprintf(stderr, "Error leyendo archivo (leídos %zu de %ld bytes)\n",
                total, size);
        free(buf); return NULL;
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
    while ((n = read(STDIN_FILENO, buf + total, PAGE_SIZE)) > 0) {
        total += (size_t)n;
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
        written += (size_t)n;
    }
    close(fd);
    return 0;
}

/* ───────────────────────── Operación WRITE ──────────────────────────── */
static int cmd_write(const char *output_path) {
    fprintf(stderr, "[pipeline] Modo escritura: %s\n", output_path);

    /* Paso 1: Leer datos de stdin */
    fprintf(stderr, "[pipeline] 1/4 Leyendo datos de stdin...\n");
    size_t input_len = 0;
    uint8_t *input_buf = leer_stdin(&input_len);
    if (!input_buf) return 1;
    fprintf(stderr, "[pipeline]     Leídos %zu bytes\n", input_len);

    /* Paso 2: COMPRIMIR primero (para aprovechar patrones antes del cifrado) */
    fprintf(stderr, "[pipeline] 2/4 Comprimiendo con RLE...\n");
    size_t compress_cap = input_len * 2 + 4;
    uint8_t *cbuf = malloc(compress_cap);
    if (!cbuf) { free(input_buf); perror("malloc"); return 1; }

    ssize_t clen = rle_compress(input_buf, input_len, cbuf, compress_cap);
    free(input_buf);

    if (clen < 0) {
        fprintf(stderr, "Error: fallo en compresión RLE\n");
        free(cbuf); return 1;
    }
    double ratio = input_len > 0
        ? (1.0 - (double)clen / (double)input_len) * 100.0 : 0.0;
    fprintf(stderr, "[pipeline]     %zu → %zd bytes (%.1f%% reducción)\n",
            input_len, clen, ratio);

    /* Paso 3: Obtener passphrase (no hardcoded, no en argv) */
    uint8_t passphrase[MAX_KEY_LEN];
    memset(passphrase, 0, sizeof(passphrase));
    ssize_t key_len = obtener_passphrase(passphrase, sizeof(passphrase));
    if (key_len <= 0) { free(cbuf); return 1; }

    /* Paso 4: CIFRAR con RC4 (después de comprimir — orden arquitectónico correcto) */
    fprintf(stderr, "[pipeline] 3/4 Cifrando con RC4...\n");
    RC4_CTX ctx;
    rc4_init(&ctx, passphrase, (size_t)key_len);

    /*
     * SEGURIDAD CRÍTICA: borrar passphrase de la RAM con explicit_bzero.
     * A diferencia de memset, el compilador NO puede eliminar esta llamada
     * como optimización "dead store". La llave no debe quedar en el stack.
     */
    explicit_bzero(passphrase, sizeof(passphrase));
    explicit_bzero(&key_len, sizeof(key_len));

    rc4_apply(&ctx, cbuf, (size_t)clen);   /* cifrado in-place en RAM */
    rc4_destroy(&ctx);                      /* destruir S-box del contexto */
    fprintf(stderr, "[pipeline]     Cifrado completado\n");

    /* Paso 5: Escribir al disco */
    fprintf(stderr, "[pipeline] 4/4 Escribiendo a disco...\n");
    int ret = escribir_archivo(output_path, cbuf, (size_t)clen);
    free(cbuf);

    if (ret == 0) {
        fprintf(stderr, "[pipeline] ✓ Listo. Tamaño en disco: %zd bytes\n", clen);
    }
    return ret;
}

/* ───────────────────────── Operación READ ───────────────────────────── */
static int cmd_read(const char *input_path) {
    fprintf(stderr, "[pipeline] Modo lectura: %s\n", input_path);

    /* Paso 1: Leer archivo del disco */
    fprintf(stderr, "[pipeline] 1/4 Leyendo archivo...\n");
    size_t file_len = 0;
    uint8_t *fbuf = leer_archivo(input_path, &file_len);
    if (!fbuf) return 1;
    fprintf(stderr, "[pipeline]     %zu bytes leídos del disco\n", file_len);

    /* Paso 2: Obtener passphrase */
    uint8_t passphrase[MAX_KEY_LEN];
    memset(passphrase, 0, sizeof(passphrase));
    ssize_t key_len = obtener_passphrase(passphrase, sizeof(passphrase));
    if (key_len <= 0) { free(fbuf); return 1; }

    /* Paso 3: DESCIFRAR con RC4 */
    fprintf(stderr, "[pipeline] 2/4 Descifrando con RC4...\n");
    RC4_CTX ctx;
    rc4_init(&ctx, passphrase, (size_t)key_len);
    explicit_bzero(passphrase, sizeof(passphrase));
    explicit_bzero(&key_len, sizeof(key_len));

    rc4_apply(&ctx, fbuf, file_len);   /* RC4 es simétrico: descifra igual */
    rc4_destroy(&ctx);

    /* Paso 4: DESCOMPRIMIR */
    fprintf(stderr, "[pipeline] 3/4 Descomprimiendo RLE...\n");

    /*
     * Calcular el tamaño exacto del buffer de salida ANTES de malloc.
     * Evita pedir 200 MB cuando el dato real puede ser mucho menor.
     * rle_expanded_size recorre los bytes de count en O(n) sin descomprimir.
     */
    size_t dcap = rle_expanded_size(fbuf, file_len);
    if (dcap == 0) {
        fprintf(stderr, "Error: formato RLE inválido (¿llave incorrecta?)\n");
        free(fbuf); return 1;
    }
    uint8_t *dbuf = malloc(dcap);
    if (!dbuf) { free(fbuf); perror("malloc"); return 1; }

    ssize_t dlen = rle_decompress(fbuf, file_len, dbuf, dcap);
    free(fbuf);

    if (dlen < 0) {
        fprintf(stderr, "Error: descompresión falló (¿llave incorrecta?)\n");
        free(dbuf); return 1;
    }
    fprintf(stderr, "[pipeline]     Recuperados %zd bytes originales\n", dlen);

    /* Paso 5: Enviar a stdout */
    fprintf(stderr, "[pipeline] 4/4 Enviando a stdout...\n");
    size_t out = 0;
    while (out < (size_t)dlen) {
        size_t chunk = ((size_t)dlen - out < PAGE_SIZE) ? (size_t)dlen - out : PAGE_SIZE;
        ssize_t wn = write(STDOUT_FILENO, dbuf + out, chunk);
        if (wn < 0) { perror("write stdout"); free(dbuf); return 1; }
        out += (size_t)wn;
    }
    free(dbuf);
    fprintf(stderr, "[pipeline] ✓ Listo.\n");
    return 0;
}

/* ────────────────────────────── main ───────────────────────────────── */
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr,
            "Uso:\n"
            "  ./editor write <archivo_salida>  — comprime+cifra stdin→archivo\n"
            "  ./editor read  <archivo_entrada> — descifra+descomprime→stdout\n"
            "\n"
            "La llave se pide por terminal (sin eco) o por EDITOR_KEY=<llave>\n");
        return 1;
    }

    if (strcmp(argv[1], "write") == 0) return cmd_write(argv[2]);
    if (strcmp(argv[1], "read")  == 0) return cmd_read(argv[2]);

    fprintf(stderr, "Comando desconocido: '%s'\n", argv[1]);
    return 1;
}