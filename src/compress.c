#include "compress.h"
#include <string.h>
#include <unistd.h>

/*
 * RLE Compress — Run-Length Encoding
 *
 * Recorre el buffer de entrada agrupando bytes consecutivos iguales.
 * Cada run se codifica como [count][byte_value].
 *
 * Ejemplo: AAABBC → [3][A][2][B][1][C]
 */
ssize_t rle_compress(const uint8_t *in, size_t in_len,
                     uint8_t *out,      size_t out_cap) {
    if (!in || !out || in_len == 0) return -1;

    size_t out_pos = 0;
    size_t i = 0;

    while (i < in_len) {
        uint8_t current = in[i];
        uint8_t count   = 1;

        /* Contar cuántos bytes consecutivos iguales hay (máx 255) */
        while (i + count < in_len &&
            in[i + count] == current &&
            count < 255) {
            count++;
        }

        /* Verificar que cabemos en el buffer de salida */
        if (out_pos + 2 > out_cap) return -1;

        out[out_pos++] = count;
        out[out_pos++] = current;

        i += count;
    }

    return (ssize_t)out_pos;
}

/*
 * RLE Decompress
 *
 * Lee pares [count][byte] y expande cada uno en el buffer de salida.
 */
ssize_t rle_decompress(const uint8_t *in, size_t in_len,
                       uint8_t *out,      size_t out_cap) {
    if (!in || !out || in_len == 0) return -1;
    if (in_len % 2 != 0) return -1; /* formato RLE: siempre pares */

    size_t out_pos = 0;

    for (size_t i = 0; i + 1 < in_len; i += 2) {
        uint8_t count = in[i];
        uint8_t value = in[i + 1];

        if (out_pos + count > out_cap) return -1;

        memset(out + out_pos, value, count);
        out_pos += count;
    }

    return (ssize_t)out_pos;
}

size_t rle_expanded_size(const uint8_t *in, size_t in_len) {
    if (!in || in_len == 0 || in_len % 2 != 0) return 0;
    size_t total = 0;
    for (size_t i = 0; i < in_len; i += 2) {
        total += in[i]; /* count byte */
    }
    return total;
}
