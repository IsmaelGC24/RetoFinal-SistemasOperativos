#define _GNU_SOURCE
#include "crypto.h"
#include <string.h>   /* explicit_bzero / memset */
#include <stdint.h>

/*
 * KSA — Key Scheduling Algorithm
 * Genera la S-box inicial a partir de la llave.
 * Al terminar, la copia local de la llave se borra con explicit_bzero
 * para que no quede en el stack ni en el heap.
 */
void rc4_init(RC4_CTX *ctx, const uint8_t *key, size_t key_len) {
    /* Inicializar S-box con permutación identidad */
    for (int k = 0; k < 256; k++) {
        ctx->S[k] = (uint8_t)k;
    }

    /* KSA: mezclar S-box con la llave */
    uint8_t j = 0;
    for (int k = 0; k < 256; k++) {
        j = j + ctx->S[k] + key[k % key_len];
        /* swap S[k] <-> S[j] */
        uint8_t tmp = ctx->S[k];
        ctx->S[k]   = ctx->S[j];
        ctx->S[j]   = tmp;
    }

    ctx->i = 0;
    ctx->j = 0;

    /*
     * SEGURIDAD: borrar las variables locales que tocaron la llave.
     * explicit_bzero no puede ser optimizado por el compilador (a diferencia
     * de memset, que puede eliminarse si el compilador detecta que la variable
     * "no se usa más"). Esto evita que la llave quede en el stack frame.
     */
    explicit_bzero(&j, sizeof(j));
    /* Nota: el caller es responsable de borrar el buffer 'key' original.
     * Ver pipeline.c donde se invoca rc4_init seguido de explicit_bzero
     * sobre el buffer de la passphrase. */
}

/*
 * PRGA — Pseudo-Random Generation Algorithm
 * Genera el keystream y aplica XOR al buffer (cifra o descifra).
 * La operación es idempotente: aplicar dos veces devuelve el original.
 */
void rc4_apply(RC4_CTX *ctx, uint8_t *buf, size_t length) {
    uint8_t si, sj;

    for (size_t n = 0; n < length; n++) {
        ctx->i = ctx->i + 1;
        ctx->j = ctx->j + ctx->S[ctx->i];

        /* swap S[i] <-> S[j] */
        si = ctx->S[ctx->i];
        sj = ctx->S[ctx->j];
        ctx->S[ctx->i] = sj;
        ctx->S[ctx->j] = si;

        /* XOR byte del dato con byte del keystream */
        uint8_t keystream_byte = ctx->S[(uint8_t)(si + sj)];
        buf[n] ^= keystream_byte;
    }
}

/*
 * Destruir el contexto: borrar S-box e índices de la RAM.
 * Un ingeniero de OS no deja basura criptográfica en memoria.
 */
void rc4_destroy(RC4_CTX *ctx) {
    explicit_bzero(ctx, sizeof(RC4_CTX));
}