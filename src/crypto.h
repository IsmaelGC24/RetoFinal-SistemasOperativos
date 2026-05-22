#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>   /* size_t */
#include <stdint.h>   /* uint8_t */

typedef struct {
    uint8_t S[256];
    uint8_t i;
    uint8_t j;
} RC4_CTX;

void rc4_init(RC4_CTX *ctx, const uint8_t *key, size_t key_len);
void rc4_apply(RC4_CTX *ctx, uint8_t *buf, size_t length);
void rc4_destroy(RC4_CTX *ctx);

#endif /* CRYPTO_H */