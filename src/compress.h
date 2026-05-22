#ifndef COMPRESS_H
#define COMPRESS_H

#include <stddef.h>   /* size_t */
#include <stdint.h>   /* uint8_t */
#include <sys/types.h> /* ssize_t */

ssize_t rle_compress(const uint8_t *in, size_t in_len,
                     uint8_t *out,      size_t out_cap);

ssize_t rle_decompress(const uint8_t *in, size_t in_len,
                       uint8_t *out,      size_t out_cap);

size_t rle_expanded_size(const uint8_t *in, size_t in_len);

#endif /* COMPRESS_H */