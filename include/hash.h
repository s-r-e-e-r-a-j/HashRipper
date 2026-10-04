
// Developer: Sreeraj
// GitHub: https://github.com/s-r-e-e-r-a-j

#ifndef HASH_H
#define HASH_H

#include <stddef.h>

typedef enum {
    HASH_MD5,
    HASH_SHA1,
    HASH_SHA224,
    HASH_SHA256,
    HASH_SHA384,
    HASH_SHA512,
    HASH_SHA3_224,
    HASH_SHA3_256,
    HASH_SHA3_384,
    HASH_SHA3_512,
    HASH_BLAKE2B,
    HASH_BLAKE2S,
    HASH_NTLM,
    HASH_MD2,
    HASH_MD4,
    HASH_RIPEMD160,
    HASH_CRC32,
    HASH_XXH32,
    HASH_XXH64,
    HASH_XXH3_64,
    HASH_XXH3_128,
    HASH_INVALID
} hash_algorithm;

hash_algorithm hash_algorithm_from_name(const char *name);

const char *hash_algorithm_name(hash_algorithm algorithm);

int hash_string(hash_algorithm algorithm, const unsigned char *data, size_t len, char *output, size_t output_size);

size_t hash_hex_size(hash_algorithm algorithm);

#endif
